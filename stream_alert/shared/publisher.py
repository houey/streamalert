from abc import abstractmethod
from copy import deepcopy
from inspect import isclass

from stream_alert.shared.importer import import_folders
from stream_alert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class AlertPublisherImporter(object):
    """A service that loads all publishers from their designated location."""
    _PUBLISHERS_DIRECTORY = 'publishers'

    @classmethod
    def import_publishers(cls):
        import_folders(cls._PUBLISHERS_DIRECTORY)


class Register(object):
    """This is a decorator used to register publishers into the AlertPublisherRepository."""

    def __new__(cls, class_or_function):
        AlertPublisherRepository.register_publisher(class_or_function)

        return class_or_function  # Return the definition, not the instantiated object


class AlertPublisher(object):
    """Interface for a Publisher. All class-based publishers must inherit from this class."""

    @abstractmethod
    def publish(self, alert, publication):
        """Publishes the given alert.

        Publishers are not intended to MODIFY the given publication; It is preferable to use
        deepcopy and to append on new fields onto the publication, in order to reduce the chance
        for bugs.

        As a general rule of thumb, published fields that are specific to a certain output are
        published as top-level keys of the following format:

        [output service name].[field name]

        E.g. "demisto.blah"

        Args:
            alert (Alert): The alert instance to publish.
            publication (dict): An existing publication generated by previous publishers in the
                series of publishers, or {}.

        Returns:
            dict: The published alert.
        """


class CompositePublisher(AlertPublisher):
    """A publisher class that combines the logic of multiple other publishers together in series"""

    def __init__(self, publishers):
        self._publishers = publishers  # Type list(BaseAlertPublisher)

        for publisher in self._publishers:
            if not isinstance(publisher, AlertPublisher):
                LOGGER.error('CompositePublisher given invalid publisher')

    def publish(self, alert, publication):
        new_publication = deepcopy(publication)

        for publisher in self._publishers:
            try:
                new_publication = publisher.publish(alert, new_publication)
            except KeyError:
                LOGGER.exception(
                    'CompositePublisher encountered KeyError with publisher: %s',
                    publisher.__name__
                )
                raise

        return new_publication


class WrappedFunctionPublisher(AlertPublisher):
    """A class only used to wrap a function publisher."""

    def __init__(self, function):
        self._function = function

    def publish(self, alert, publication):
        return self._function(alert, publication)


class AlertPublisherRepository(object):
    """A repository mapping names -> publishers"""
    _publishers = {}

    @staticmethod
    def is_valid_publisher(class_or_function):
        """Returns TRUE if the given reference can be registered as a publisher"""
        if isclass(class_or_function) and issubclass(class_or_function, AlertPublisher):
            return True
        elif callable(class_or_function):
            return True

        return False

    @staticmethod
    def get_publisher_name(class_or_function):
        """Given a class or function, will return its fully qualified name.

            This is useful for assigning a unique string name for a publisher."""
        return '{}.{}'.format(class_or_function.__module__, class_or_function.__name__)

    @classmethod
    def register_publisher(cls, publisher):
        """Registers the publisher into the repository.

        Args:
             publisher (callable|AlertPublisher): An instance of a publisher class

        Return:
            void
        """
        if not AlertPublisherRepository.is_valid_publisher(publisher):
            LOGGER.error(
                'Could not register publisher %s; Not callable nor subclass of AlertPublisher',
                publisher
            )
            return

        # We have to put the isclass() check BEFORE the callable() check because classes are also
        # callable!
        elif isclass(publisher):
            # If the provided publisher is a Class, then we simply need to instantiate an instance
            # of the class and register it.
            publisher_instance = publisher()
        else:
            # If the provided publisher is a function, we wrap it with a WrappedFunctionPublisher
            # to make them easier to handle.
            publisher_instance = WrappedFunctionPublisher(publisher)

        name = AlertPublisherRepository.get_publisher_name(publisher)

        if name in cls._publishers:
            LOGGER.error('Publisher with name [%s] has already been registered.', name)
            return

        cls._publishers[name] = publisher_instance

    @classmethod
    def get_publisher(cls, name):
        """Returns the subclass that should handle this particular service

        Args:
            name (str): The name of the publisher.

        Returns:
            AlertPublisher|None
        """
        if cls.has_publisher(name):
            return cls._publishers[name]

        LOGGER.error('Publisher [%s] does not exist', name)

    @classmethod
    def has_publisher(cls, name):
        AlertPublisherImporter.import_publishers()
        return name in cls._publishers

    @classmethod
    def all_publishers(cls):
        """
        Returns:
            dict
        """
        return cls._publishers

    @classmethod
    def create_composite_publisher(cls, publisher_names):
        """Assembles a single publisher that combines logic from multiple publishers

        Args:
            publisher_names (list(str)): A list of string names of publishers

        Return:
            CompositePublisher|DefaultPublisher
        """
        publisher_names = publisher_names or []
        publishers = []

        for publisher_name in publisher_names:
            publisher = cls.get_publisher(publisher_name)
            if publisher:
                publishers.append(publisher)

        if len(publishers) <= 0:
            # If no publishers were given, or if all of the publishers failed to load, then we
            # load a default publisher.
            default_publisher_name = cls.get_publisher_name(DefaultPublisher)
            return cls.get_publisher(default_publisher_name)

        return CompositePublisher(publishers)


@Register
class DefaultPublisher(AlertPublisher):
    """The default publisher that is used when no other publishers are provided"""

    DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

    def publish(self, alert, publication):
        return {
            'cluster': alert.cluster or '',
            'context': alert.context or {},
            'created': alert.created.strftime(self.DATETIME_FORMAT),
            'id': alert.alert_id,
            'log_source': alert.log_source or '',
            'log_type': alert.log_type or '',
            'outputs': list(sorted(alert.outputs)),  # List instead of set for JSON-compatibility
            'publishers': alert.publishers or {},
            'record': alert.record,
            'rule_description': alert.rule_description or '',
            'rule_name': alert.rule_name or '',
            'source_entity': alert.source_entity or '',
            'source_service': alert.source_service or '',
            'staged': alert.staged,
        }
