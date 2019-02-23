import cgi
import time
import urllib

from stream_alert.shared.publisher import AlertPublisher, Register
from stream_alert.shared.description import RuleDescriptionParser

RAUSCH = '#ff5a5f'
BABU = '#00d1c1'
LIMA = '#8ce071'
HACKBERRY = '#7b0051'


@Register
class ShortenTitle(AlertPublisher):
    """Adds a brief summary with the rule triggered, author, description, and time

    To customize the behavior of this Publisher, it is recommended to subclass this and override
    parameters as necessary. For example, an implementation could override _GITHUB_REPO_URL with
    the URL appropriate for the organization using StreamAlert.
    """

    _GITHUB_REPO_URL = 'https://github.com/airbnb/streamalert'
    _SEARCH_PATH = '/search'
    _RULES_PATH = '/rules'

    def publish(self, alert, publication):
        rule_name = alert.rule_name
        rule_description = alert.rule_description
        rule_presentation = RuleDescriptionParser.present(rule_description)

        author = rule_presentation['author']

        return {
            'slack.text': 'Rule triggered',
            'slack.attachments': [
                {
                    'fallback': 'Rule triggered: {}'.format(rule_name),
                    'color': self._color(),
                    'author_name': author,
                    'author_link': self._author_url(author),
                    'author_icon': self._author_icon(author),
                    'title': rule_name,
                    'title_link': self._title_url(rule_name),
                    'text': cgi.escape(rule_presentation['description']),
                    'fields': map(
                        lambda(key): {'title': key, 'value': rule_presentation['fields'][key]},
                        rule_presentation['fields'].keys()
                    ),
                    'image_url': '',
                    'thumb_url': '',
                    'footer': '',
                    'footer_icon': '',
                    'ts': time.mktime(alert.created.timetuple()) if alert.created else '',
                    'mrkdwn_in': [],
                },
            ],

            # This information is passed-through to future publishers.
            '_previous_publication': publication,
        }

    @staticmethod
    def _color():
        """The color of this section"""
        return RAUSCH

    @classmethod
    def _author_url(cls, _):
        """When given an author name, returns a clickable link, if any"""
        return ''

    @classmethod
    def _author_icon(cls, _):
        """When given an author name, returns a URL to an icon, if any"""
        return ''

    @classmethod
    def _title_url(cls, rule_name):
        """When given the rule_name, returns a clickable link, if any"""

        # It's actually super hard to generate a exact link to a file just from the rule_name,
        # because the rule/ directory files are not deployed with the publishers in the alert
        # processor.
        # Instead, we send them to Github with a formatted query string that is LIKELY to
        # find the correct file.
        #
        # If you do not want URLs to show up, simply override this method and return empty string.
        return '{}{}?{}'.format(
            cls._GITHUB_REPO_URL,
            cls._SEARCH_PATH,
            urllib.urlencode({
                'q': '{} path:{}'.format(rule_name, cls._RULES_PATH)
            })
        )
