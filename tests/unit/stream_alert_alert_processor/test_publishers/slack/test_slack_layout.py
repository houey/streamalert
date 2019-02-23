from datetime import datetime

from nose.tools import assert_equal, assert_true, assert_less_equal

from publishers.community.slack.slack_layout import Summary, AttachRuleInfo, AttachPublication, \
    AttachFullRecord
from tests.unit.stream_alert_alert_processor.helpers import get_alert


class TestPrettyLayout(object):

    def setup(self):
        self._publisher = Summary()

    def test_simple(self):
        """Publishers - Slack - PrettyLayout"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        publication = self._publisher.publish(alert, {})

        expectation = {
            'slack.text': 'Rule triggered',
            '_previous_publication': {},
            'slack.attachments': [
                {
                    'author_link': '',
                    'color': '#ff5a5f',
                    'text': 'Info about this rule and what actions to take',
                    'author_name': '',
                    'footer_icon': '',
                    'mrkdwn_in': [],
                    'thumb_url': '',
                    'title': 'cb_binarystore_file_added',
                    'fields': [],
                    'footer': '',
                    'ts': 1546329600.0,
                    'title_link': (
                        'https://github.com/airbnb/streamalert/search'
                        '?q=cb_binarystore_file_added+path%3A%2Frules'
                    ),
                    'image_url': '',
                    'fallback': 'Rule triggered: cb_binarystore_file_added',
                    'author_icon': ''
                }
            ]
        }

        assert_equal(publication, expectation)


class TestAttachRuleInfo(object):

    def setup(self):
        self._publisher = AttachRuleInfo()

    def test_simple(self):
        """Publishers - Slack - AttachRuleInfo"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)
        alert.rule_description = '''
Author: unit_test
Reference: somewhere_over_the_rainbow
Description: ?
Att&ck vector:  Assuming direct control
'''

        publication = self._publisher.publish(alert, {})

        expectation = {
            'slack.attachments': [
                {
                    'color': '#8ce071',
                    'fields': [
                        {
                            'title': 'att&ck vector',
                            'value': 'Assuming direct control',
                        },
                        {
                            'title': 'reference',
                            'value': 'somewhere_over_the_rainbow',
                        }
                    ]
                }
            ]
        }

        assert_equal(publication, expectation)


class TestAttachPublication(object):

    def setup(self):
        self._publisher = AttachPublication()

    def test_simple(self):
        """Publishers - Slack - AttachPublication"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        previous = {
            '_previous_publication': {'foo': 'bar'},
            'slack.attachments': [
                {
                    'text': 'attachment1',
                },
            ]
        }
        publication = self._publisher.publish(alert, previous)

        expectation = {
            '_previous_publication': {'foo': 'bar'},
            'slack.attachments': [
                {'text': 'attachment1'},
                {
                    'color': '#00d1c1',
                    'text': '```\n{\n  "foo": "bar"\n}\n```',
                    'mrkdwn_in': ['text'],
                    'title': 'Alert Data:'
                }
            ]
        }

        assert_equal(publication, expectation)


class TestAttachFullRecord(object):

    def setup(self):
        self._publisher = AttachFullRecord()

    def test_simple(self):
        """Publishers - Slack - AttachFullRecord"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        publication = self._publisher.publish(alert, {})

        expectation = {
            'slack.attachments': [
                {
                    'footer': 'via <https://console.aws.amazon.com/s3/home|s3>',
                    'fields': [
                        {'value': '79192344-4a6d-4850-8d06-9c3fef1060a4', 'title': 'Alert Id'}
                    ],
                    'mrkdwn_in': ['text'],
                    'author': 'corp-prefix.prod.cb.region',
                    'color': '#7b0051',
                    'text': (
                        '```\n\n{\n  "cb_server": "cbserver",\n  "compressed_size": "9982",'
                        '\n  "file_path": "/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip",'
                        '\n  "md5": "0F9AA55DA3BDE84B35656AD8911A22E1",\n  "node_id": "1",'
                        '\n  "size": "21504",\n  "timestamp": "1496947381.18",'
                        '\n  "type": "binarystore.file.added"\n}\n```'
                    ),
                    'title': 'Record',
                    'footer_icon': ''
                }
            ]
        }
        assert_equal(publication, expectation)

    def test_record_splitting(self):
        """Publishers - Slack - AttachFullRecord - Split Record"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        alert.record = {
            'massive_record': []
        }
        for index in range(0, 999):
            alert.record['massive_record'].append({
                'index': index,
                'value': 'foo'
            })

        publication = self._publisher.publish(alert, {})

        attachments = publication['slack.attachments']

        assert_equal(len(attachments), 14)
        for attachment in attachments:
            assert_less_equal(len(attachment['text']), 4000)

        assert_equal(attachments[0]['title'], 'Record')
        assert_equal(len(attachments[0]['fields']), 0)
        assert_equal(attachments[0]['footer'], '')

        assert_equal(attachments[1]['title'], '')
        assert_equal(len(attachments[1]['fields']), 0)
        assert_equal(attachments[1]['footer'], '')

        assert_equal(attachments[13]['title'], '')
        assert_equal(len(attachments[13]['fields']), 1)
        assert_equal(attachments[13]['footer'], 'via <https://console.aws.amazon.com/s3/home|s3>')
