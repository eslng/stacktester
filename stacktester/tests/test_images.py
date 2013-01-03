import json
import os
import re

import unittest2 as unittest

from stacktester import openstack


class ImagesTest(unittest.TestCase):

    def setUp(self):
        self.os = openstack.Manager()

        host = self.os.config.nova.host
        port = self.os.config.nova.port

    def tearDown(self):
        pass

    def _assert_image_links(self, image):
        image_id = str(image['id'])

        mgmt_url = self.os.nova.management_url
        bmk_url = re.sub(r'v1.1\/', r'', mgmt_url)

        self_link = os.path.join(mgmt_url, 'images', image_id)
        bookmark_link = os.path.join(bmk_url, 'images', image_id)

        expected_links = [
            {
                u'rel': u'self',
                u'href': self_link,
            },
            {
                u'rel': u'bookmark',
                u'href': bookmark_link,
            },
        ]

        # We'll remove alternate URLs as they are not so critical
        image_links = []
        for link in image['links']:
            if link['rel'] != 'alternate':
                image_links.append(link)

        self.assertEqual(image_links, expected_links)

    def _assert_image_entity_basic(self, image):
        actual_keys = set(image.keys())
        expected_keys = set((
            'id',
            'name',
            'links',
        ))
        self.assertEqual(actual_keys, expected_keys)

        self._assert_image_links(image)

    def _assert_image_entity_detailed(self, image):
        keys = image.keys()
        if 'server' in keys:
            keys.remove('server')
        actual_keys = set(keys)
        expected_keys = set((
            'id',
            'name',
            'progress',
            'created',
            'updated',
            'status',
            'metadata',
            'links',
            'minRam',
            'minDisk',
        ))
        self.assertEqual(actual_keys, expected_keys)

        self._assert_image_links(image)

    def test_index(self):
        """List all images"""

        response, body = self.os.nova.request('GET', '/images')

        self.assertEqual(response['status'], '200')
        resp_body = json.loads(body)
        self.assertEqual(resp_body.keys(), ['images'])

        for image in resp_body['images']:
            self._assert_image_entity_basic(image)

    def test_detail(self):
        """List all images in detail"""

        response, body = self.os.nova.request('GET', '/images/detail')

        self.assertEqual(response['status'], '200')
        resp_body = json.loads(body)
        self.assertEqual(resp_body.keys(), ['images'])

        for image in resp_body['images']:
            self._assert_image_entity_detailed(image)
