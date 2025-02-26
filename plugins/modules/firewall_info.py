#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This module contains all of the functionality for Linode Firewall info."""

from __future__ import absolute_import, division, print_function

# pylint: disable=unused-import
from typing import Optional, List, Any, Dict

from linode_api4 import Firewall

from ansible_collections.linode.cloud.plugins.module_utils.linode_common import LinodeModuleBase
from ansible_collections.linode.cloud.plugins.module_utils.linode_helper import create_filter_and, \
    paginated_list_to_json
from ansible_collections.linode.cloud.plugins.module_utils.linode_docs import global_authors, \
    global_requirements

import ansible_collections.linode.cloud.plugins.module_utils.doc_fragments.firewall as docs_parent
import ansible_collections.linode.cloud.plugins.module_utils.doc_fragments.firewall_info as docs

linode_firewall_info_spec = dict(
    # We need to overwrite attributes to exclude them as requirements
    state=dict(type='str', required=False, doc_hide=True),

    id=dict(type='int', required=False,
            description=[
                'The unique id of the Firewall.',
                'Optional if `label` is defined.'
            ]),
    label=dict(type='str', required=False,
               description=[
                   'The Firewall’s label.',
                   'Optional if `id` is defined.'
               ])
)

specdoc_meta = dict(
    description=[
        'Get info about a Linode Firewall.'
    ],
    requirements=global_requirements,
    author=global_authors,
    spec=linode_firewall_info_spec,
    examples=docs.specdoc_examples,
    return_values=dict(
        firewall=dict(
            description='The Firewall description in JSON serialized form.',
            docs_url='https://www.linode.com/docs/api/networking/#firewall-view',
            type='dict',
            sample=docs_parent.result_firewall_samples
        ),
        devices=dict(
            description='A list of Firewall devices JSON serialized form.',
            docs_url='https://www.linode.com/docs/api/networking/#firewall-device-view',
            type='list',
            sample=docs_parent.result_devices_samples
        )
    )
)

linode_firewall_valid_filters = [
    'id', 'label'
]


class LinodeFirewallInfo(LinodeModuleBase):
    """Module for viewing info about a Linode Firewall"""

    def __init__(self) -> None:
        self.module_arg_spec = linode_firewall_info_spec
        self.required_one_of: List[str] = []
        self.results: Dict[str, Any] = dict(
            firewall=None,
        )

        super().__init__(module_arg_spec=self.module_arg_spec,
                         required_one_of=self.required_one_of)

    def _get_matching_firewall(self) -> Optional[Firewall]:
        """Gets the Firewall with the param properties"""

        filter_items = {k: v for k, v in self.module.params.items()
                        if k in linode_firewall_valid_filters and v is not None}

        filter_statement = create_filter_and(Firewall, filter_items)

        try:
            # Special case because ID is not filterable
            if 'id' in filter_items.keys():
                result = Firewall(self.client, self.module.params.get('id'))
                result._api_get()  # Force lazy-loading

                return result

            return self.client.networking.firewalls(filter_statement)[0]
        except IndexError:
            return None
        except Exception as exception:
            return self.fail(msg='failed to get firewall {0}'.format(exception))

    def exec_module(self, **kwargs: dict) -> Optional[dict]:
        """Entrypoint for Firewall info module"""

        firewall = self._get_matching_firewall()

        if firewall is None:
            self.fail('failed to get firewall')

        self.results['firewall'] = firewall._raw_json
        self.results['devices'] = paginated_list_to_json(firewall.devices)

        return self.results


def main() -> None:
    """Constructs and calls the Linode Firewall info module"""
    LinodeFirewallInfo()


if __name__ == '__main__':
    main()
