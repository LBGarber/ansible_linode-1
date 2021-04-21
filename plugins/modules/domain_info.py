#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This module contains all of the functionality for Linode Domains."""

from __future__ import absolute_import, division, print_function

# pylint: disable=unused-import
from linode_api4 import Domain

from ansible_collections.linode.cloud.plugins.module_utils.linode_common import LinodeModuleBase
from ansible_collections.linode.cloud.plugins.module_utils.linode_helper import create_filter_and

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'Linode'
}

DOCUMENTATION = '''
'''

EXAMPLES = '''
'''

RETURN = '''
'''

linode_domain_info_spec = dict(
    # We need to overwrite attributes to exclude them as requirements
    state=dict(type='str'),
    label=dict(type='str'),

    id=dict(type='int'),
    domain=dict(type='str')
)

linode_instance_valid_filters = [
    'id', 'domain'
]

class LinodeDomainInfo(LinodeModuleBase):
    """Gets information about a Linode domain"""

    def __init__(self):
        self.module_arg_spec = linode_domain_info_spec
        self.required_one_of = []
        self.results = dict(
            domain=None,
        )

        super().__init__(module_arg_spec=self.module_arg_spec,
                         required_one_of=self.required_one_of)

    def get_domain_by_properties(self, **kwargs) -> Domain:
        """Gets the domain with the given properties in kwargs"""

        filter_items = {k: v for k, v in kwargs.items()
                        if k in linode_instance_valid_filters and v is not None}

        filter_statement = create_filter_and(Domain, filter_items)

        try:
            # Special case because ID is not filterable
            if 'id' in filter_items.keys():
                result = Domain(self.client, kwargs.get('id'))
                result._api_get()  # Force lazy-loading

                return result

            return self.client.domains(filter_statement)[0]
        except IndexError:
            return None
        except Exception as exception:
            self.fail(msg='failed to get domain {0}'.format(exception))

    def exec_module(self, **kwargs):
        """Entrypoint for domain module"""
        domain: Domain = self.get_domain_by_properties(**kwargs)

        if domain is None:
            self.fail('failed to get domain')

        self.results['domain'] = domain._raw_json

        return self.results


def main():
    """Constructs and calls the Linode Domain Info module"""
    LinodeDomainInfo()


if __name__ == '__main__':
    main()
