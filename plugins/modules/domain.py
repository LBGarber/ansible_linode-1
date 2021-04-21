#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This module contains all of the functionality for Linode Domains."""

from __future__ import absolute_import, division, print_function

# pylint: disable=unused-import
from linode_api4 import Domain

from ansible_collections.linode.cloud.plugins.module_utils.linode_common import LinodeModuleBase
from ansible_collections.linode.cloud.plugins.module_utils.linode_helper import filter_null_values

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

linode_domain_spec = dict(
    domain=dict(type='str', required=True),
    type=dict(type='str'),
    axfr_ips=dict(type='list', elements='str'),
    description=dict(type='str'),
    expire_sec=dict(type='int'),
    group=dict(type='str'),
    master_ips=dict(type='list', elements='str'),
    refresh_sec=dict(type='int'),
    retry_sec=dict(type='int'),
    soa_email=dict(type='str'),
    status=dict(type='str'),
    ttl_sec=dict(type='int'),

    # Label should be ignored in this context
    label=dict(type='str')
)

class LinodeDomain(LinodeModuleBase):
    """Configuration class for Linode domain resource"""

    def __init__(self):
        self.module_arg_spec = linode_domain_spec
        self.required_one_of = ['state']
        self.results = dict(
            changed=False,
            actions=[],
            domain=None,
        )

        self._domain: Domain = None

        super().__init__(module_arg_spec=self.module_arg_spec,
                         required_one_of=self.required_one_of)

    def get_domain_by_domain(self, domain: str):
        """Gets the domain with the given domain string"""

        try:
            return self.client.domains(Domain.domain == domain)[0]
        except IndexError:
            return None
        except Exception as exception:
            self.fail(msg='failed to get domain {0}: {1}'.format(domain, exception))

    def create_domain(self, **kwargs):
        """Creates a domain with the given kwargs"""

        domain: str = kwargs.pop('domain')
        master: bool = kwargs.pop('type') == 'master'

        try:
            return self.client.domain_create(domain, master, **kwargs)
        except Exception as exception:
            self.fail(msg='failed to create domain: {0}'.format(exception))

    def __update_domain(self, domain_object: Domain, **kwargs):
        """Updates the domain if any changes are found"""

        should_update: bool = False

        for key, value in filter_null_values(kwargs).items():
            if hasattr(domain_object, key) and value != getattr(domain_object, key):
                should_update = True
                setattr(domain_object, key, value)

        if not should_update:
            return

        # Group should not be updated if None
        if domain_object.group == '':
            domain_object.group = None

        try:
            domain_object.save()
        except Exception as exception:
            self.fail(msg='failed to update domain: {0}'.format(exception))

        self.register_action('Updated domain {0}'.format(domain_object.domain))

    def __handle_domain(self, **kwargs):
        """Updates the domain defined in kwargs"""

        domain: str = kwargs.get('domain')

        self._domain = self.get_domain_by_domain(domain)

        # Create the domain if it does not already exist
        if self._domain is None:
            self._domain = self.create_domain(**kwargs)
            self.register_action('Created domain {0}'.format(domain))

        # Make necessary updates
        self.__update_domain(self._domain, **kwargs)

        # Force lazy-loading
        self._domain._api_get()

        self.results['domain'] = self._domain._raw_json

    def __handle_domain_absent(self, **kwargs):
        """Updates the domain for the absent state"""

        domain: str = kwargs.get('domain')

        self._domain = self.get_domain_by_domain(domain)

        if self._domain is not None:
            self.results['domain'] = self._domain._raw_json
            self._domain.delete()
            self.register_action('Deleted domain {0}'.format(domain))

    def exec_module(self, **kwargs):
        """Entrypoint for domain module"""
        state = kwargs.get('state')

        if state == 'absent':
            self.__handle_domain_absent(**kwargs)
            return self.results

        self.__handle_domain(**kwargs)

        return self.results


def main():
    """Constructs and calls the Linode Domain module"""
    LinodeDomain()


if __name__ == '__main__':
    main()
