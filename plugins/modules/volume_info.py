#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This module contains all of the functionality for Linode Volumes."""

from __future__ import absolute_import, division, print_function

# pylint: disable=unused-import
from typing import List, Any, Optional

from linode_api4 import Volume

from ansible_collections.linode.cloud.plugins.module_utils.linode_common import LinodeModuleBase
from ansible_collections.linode.cloud.plugins.module_utils.linode_helper import create_filter_and
from ansible_collections.linode.cloud.plugins.module_utils.linode_docs import global_authors, \
    global_requirements

import ansible_collections.linode.cloud.plugins.module_utils.doc_fragments.volume as docs_parent
import ansible_collections.linode.cloud.plugins.module_utils.doc_fragments.volume_info as docs

linode_volume_info_spec = dict(
    # We need to overwrite attributes to exclude them as requirements
    state=dict(type='str', required=False, doc_hide=True),

    id=dict(
        type='int', required=False,
        description=[
            'The ID of the Volume.',
            'Optional if `label` is defined.'
        ]),

    label=dict(
        type='str', required=False,
        description=[
            'The label of the Volume.',
            'Optional if `id` is defined.'
        ])
)

specdoc_meta = dict(
    description=[
        'Get info about a Linode Volume.'
    ],
    requirements=global_requirements,
    author=global_authors,
    spec=linode_volume_info_spec,
    examples=docs.specdoc_examples,
    return_values=dict(
        volume=dict(
            description='The volume in JSON serialized form.',
            docs_url='https://www.linode.com/docs/api/volumes/#volume-view__responses',
            type='dict',
            sample=docs_parent.result_volume_samples
        )
    )
)

linode_volume_valid_filters = [
    'id', 'label'
]


class LinodeVolumeInfo(LinodeModuleBase):
    """Module for getting info about a Linode Volume"""

    def __init__(self) -> None:
        self.module_arg_spec = linode_volume_info_spec
        self.required_one_of: List[str] = []
        self.results = dict(
            volume=None,
        )

        self._volume = None

        super().__init__(module_arg_spec=self.module_arg_spec,
                         required_one_of=self.required_one_of)

    def _get_matching_volume(self, spec_args: dict) -> Optional[Volume]:
        filter_items = {k: v for k, v in spec_args.items()
                        if k in linode_volume_valid_filters and v is not None}

        filter_statement = create_filter_and(Volume, filter_items)

        try:
            # Special case because ID is not filterable
            if 'id' in filter_items.keys():
                result = Volume(self.client, spec_args.get('id'))
                result._api_get()  # Force lazy-loading

                return result

            return self.client.volumes(filter_statement)[0]
        except IndexError:
            return None
        except Exception as exception:
            return self.fail(msg='failed to get volume {0}'.format(exception))

    def exec_module(self, **kwargs: Any) -> Optional[dict]:
        """Entrypoint for volume info module"""

        volume = self._get_matching_volume(kwargs)

        if volume is None:
            self.fail('failed to get volume')

        self.results['volume'] = volume._raw_json

        return self.results


def main() -> None:
    """Constructs and calls the Linode Volume info module"""
    LinodeVolumeInfo()


if __name__ == '__main__':
    main()
