#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This module contains all of the functionality for Linode Object Storage Cluster info."""

from __future__ import absolute_import, division, print_function

# pylint: disable=unused-import
from typing import List, Optional, Any

from linode_api4 import ObjectStorageKeys, ObjectStorageCluster

from ansible_collections.linode.cloud.plugins.module_utils.linode_common import LinodeModuleBase
from ansible_collections.linode.cloud.plugins.module_utils.linode_helper import create_filter_and
from ansible_collections.linode.cloud.plugins.module_utils.linode_docs import global_authors, \
    global_requirements

import ansible_collections.linode.cloud.plugins.module_utils.doc_fragments.object_cluster_info \
    as docs

linode_object_cluster_info_spec = dict(
    # We need to overwrite attributes to exclude them as requirements
    state=dict(type='str', required=False, doc_hide=True),
    label=dict(type='str', required=False, doc_hide=True),

    id=dict(
        type='str', required=False,
        description='The unique id given to the clusters.'),

    region=dict(
        type='str', required=False,
        description='The region the clusters are in.'),

    domain=dict(
        type='str', required=False,
        description='The domain of the clusters.'),

    static_site_domain=dict(
        type='str', required=False,
        description='The static-site domain of the clusters.')
)

specdoc_meta = dict(
    description=[
        'Get info about a Linode Object Storage Cluster.'
    ],
    requirements=global_requirements,
    author=global_authors,
    spec=linode_object_cluster_info_spec,
    examples=docs.specdoc_examples,
    return_values=dict(
        clusters=dict(
            description='The Object Storage clusters in JSON serialized form.',
            docs_url='https://www.linode.com/docs/api/object-storage/#cluster-view__responses',
            type='list',
            sample=docs.result_clusters_samples
        )
    )
)

linode_object_cluster_valid_filters = [
    'id', 'region', 'domain', 'static_site_domain'
]


class LinodeObjectStorageClustersInfo(LinodeModuleBase):
    """Module for getting info about a Linode Object Storage Cluster"""

    def __init__(self) -> None:
        self.module_arg_spec = linode_object_cluster_info_spec
        self.required_one_of: List[str] = []
        self.results = dict(
            changed=False,
            actions=[],
            clusters=None,
        )

        super().__init__(module_arg_spec=self.module_arg_spec,
                         required_one_of=self.required_one_of)

    def _get_matching_cluster(self) -> Optional[List[ObjectStorageCluster]]:
        filter_items = {k: v for k, v in self.module.params.items()
                        if k in linode_object_cluster_valid_filters and v is not None}

        filter_statement = create_filter_and(ObjectStorageCluster, filter_items)

        try:
            # Special case because ID is not filterable
            if 'id' in filter_items.keys():
                result = ObjectStorageCluster(self.client, self.module.params.get('id'))
                result._api_get()  # Force lazy-loading

                return [result]

            return self.client.object_storage.clusters(filter_statement)
        except IndexError:
            return None
        except Exception as exception:
            return self.fail(msg='failed to get clusters {0}'.format(exception))

    def exec_module(self, **kwargs: Any) -> Optional[dict]:
        """Constructs and calls the Linode Object Storage Clusters module"""

        clusters = self._get_matching_cluster()

        if clusters is None:
            return self.fail('failed to get clusters')

        self.results['clusters'] = [cluster._raw_json for cluster in clusters]

        return self.results


def main() -> None:
    """Constructs and calls the Linode Object Storage Clusters module"""

    LinodeObjectStorageClustersInfo()


if __name__ == '__main__':
    main()
