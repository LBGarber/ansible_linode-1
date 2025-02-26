# Linode Ansible Collection
[![Ansible Galaxy](https://img.shields.io/badge/galaxy-linode.cloud-660198.svg?style=flat)](https://galaxy.ansible.com/linode/cloud/) 
![Build](https://img.shields.io/github/workflow/status/linode/ansible_linode/Run%20Integration%20Tests/main?label=tests)
![Code Quality](https://img.shields.io/lgtm/grade/python/github/linode/ansible_linode?label=code%20quality)

The Ansible Linode Collection contains various plugins for managing Linode services.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.9.10**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

<!--start collection content-->
### Modules
Name | Description
--- | ---
[linode.cloud.domain](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/domain.md)|Create and destroy domains.
[linode.cloud.domain_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/domain_info.md)|Gather info about an existing domain.
[linode.cloud.domain_record](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/domain_record.md)|Create and destroy domain records.
[linode.cloud.domain_record_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/domain_record_info.md)|Gather info about an existing domain record.
[linode.cloud.firewall](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/firewall.md)|Create and destroy Firewalls.
[linode.cloud.firewall_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/firewall_info.md)|Gather info about an existing Firewall.
[linode.cloud.firewall_device](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/firewall_device.md)|Manage Firewall Devices.
[linode.cloud.instance](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/instance.md)|Create and destroy Linodes.
[linode.cloud.instance_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/instance_info.md)|Gather info about an existing Linode instance.
[linode.cloud.lke_cluster](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/lke_cluster.md)|Manage LKE clusters.
[linode.cloud.lke_cluster_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/lke_cluster_info.md)|Gather info about an existing LKE cluster.
[linode.cloud.lke_node_pool](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/lke_node_pool.md)|Manage LKE Node Pools.
[linode.cloud.nodebalancer](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/nodebalancer.md)|Create, destroy, and configure NodeBalancers.
[linode.cloud.nodebalancer_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/nodebalancer_info.md)|Gather info about an existing NodeBalancer.
[linode.cloud.nodebalancer_node](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/nodebalancer_node.md)|Manage NodeBalancer nodes.
[linode.cloud.object_cluster_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/object_cluster_info.md)|Gather info about Object Storage clusters.
[linode.cloud.object_keys](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/object_keys.md)|Create and destroy Object Storage keys.
[linode.cloud.stackscript](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/stackscript.md)|Create and destroy StackScripts.
[linode.cloud.token](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/token.md)|Create and destroy Tokens.
[linode.cloud.vlan_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/vlan_info.md)|Gather info about an existing Linode VLAN.
[linode.cloud.volume](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/volume.md)|Create, destroy, and attach Linode volumes.
[linode.cloud.volume_info](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/modules/volume_info.md)|Gather info about an existing Linode volume.

### Inventory
Name | Description
--- | ---
[linode.cloud.instance](https://github.com/linode/ansible_linode/blob/v0.7.1/docs/inventory/instance.rst)|Reads instance inventories from Linode.

<!--end collection content-->

## Installation

You can install the Linode collection with the Ansible Galaxy CLI:

```shell
ansible-galaxy collection install linode.cloud
```

The python module dependencies are not installed by `ansible-galaxy`.  They can
be manually installed using pip:

```shell
pip install -r requirements.txt
```

## Usage
Once the Linode Ansible collection is installed, it can be referenced by its [Fully Qualified Collection Namespace (FQCN)](https://github.com/ansible-collections/overview#terminology): `linode.cloud.module_name`.

In order to use this collection, the `LINODE_API_TOKEN` environment variable must be set to a valid Linode API v4 token. 
Alternatively, you can pass your Linode API v4 token into the `api_token` option for each Linode module you reference.

#### Example Playbook
```yaml
---
- name: create linode instance
  hosts: localhost
  tasks:
    - name: Create a Linode instance    
      linode.cloud.instance:
        label: my-linode
        type: g6-nanode-1
        region: us-east
        image: linode/ubuntu20.04
        root_pass: verysecurepassword!!!
        state: present
```

For more information on Ansible collection usage, see [Ansible's official usage guide](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html).

## Examples

Use-case examples for this collection can be found [here](./examples/README.md).

## Licensing

GNU General Public License v3.0.

See [COPYING](COPYING) to see the full text.
