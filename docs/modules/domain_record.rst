.. _domain_record_module:


domain_record
=============

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Manage Linode domain records.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- linode_api4 >= 3.0



Parameters
----------

  name (True, str, None)
    The name of this Record.


  type (optional, str, None)
    The type of Record this is in the DNS system.


  port (optional, int, None)
    The port this Record points to.

    Only valid and required for SRV record requests.


  priority (optional, int, None)
    The priority of the target host for this Record.

    Lower values are preferred.

    Only valid for MX and SRV record requests.

    Required for SRV record requests.


  protocol (optional, str, None)
    The protocol this Record’s service communicates with.

    An underscore (_) is prepended automatically to the submitted value for this property.

    Only valid for SRV record requests.


  service (optional, str, None)
    The name of the service.

    An underscore (_) is prepended and a period (.) is appended automatically to the submitted value for this property.

    Only valid and required for SRV record requests.


  tag (optional, str, None)
    The tag portion of a CAA record.

    Only valid and required for CAA record requests.


  target (optional, str, None)
    The target for this Record.


  ttl_sec (optional, int, None)
    Time to Live

    The amount of time in seconds that this Domain’s records may be cached by resolvers or other domain servers.


  weight (optional, int, None)
    The relative weight of this Record used in the case of identical priority.









Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create a A record
      linode.cloud.domain_record:
        domain: my-domain.com
        name: my-subdomain
        type: 'A'
        target: '127.0.0.1'
        state: present

    - name: Delete a domain record
      linode.cloud.domain:
        domain: my-domain.com
        name: my-subdomain
        state: absent




Return Values
-------------

**record (always, dict):**

The domain record in JSON serialized form.

`Linode Response Object Documentation <https://www.linode.com/docs/api/domains/#domain-record-view>`_

Sample Response:

.. code-block:: JSON

    {
     "created": "xxxxx",
     "id": "xxxxx",
     "name": "xxxx",
     "port": 0,
     "priority": 0,
     "protocol": null,
     "service": null,
     "tag": null,
     "target": "127.0.0.1",
     "ttl_sec": 3600,
     "type": "A",
     "updated": "xxxxx",
     "weight": 55
    }





Status
------




- This module is maintained by Linode.



Authors
~~~~~~~

- Luke Murphy (@decentral1se)
- Charles Kenney (@charliekenney23)
- Phillip Campbell (@phillc)
- Lena Garber (@lbgarber)

