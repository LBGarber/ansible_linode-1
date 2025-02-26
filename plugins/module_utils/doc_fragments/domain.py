"""Documentation fragments for the domain module"""

specdoc_examples = ['''
- name: Create a domain 
  linode.cloud.domain:
    domain: my-domain.com
    type: master
    state: present''', '''
- name: Delete a domain
  linode.cloud.domain:
    domain: my-domain.com
    state: absent''']

result_domain_samples = ['''{
  "axfr_ips": [],
  "description": null,
  "domain": "example.org",
  "expire_sec": 300,
  "group": null,
  "id": 1234,
  "master_ips": [],
  "refresh_sec": 300,
  "retry_sec": 300,
  "soa_email": "admin@example.org",
  "status": "active",
  "tags": [
    "example tag",
    "another example"
  ],
  "ttl_sec": 300,
  "type": "master"
}''']

result_records_samples = ['''[
  {
    "created": "2018-01-01T00:01:01",
    "id": 123456,
    "name": "test",
    "port": 80,
    "priority": 50,
    "protocol": null,
    "service": null,
    "tag": null,
    "target": "192.0.2.0",
    "ttl_sec": 604800,
    "type": "A",
    "updated": "2018-01-01T00:01:01",
    "weight": 50
  }
]''']
