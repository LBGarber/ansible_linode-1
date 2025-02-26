# firewall

Manage Linode Firewalls.


- [Examples](#examples)
- [Parameters](#parameters)
- [Return Values](#return-values)

## Examples

```yaml
- name: Create a Linode Firewall
  linode.cloud.firewall:
    label: 'my-firewall'
    devices:
      - id: 123
        type: linode
    rules:
      inbound_policy: DROP
      inbound:
        - label: allow-http-in
          addresses:
            ipv4:
              - 0.0.0.0/0
            ipv6:
              - 'ff00::/8'
          description: Allow inbound HTTP and HTTPS connections.
          ports: '80,443'
          protocol: TCP
          action: ACCEPT

      outbound_policy: DROP
      outbound:
        - label: allow-http-out
          addresses:
            ipv4:
              - 0.0.0.0/0
            ipv6:
              - 'ff00::/8'
          description: Allow outbound HTTP and HTTPS connections.
          ports: '80,443'
          protocol: TCP
          action: ACCEPT
    state: present
```

```yaml
- name: Delete a Linode Firewall
  linode.cloud.firewall:
    label: 'my-firewall'
    state: absent
```









## Parameters

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `state` | `str` | **Required** | The desired state of the target.  (Choices:  `present` `absent`) |
| `label` | `str` | Optional | The unique label to give this Firewall.   |
| [`devices` (sub-options)](#devices) | `list` | Optional | The devices that are attached to this Firewall.   |
| [`rules` (sub-options)](#rules) | `dict` | Optional | The inbound and outbound access rules to apply to this Firewall.   |
| `status` | `str` | Optional | The status of this Firewall.   |





### devices

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `id` | `int` | **Required** | The unique ID of the device to attach to this Firewall.   |
| `type` | `str` | Optional | The type of device to be attached to this Firewall.  ( Default: `linode`) |





### rules

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| [`inbound` (sub-options)](#inbound) | `list` | Optional | A list of rules for inbound traffic.   |
| `inbound_policy` | `str` | Optional | The default behavior for inbound traffic.   |
| [`outbound` (sub-options)](#outbound) | `list` | Optional | A list of rules for outbound traffic.   |
| `outbound_policy` | `str` | Optional | The default behavior for outbound traffic.   |





### inbound

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `label` | `str` | **Required** | The label of this rule.   |
| `action` | `str` | **Required** | Controls whether traffic is accepted or dropped by this rule.   |
| [`addresses` (sub-options)](#addresses) | `dict` | Optional | Allowed IPv4 or IPv6 addresses.   |
| `description` | `str` | Optional | A description for this rule.   |
| `ports` | `str` | Optional | A string representing the port or ports on which traffic will be allowed. See U(https://www.linode.com/docs/api/networking/#firewall-create)   |
| `protocol` | `str` | Optional | The type of network traffic to allow.   |





### addresses

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `ipv4` | `list` | Optional | A list of IPv4 addresses or networks. Must be in IP/mask format.   |
| `ipv6` | `list` | Optional | A list of IPv4 addresses or networks. Must be in IP/mask format.   |





### outbound

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `label` | `str` | **Required** | The label of this rule.   |
| `action` | `str` | **Required** | Controls whether traffic is accepted or dropped by this rule.   |
| [`addresses` (sub-options)](#addresses) | `dict` | Optional | Allowed IPv4 or IPv6 addresses.   |
| `description` | `str` | Optional | A description for this rule.   |
| `ports` | `str` | Optional | A string representing the port or ports on which traffic will be allowed. See U(https://www.linode.com/docs/api/networking/#firewall-create)   |
| `protocol` | `str` | Optional | The type of network traffic to allow.   |





## Return Values

- `firewall` - The Firewall description in JSON serialized form.

    - Sample Response:
        ```json
        {
          "created": "2018-01-01T00:01:01",
          "id": 123,
          "label": "firewall123",
          "rules": {
            "inbound": [
              {
                "action": "ACCEPT",
                "addresses": {
                  "ipv4": [
                    "192.0.2.0/24"
                  ],
                  "ipv6": [
                    "2001:DB8::/32"
                  ]
                },
                "description": "An example firewall rule description.",
                "label": "firewallrule123",
                "ports": "22-24, 80, 443",
                "protocol": "TCP"
              }
            ],
            "inbound_policy": "DROP",
            "outbound": [
              {
                "action": "ACCEPT",
                "addresses": {
                  "ipv4": [
                    "192.0.2.0/24"
                  ],
                  "ipv6": [
                    "2001:DB8::/32"
                  ]
                },
                "description": "An example firewall rule description.",
                "label": "firewallrule123",
                "ports": "22-24, 80, 443",
                "protocol": "TCP"
              }
            ],
            "outbound_policy": "DROP"
          },
          "status": "enabled",
          "tags": [
            "example tag",
            "another example"
          ],
          "updated": "2018-01-02T00:01:01"
        }
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/networking/#firewall-view) for a list of returned fields


- `devices` - A list of Firewall devices JSON serialized form.

    - Sample Response:
        ```json
        [
          {
            "created": "2018-01-01T00:01:01",
            "entity": {
              "id": 123,
              "label": "my-linode",
              "type": "linode",
              "url": "/v4/linode/instances/123"
            },
            "id": 123,
            "updated": "2018-01-02T00:01:01"
          }
        ]
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/networking/#firewall-device-view) for a list of returned fields


