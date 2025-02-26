# volume

Manage a Linode Volume.


- [Examples](#examples)
- [Parameters](#parameters)
- [Return Values](#return-values)

## Examples

```yaml
- name: Create a volume attached to an instance
  linode.cloud.volume:
    label: example-volume
    region: us-east
    size: 30
    linode_id: 12345
    state: present
```

```yaml
- name: Create an unattached volume
  linode.cloud.volume:
    label: example-volume
    region: us-east
    size: 30
    state: present
```

```yaml
- name: Resize a volume
  linode.cloud.volume:
    label: example-volume
    size: 50
    state: present
```

```yaml
- name: Detach a volume
  linode.cloud.volume:
    label: example-volume
    attached: false
    state: present
```

```yaml
- name: Delete a volume
  linode.cloud.volume:
    label: example-volume
    state: absent
```









## Parameters

| Field     | Type | Required | Description                                                                  |
|-----------|------|----------|------------------------------------------------------------------------------|
| `state` | `str` | **Required** | The desired state of the target.  (Choices:  `present` `absent`) |
| `label` | `str` | Optional | The Volume’s label, which is also used in the filesystem_path of the resulting volume.   |
| `config_id` | `int` | Optional | When creating a Volume attached to a Linode, the ID of the Linode Config to include the new Volume in.   |
| `linode_id` | `int` | Optional | The Linode this volume should be attached to upon creation. If not given, the volume will be created without an attachment.   |
| `region` | `str` | Optional | The location to deploy the volume in. See U(https://api.linode.com/v4/regions)   |
| `size` | `int` | Optional | The size of this volume, in GB. Be aware that volumes may only be resized up after creation.   |
| `attached` | `bool` | Optional | If true, the volume will be attached to a Linode. Otherwise, the volume will be detached.  ( Default: `True`) |
| `wait_timeout` | `int` | Optional | The amount of time, in seconds, to wait for a volume to have the active status.  ( Default: `240`) |





## Return Values

- `volume` - The volume in JSON serialized form.

    - Sample Response:
        ```json
        {
          "created": "2018-01-01T00:01:01",
          "filesystem_path": "/dev/disk/by-id/scsi-0Linode_Volume_my-volume",
          "hardware_type": "nvme",
          "id": 12345,
          "label": "my-volume",
          "linode_id": 12346,
          "linode_label": "linode123",
          "region": "us-east",
          "size": 30,
          "status": "active",
          "tags": [
            "example tag",
            "another example"
          ],
          "updated": "2018-01-01T00:01:01"
        }
        ```
    - See the [Linode API response documentation](https://www.linode.com/docs/api/volumes/#volume-view__responses) for a list of returned fields


