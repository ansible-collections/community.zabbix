# Zabbix collection for Ansible

This repo hosts the `community.zabbix` Ansible Collection.

The collection includes a variety of Ansible content to help automate the management of resources in Zabbix.

## Included content

Click on the name of a plugin or module to view that content's documentation:

  - **Connection Plugins**:
  - **Filter Plugins**:
  - **Inventory Source**:
    - [zabbix](https://github.com/ansible-collections/community.zabbix/blob/master/scripts/inventory/zabbix.py)
  - **Callback Plugins**:
  - **Lookup Plugins**:
  - **Modules**:
    - [zabbix\_action](https://docs.ansible.com/ansible/latest/modules/zabbix_action_module.html)
    - [zabbix\_group\_info](https://docs.ansible.com/ansible/latest/modules/zabbix_group_info_module.html)
    - [zabbix\_group](https://docs.ansible.com/ansible/latest/modules/zabbix_group_module.html)
    - zabbix\_host\_events\_info
    - [zabbix\_host\_info](https://docs.ansible.com/ansible/latest/modules/zabbix_host_info_module.html)
    - [zabbix\_hostmacro](https://docs.ansible.com/ansible/latest/modules/zabbix_hostmacro_module.html)
    - [zabbix\_host](https://docs.ansible.com/ansible/latest/modules/zabbix_host_module.html)
    - [zabbix\_maintenance](https://docs.ansible.com/ansible/latest/modules/zabbix_maintenance_module.html)
    - [zabbix\_map](https://docs.ansible.com/ansible/latest/modules/zabbix_map_module.html)
    - [zabbix\_mediatype](https://docs.ansible.com/ansible/latest/modules/zabbix_mediatype_module.html)
    - [zabbix\_proxy](https://docs.ansible.com/ansible/latest/modules/zabbix_proxy_module.html)
    - [zabbix\_screen](https://docs.ansible.com/ansible/latest/modules/zabbix_screen_module.html)
    - zabbix\_service
    - zabbix\_template\_info
    - [zabbix\_template](https://docs.ansible.com/ansible/latest/modules/zabbix_template_module.html)
    - zabbix\_user\_info
    - zabbix\_user
    - zabbix\_valuemap

## Supported Zabbix versions

## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the Zabbix collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install community.zabbix

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.zabbix
    version: v0.1.0
```

### Using modules from the Zabbix Collection in your playbooks

You can either call modules by their Fully Qualified Collection Namespace (FQCN), like `community.zabbix.zabbix_host`, or you can call modules by their short name if you list the `community.zabbix` collection in the playbook's `collections`, like so:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  collections:
    - community.zabbix

  tasks:
    - name: Ensure host is monitored by Zabbix.
      zabbix_host:
        server_url: https://zabbix.example.com
        login_user: username
        login_password: password
        host_name: '{{ inventory_hostname }}'
        host_groups:
          - Linux servers
        link_templates:
          - Template Module ICMP Ping
        status: enabled
        state: present
        interfaces:
          - type: 1
            main: 1
            dns: '{{ inventory_hostname }}'
        proxy: zbx-proxy.example.com
        macros:
          - macro: SITE
            value: '{{ ansible_domain }}'
      delegate_to: localhost
```

For documentation on how to use individual modules and other content included in this collection, please see the links in the 'Included content' section earlier in this README.

## Testing and Development

Coming soon

## Publishing New Versions

Coming soon

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

## Contributing

Coming soon
