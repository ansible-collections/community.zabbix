# Zabbix collection for Ansible

![plugins](https://github.com/ansible-collections/community.zabbix/workflows/plugins/badge.svg)

This repo hosts the `community.zabbix` Ansible Collection.

The collection includes a variety of Ansible content to help automate the management of resources in Zabbix.

## Included content

Click on the name of a plugin or module to view that content's documentation:

  - **Inventory Source**:
    - [zabbix](scripts/inventory/zabbix.py)
  - **Modules**:
    - [zabbix_action](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_action_module.html)
    - [zabbix_group_info](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_group_info_module.html)
    - [zabbix_discovery_rule](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_discovery_rule_module.html)
    - [zabbix_group](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_group_module.html)
    - [zabbix_host_events_info](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_host_events_info_module.html)
    - [zabbix_host_info](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_host_info_module.html)
    - [zabbix_hostmacro](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_hostmacro_module.html)
    - [zabbix_host](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_host_module.html)
    - [zabbix_maintenance](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_maintenance_module.html)
    - [zabbix_map](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_map_module.html)
    - [zabbix_mediatype](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_mediatype_module.html)
    - [zabbix_proxy](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_proxy_module.html)
    - [zabbix_screen](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_screen_module.html)
    - [zabbix_service](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_service_module.html)
    - [zabbix_template_info](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_template_info_module.html)
    - [zabbix_template](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_template_module.html)
    - [zabbix_user_info](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_user_info_module.html)
    - [zabbix_user](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_user_module.html)
    - [zabbix_usergroup](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_usergroup_module.html)
    - [zabbix_valuemap](https://docs.ansible.com/ansible/2.10/collections/community/zabbix/zabbix_valuemap_module.html)
  - **Roles**:
    - [zabbix_agent](docs/ZABBIX_AGENT_ROLE.md)
    - [zabbix_javagateway](docs/ZABBIX_JAVAGATEWAY_ROLE.md)
    - [zabbix_proxy](docs/ZABBIX_PROXY_ROLE.md)
    - [zabbix_server](docs/ZABBIX_SERVER_ROLE.md)
    - [zabbix_web](docs/ZABBIX_WEB_ROLE.md)

## Installation

### Requirements

Each component in this collection requires additional dependencies. Review components you are interested in by visiting links present in the [Included content](#included-content) section.

This is especially important for some of the Zabbix roles that require you to **install additional standalone roles** from Ansible Galaxy.

For the majority of modules, however, you can get away with just:

```bash
pip install zabbix-api
```

### Installing the Collection from Ansible Galaxy

Before using the Zabbix collection, you need to install it with the Ansible Galaxy CLI:

```bash
ansible-galaxy collection install community.zabbix
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.zabbix
    version: 1.0.0
```

### Upgrading collection

Make sure to read [UPGRADE](docs/UPGRADE.md) document before installing newer version of this collection.

## Usage

*Please note that these are not working examples. For documentation on how to use content included in this collection, refer to the links in the [Included content](#included-content) section.*

To use a module or role from this collection, reference them with their Fully Qualified Collection Namespace (FQCN) like so:

```yaml
---
- name: Using Zabbix collection
  hosts: localhost
  roles:
    - role: community.zabbix.zabbix_agent
      zabbix_agent_server: zabbix.example.com
      ...

  tasks:
    - name: Ensure host is monitored by Zabbix
      community.zabbix.zabbix_host:
        server_url: https://zabbix.example.com
        ...
```

Or you include collection name `community.zabbix` in the playbook's `collections` element, like this:

```yaml
---
- name: Using Zabbix collection
  hosts: localhost
  collections:
    - community.zabbix

  roles:
    - role: zabbix_agent
      zabbix_agent_server: zabbix.example.com
      ...

  tasks:
    - name: Ensure host is monitored by Zabbix
      zabbix_host:
        server_url: https://zabbix.example.com
        ...
```

## Supported Zabbix versions

As a main priority, this collection aims to cover all of the currently supported Zabbix releases, which are noted on the [Zabbix Life Cycle & Release Policy](https://www.zabbix.com/life_cycle_and_release_policy) page.
Other versions are supported too, but not as strictly (changes would not be actively tested against them).

If you find any inconsistencies with the version of Zabbix you are using, feel free to open a pull request or an issue and we will try to address it as soon as possible.
In case of pull requests, please make sure that your changes will not break any existing functionality for currently supported Zabbix releases.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for more information about how to contribute to this repository.

Please also feel free to stop by our [Gitter community](https://gitter.im/community-zabbix/community).

## License

GNU General Public License v3.0 or later

See [LICENSE](LICENSE) to see the full text.
