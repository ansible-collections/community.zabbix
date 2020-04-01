# Zabbix collection for Ansible

![](https://github.com/ansible-collections/community.zabbix/workflows/CI/badge.svg)

This repo hosts the `community.zabbix` Ansible Collection.

The collection includes a variety of Ansible content to help automate the management of resources in Zabbix.

## Supported Zabbix versions

As a main priority, this collection aims to cover all of the currently supported Zabbix releases, which are noted on the [Zabbix Life Cycle & Release Policy](https://www.zabbix.com/life_cycle_and_release_policy) page.
Other versions are supported too, but not as strictly (e.g. we won't be testing new changes against them).

If you find any inconsistencies with the version of Zabbix you are using, feel free to open a pull request or an issue and we will try to address it as soon as possible.
In case of pull requests, please make sure that your changes won't break any existing functionality for currently supported Zabbix releases.

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

### Testing with `ansible-test`

As of right now, `ansible-test` will fail unless executed in a path containing a specific component. Easiest way to start working on this collection is to clone it to the `~/ansible_collections/community/zabbix` directory. To use this modified version of the collection in playbooks, set [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths) to the `~/ansible_collections` directory.

Running test suites locally requires few dependencies (use virtualenv):

    pip install docker-compose zabbix-api

The `tests` directory contains configuration for running sanity and integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

Collection's integration test suite can be run with the commands (`zabbix_version=X.Y` will be expanded to `X.Y-latest`):

    export zabbix_version=X.Y
    docker-compose up -d
    ansible-test integration -v --color --retry-on-error --continue-on-error --diff
    docker-compose down

Collection's sanity test suite can be run with the commands:

    ansible-test sanity -v --color --docker --python 3.6

### Developing new Zabbix modules

New modules must adhere to these rules:

* Features and modules must be compatible with [currently supported Zabbix releases](https://www.zabbix.com/life_cycle_and_release_policy).
* New logic for existing modules or new modules are submitted with integration tests included.
* Must include the same set of general options as other zabbix modules both in `DOCUMENTATION` block (via document fragment) and `argument_spec`.
* Must implement proper logout mechanism.
* Use the same version of `zabbix-api` library as the other modules.
* Comply with [Ansible module best practices](https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_best_practices.html).

## Publishing New Versions

The current process for publishing new collection versions is manual, and requires a user who has access to the `community.zabbix` namespace on Ansible Galaxy to publish the build artifact.

  1. Ensure `CHANGELOG.md` contains all the latest changes.
  2. Update `galaxy.yml` and this README's `requirements.yml` example with the new `version` for the collection.
  3. Tag the version in Git and push to GitHub.
  4. Run the following commands to build and release the new version on Galaxy:

     ```
     ansible-galaxy collection build
     ansible-galaxy collection publish ./community-zabbix-$VERSION_HERE.tar.gz
     ```

After the version is published, verify it exists on the [Zabbix Collection Galaxy page](https://galaxy.ansible.com/community/zabbix).

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

## Contributing

Any contribution is welcome and we only ask contributors to:

* Provide at least integration tests for any contribution.
* Create an issues for any significant contribution that would change a large portion of the code base.

If you are interested in joining us as a maintainer, either open an issue or contact @D3DeFi or @sky-joker directly :)
