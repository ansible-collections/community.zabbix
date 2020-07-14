# Zabbix Collection Changes

## devel

### New modules:
  - `zabbix_discovery_rule` - Create/delete/update Zabbix discovery rules. (PR [#111](https://github.com/ansible-collections/community.zabbix/pull/111))
  - `zabbix_usergroup` - Create/update or delete Zabbix user groups. (PR [#119](https://github.com/ansible-collections/community.zabbix/pull/119))

### Improvements
#### Modules:
  - zabbix_action - fixed error on changed API fields `*default_message` and `*default_subject` for Zabbix 5.0 (PR [#92](https://github.com/ansible-collections/community.zabbix/pull/92)).
  - zabbix_action - parameter `ssh_auth_type` for SSH `remote_command` operation now correctly identifies which other parameters are required (PR [#113](https://github.com/ansible-collections/community.zabbix/pull/113)).
  - zabbix_action - no longer requires `password` and `ssh_*key_file` parameters at the same time for `remote_command` operations of type SSH (PR [#113](https://github.com/ansible-collections/community.zabbix/pull/113)).
  - zabbix_mediatype - now supports new `webhook` media type (PR [#82](https://github.com/ansible-collections/community.zabbix/pull/82)).
  - zabbix_mediatype - new options `message_templates`, `description` and many more related to `type=webhook` (PR [#82](https://github.com/ansible-collections/community.zabbix/pull/82)).
  - zabbix_discovery_rule - refactoring module to use `module_utils` classes and functions, adjust return values on success, add documentation for return values (PR [#120](https://github.com/ansible-collections/community.zabbix/pull/120)).
  - zabbix_discovery_rule - refactoring the module to remove unnecessary variables and fix a variable typo (PR [#129](https://github.com/ansible-collections/community.zabbix/pull/129))

### Bug Fixes:
#### Modules:
  - zabbix_action - now correctly selects mediatype for the (normal|recovery|update) operations with Zabbix 4.4 and newer. (PR [#90](https://github.com/ansible-collections/community.zabbix/pull/90))
  - zabbix_action - clarified choices for the `inventory` paramters in `*operations` sub option to `manual` and `automatic` (PR [#113](https://github.com/ansible-collections/community.zabbix/pull/113)).
  - zabbix_action - module will no longer fail when searching for global script provided to `script_name` parameter (PR [#113](https://github.com/ansible-collections/community.zabbix/pull/113)).
  - zabbix_service - fixed the zabbix_service has no idempotency with Zabbix 5.0 (PR [#116](https://github.com/ansible-collections/community.zabbix/pull/116))

## 0.2.0

### New roles:
  - `zabbix_agent` previously known as [dj-wasabi/zabbix-agent](https://galaxy.ansible.com/dj-wasabi/zabbix-agent)
  - `zabbix_javagateway` previously known as [dj-wasabi/zabbix-javagateway](https://galaxy.ansible.com/dj-wasabi/zabbix-javagateway)
  - `zabbix_proxy` previously known as [dj-wasabi/zabbix-proxy](https://galaxy.ansible.com/dj-wasabi/zabbix-proxy)
  - `zabbix_server` previously known as [dj-wasabi/zabbix-server](https://galaxy.ansible.com/dj-wasabi/zabbix-server)
  - `zabbix_web` previously known as [dj-wasabi/zabbix-web](https://galaxy.ansible.com/dj-wasabi/zabbix-web)

### Major Changes:
#### Roles:
  - Role names are now using underscores(\_) instead of hyphens(-) (example: `community.zabbix.zabbix_agent` instead of `dj-wasabi/zabbix-agent`).

### Improvements:
#### Modules:
  - zabbix_action - new alias `update_operations` for `acknowledge_operations` parameter.
  - zabbix_host - now supports Zabbix 5.0 (PR #51).
  - zabbix_host - new option `details` (additional SNMP details) for `interfaces` parameter (PR #51).
  - zabbix_host - `macros` now support new macro types `text` and `secret` (PR #51).
  - zabbix_proxy - now supports Zabbix 5.0 (PR #53).
  - zabbix_screen - `host_group` parameter now accepts multiple groups (PR #68).

#### Roles:
  - Documentation for roles moved to `docs/` sub-directory in the collection.

### Bug Fixes:
#### Modules:
  - zabbix_action - documented `value2` parameter and `notify_all_involved` option.
  - zabbix_maintenance - changing value of `description` parameter now actually updates maintenance's description.
  - zabbix_template - no longer imports template from `template_json` or `template_xml` when using `ansible-playbook --check`.
  - zabbix_template - is now able to perform `state=dump` when using `ansible-playbook --check`.

## 0.1.0
  - Initial migration of Zabbix content from Ansible core (2.9 / devel), including content:
    - **Connection Plugins**:
    - **Filter Plugins**:
    - **Inventory Source**:
      - `zabbix`
    - **Callback Plugins**:
    - **Lookup Plugins**:
    - **Modules**:
      - `zabbix_action`
      - `zabbix_group_facts`
      - `zabbix_group_info`
      - `zabbix_group`
      - `zabbix_host_events_info`
      - `zabbix_host_facts`
      - `zabbix_host_info`
      - `zabbix_hostmacro`
      - `zabbix_host`
      - `zabbix_maintenance`
      - `zabbix_map`
      - `zabbix_mediatype`
      - `zabbix_proxy`
      - `zabbix_screen`
      - `zabbix_service`
      - `zabbix_template_info`
      - `zabbix_template`
      - `zabbix_user_info`
      - `zabbix_user`
      - `zabbix_valuemap`
