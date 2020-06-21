# Zabbix Collection Changes

## devel

### Improvements
#### Modules:
  - zabbix_action - fixed error on changed API fields for Zabbix 5.0 [GitHub Issue](https://github.com/rockaut/community.zabbix/edit/fix_92)

### Bug Fixes:
#### Modules:
  - zabbix_action - now correctly selects mediatype for the (normal|recovery|update) operations with Zabbix 4.4 and newer. (PR [#90](https://github.com/ansible-collections/community.zabbix/pull/90))

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
