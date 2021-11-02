__Upgrade__

Table of content

- [1.0.0](#100)
  * [Roles](#roles)
    + [Proxy](#proxy)
    + [Java Gateway](#java-gateway)
- [0.2.0](#020)
  * [Roles](#roles-1)
    + [Agent](#agent)
    + [Server](#server)
    + [Proxy](#proxy-1)
    + [Web](#web)
    + [Java Gateway](#java-gateway-1)

This document provides an overview of all the changes that are needed to be applied to have a correctly working environment per version. If a version is not part of this document, then there are no changes needed to apply.

## 1.5.0

### Roles

#### Agent

The following properties are added in the `zabbix_agent` role.

* `zabbix_api_timeout = 30`
* `zabbix_agent_tls_subject = "{{ zabbix_agent_tlsservercertsubject }}"`
* `zabbix_agent2_server = "{{ zabbix_agent_server }}"`
* `zabbix_agent2_serveractive = "{{ zabbix_agent_serveractive }}"`
* `zabbix_agent2_allow_key = "{{ zabbix_agent_allow_key }}"`
* `zabbix_agent2_deny_key = "{{ zabbix_agent_deny_key }}"`
* `zabbix_agent2_tls_subject = "{{ zabbix_agent2_tlsservercertsubject }}"`

NOTE: The original properties can still be used but it's suggested to update to
use the new ones.

The following properties are renamed in the `zabbix_agent` role.

| From                          | To                            |
|-------------------------------|-------------------------------|
| zabbix_url                    | zabbix_api_server_url         |
| zabbix_agent_server_url       | zabbix_api_server_url         |
| zabbix_http_user              | zabbix_api_http_user          |
| zabbix_http_password          | zabbix_api_http_password      |
| zabbix_api_user               | zabbix_api_login_user         |
| zabbix_api_pass               | zabbix_api_login_pass         |
| zabbix_validate_certs         | zabbix_api_validate_certs     |
| zabbix_create_hostgroup       | zabbix_agent_hostgroups_state |
| zabbix_macros                 | zabbix_agent_macros           |
| zabbix_inventory_mode         | zabbix_agent_inventory_mode   |
| zabbix_link_templates         | zabbix_agent_link_templates   |
| zabbix_proxy                  | zabbix_agent_proxy            |
| zabbix_update_host            | zabbix_agent_host_update      |
| zabbix_create_host            | zabbix_agent_host_state       |
| zabbix_visible_hostname       | zabbix_agent_visible_hostname |

NOTE: the old parameters are still valid but it's suggested to update to use the
new ones.

#### Proxy

The following properties are added in the `zabbix_proxy` role.

* `zabbix_api_timeout = 30`
* `zabbix_proxy_tls_subject = "{{ zabbix_proxy_tlsservercertsubject }}"`

The following properties are renamed in the `zabbix_proxy` role.

| From                       | To                              |
|----------------------------|---------------------------------|
| zabbix_server_host         | zabbix_proxy_server             |
| zabbix_server_port         | zabbix_proxy_serverport         |
| zabbix_proxy_localbuffer   | zabbix_proxy_proxylocalbuffer   |
| zabbix_proxy_offlinebuffer | zabbix_proxy_proxyofflinebuffer |
| zabbix_create_proxy        | zabbix_proxy_state              |
| zabbix_url                 | zabbix_api_server_url           |
| zabbix_http_user           | zabbix_api_http_user            |
| zabbix_http_password       | zabbix_api_http_password        |
| zabbix_api_user            | zabbix_api_login_user           |
| zabbix_api_pass            | zabbix_api_login_pass           |
| zabbix_validate_certs      | zabbix_api_validate_certs       |

NOTE: the old parameters are still valid but it's suggested to update to use the
new ones.

## 1.0.0

### Roles

#### Proxy

The following property is renamed in the `zabbix_proxy` role.

|From|To|
|----|--|
|`zabbix_version`|`zabbix_proxy_version`|

NOTE: The `zabbix_version` can still be used, but will be deprecated in later releases.

#### Java Gateway

The following properties are renamed in the `zabbix_javagateway` role.

|From|To|
|----|--|
|`zabbix_version`|`zabbix_javagateway_version`|
|`javagateway_package_state`|`zabbix_javagateway_package_state`|
|`javagateway_pidfile`|`zabbix_javagateway_pidfile`|
|`javagateway_listenip`|`zabbix_javagateway_listenip`|
|`javagateway_listenport`|`zabbix_javagateway_listenport`|
|`javagateway_startpollers`|`zabbix_javagateway_startpollers`|

NOTE: The `zabbix_version` can still be used, but will be deprecated in later releases.

## 0.2.0

### Roles

#### Agent

A 1-on-1 copy of the Ansible role `dj-wasabi.zabbix-agent` to this collection. Due to naming of roles as part of a collection, some characters (Like the `-`) are not allowed anymore. This role is therefore renamed from `zabbix-agent` to `zabbix_agent`.

Example of using the role in this collection:
```yaml
- hosts: all
  roles:
    - role: community.zabbix.zabbix_agent
      zabbix_agent_server: 192.168.33.30
      zabbix_agent_serveractive: 192.168.33.30
```

#### Server

A 1-on-1 copy of the Ansible role `dj-wasabi.zabbix-server` to this collection. Due to naming of roles as part of a collection, some characters (Like the `-`) are not allowed anymore. This role is therefore renamed from `zabbix-server` to `zabbix_server`.

Example of using the role in this collection::
```yaml
- hosts: zabbix-server
  roles:
    - role: community.zabbix.zabbix_server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
```

#### Proxy

A 1-on-1 copy of the Ansible role `dj-wasabi.zabbix-proxy` to this collection. Due to naming of roles as part of a collection, some characters (Like the `-`) are not allowed anymore. This role is therefore renamed from `zabbix-proxy` to `zabbix_proxy`.

Example of using the role in this collection::
```yaml
- hosts: zabbix-proxy
  roles:
    - role: community.zabbix.zabbix_proxy
      zabbix_proxy_server: 192.168.1.1
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
```

#### Web

A 1-on-1 copy of the Ansible role `dj-wasabi.zabbix-web` to this collection. Due to naming of roles as part of a collection, some characters (Like the `-`) are not allowed anymore. This role is therefore renamed from `zabbix-web` to `zabbix_web`.

Example of using the role in this collection::
```yaml
- hosts: zabbix-web
  become: yes
  roles:
    - role: geerlingguy.apache
    - role: community.zabbix.zabbix_web
      zabbix_url: zabbix.mydomain.com
      zabbix_server_hostname: zabbix-server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
```

#### Java Gateway

A 1-on-1 copy of the Ansible role `dj-wasabi.zabbix-javagateway` to this collection. Due to naming of roles as part of a collection, some characters (Like the `-`) are not allowed anymore. This role is therefore renamed from `zabbix-javagateway` to `zabbix_javagateway`.

Example of using the role in this collection::
```yaml
- hosts: zabbix-server
  roles:
    - role: community.zabbix.zabbix_server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
      zabbix_server_javagateway: 192.168.1.1
    - role: community.zabbix.zabbix_javagateway
```
