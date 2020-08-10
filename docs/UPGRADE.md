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
      zabbix_server_host: 192.168.1.1
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
