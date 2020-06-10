Table of Content

- [Overview](#overview)
- [Upgrades](#upgrades)
  * [1.0.0](#100)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
    + [Zabbix 4.2](#zabbix-42)
    + [Zabbix 4.0](#zabbix-40)
    + [Zabbix 3.4](#zabbix-34)
    + [Zabbix 3.2](#zabbix-32)
    + [Zabbix 3.0](#zabbix-30)
    + [Zabbix 2.4](#zabbix-24)
    + [Zabbix 2.2](#zabbix-22)
- [Role Variables](#role-variables)
- [Dependencies](#dependencies)
- [Example Playbook](#example-playbook)
- [License](#license)
- [Author Information](#author-information)


[![Build Status](https://travis-ci.org/dj-wasabi/ansible-zabbix-proxy.svg?branch=master)](https://travis-ci.org/dj-wasabi/ansible-zabbix-proxy)

# Overview

This role is migrated to: https://github.com/ansible-collections/community.zabbix/
In this repository, a read only version is/will be available for those who can not make use of collections (yet). Changes/updates will only be applied to the collection and not in this repository.

# Upgrades

## 1.0.0

With this 1.0.0 release, the following is changed:

* All properties starts with `zabbix_` now. Example, property named `proxy_dbhost` is now `zabbix_proxy_dbhost`.

## Operating systems

This role will work on the following operating systems:

 * Red Hat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please sent Pull Requests or suggestions when you want to use this role for other Operating systems.

## Zabbix Versions

See the following list of supported Operating systems with the Zabbix releases.

### Zabbix 4.4

  * CentOS 7.x, 8.x
  * Amazon 7.x
  * RedHat 7.x, 8.x
  * OracleLinux 7.x, 8.x
  * Scientific Linux 7.x, 8.x
  * Ubuntu 14.04, 16.04, 18.04
  * Debian 8, 9

### Zabbix 4.2

  * CentOS 7.x
  * Amazon 7.x
  * RedHat 7.x
  * OracleLinux 7.x
  * Scientific Linux 7.x
  * Ubuntu 14.04, 16.04, 18.04
  * Debian 8, 9

### Zabbix 4.0

  * CentOS 7.x
  * Amazon 7.x
  * RedHat 7.x
  * OracleLinux 7.x
  * Scientific Linux 7.x
  * Ubuntu 14.04, 16.04, 18.04
  * Debian 8, 9

### Zabbix 3.4

  * CentOS 7.x
  * Amazon 7.x
  * RedHat 7.x
  * OracleLinux 7.x
  * Scientific Linux 7.x
  * Ubuntu 14.04, 16.04
  * Debian 7, 8, 9

### Zabbix 3.2

  * CentOS 7.x
  * Amazon 7.x
  * RedHat 7.x
  * OracleLinux 7.x
  * Scientific Linux 7.x
  * Ubuntu 14.04, 16.04
  * Debian 7, 8

### Zabbix 3.0

  * CentOS 5.x, 6.x, 7.x
  * Amazon 5.x, 6.x, 7.x
  * RedHat 5.x, 6.x, 7.x
  * OracleLinux 5.x, 6.x, 7.x
  * Scientific Linux 5.x, 6.x, 7.x
  * Ubuntu 14.04
  * Debian 7, 8

### Zabbix 2.4

  * CentOS 6.x, 7.x
  * Amazon 6.x, 7.x
  * RedHat 6.x, 7.x
  * OracleLinux 6.x, 7.x
  * Scientific Linux 6.x, 7.x
  * Ubuntu 12.04 14.04
  * Debian 7

### Zabbix 2.2

  * CentOS 5.x, 6.x
  * RedHat 5.x, 6.x
  * OracleLinux 5.x, 6.x
  * Scientific Linux 5.x, 6.x
  * Ubuntu 12.04
  * Debian 7

# Role Variables

## Main variables

There are some variables in de default/main.yml which can (Or needs to) be changed/overriden:

* `zabbix_server_host`: The ip or dns name for the zabbix-server machine.

* `zabbix_server_port`: The port on which the zabbix-server is running. Default: 10051

* `zabbix_version`: This is the version of zabbix. Default it is 4.2, but can be overriden to 4.0/3.4/3.2/3.0/2.4/2.2.

* `zabbix_proxy_{rhel,debian,ubuntu}_version`: This is the version of zabbix proxy. For example 4.4.4/4.2.5/4.2.8

* `zabbix_repo`: True / False. When you already have an repository with the zabbix components, you can set it to False.

* `*zabbix_proxy_package_state`: Default: _present_. Can be overridden to "latest" to update packages when needed.

* `zabbix_proxy_install_database_client`: True / False. False does not install database client. Default: True.

* `zabbix_agent_become_on_localhost`: Set to `False` if you don't need to elevate privileges on localhost to install packages locally with pip. Default: True

* `zabbix_proxy_manage_service`: True / False. When you run multiple Zabbix proxies in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-proxy service, because Pacemaker is in control of zabbix-proxy service.

* `zabbix_install_pip_packages`: Set to `False` if you don't want to install the required pip packages. Useful when you control your environment completely. Default: True

There are some zabbix-proxy specific variables which will be used for the zabbix-proxy configuration file, these can be found in the default/main.yml file. There are 2 which needs some explanation:

```bash
  #zabbix_proxy_database: mysql
  #zabbix_proxy_database_long: mysql
  #zabbix_proxy_database: sqlite3
  #zabbix_proxy_database_long: sqlite3
  zabbix_proxy_database: pgsql
  zabbix_proxy_database_long: postgresql
```

There are 3 database_types which will be supported: mysql/postgresql and sqlite. You'll need to comment or uncomment the database you would like to use. In example from above, the postgresql database is used. If you want to use mysql, uncomment the 2 lines from mysql and comment the 2 lines for postgresql.

If you use mysql, then you should define mysql username, password and host to prepare zabbix database, otherwise they will be considered as their default value (and therefor, connecting to database will be considered as connecting to localhost with no password). the keys are belows:
   zabbix_proxy_mysql_login_host
   zabbix_proxy_mysql_login_user
   zabbix_proxy_mysql_login_password

## TLS Specific configuration

These variables are specific for Zabbix 3.0 and higher:

* `*zabbix_proxy_tlsconnect`: How the proxy should connect to server or proxy. Used for active checks.

     Possible values:
     
     * no_encryption
     * PSK
     * certificate
     
* `*zabbix_proxy_tlsaccept`: What incoming connections to accept.

     Possible values:
     
     * no_encryption
     * PSK
     * certificate

* `*zabbix_proxy_tlscafile`: Full pathname of a file containing the top-level CA(s) certificates for peer certificate verification.

* `*zabbix_proxy_tlscrlfile`: Full pathname of a file containing revoked certificates.

* `*zabbix_proxy_tlsservercertissuer`: Allowed server certificate issuer.

* `*zabbix_proxy_tlsservercertsubject`: Allowed server certificate subject.

* `*zabbix_proxy_tlscertfile`: Full pathname of a file containing the agent certificate or certificate chain.

* `*zabbix_proxy_tlskeyfile`: Full pathname of a file containing the agent private key.

* `*zabbix_proxy_tlspskidentity`: Unique, case sensitive string used to identify the pre-shared key.

## Zabbix API variables

These variables need to be overridden when you want to make use of the zabbix-api for automatically creating and or updating hosts.

Host encryption configuration will be set to match agent configuration.

When `zabbix_api_create_proxy` is set to `True`, it will install on the host executing the Ansible playbook the `zabbix-api` python module.

* `zabbix_url`: The url on which the Zabbix webpage is available. Example: http://zabbix.example.com

* `zabbix_api_http_user`: The http user to access zabbix url with Basic Auth
* `zabbix_api_http_password`: The http password to access zabbix url with Basic Auth

* `zabbix_api_create_proxy`: When you want to enable the Zabbix API to create/delete the proxy. This has to be set to `True` if you want to make use of `zabbix_create_proxy`. Default: `False`

* `zabbix_api_user`: Username of user which has API access.

* `zabbix_api_pass`: Password for the user which has API access.

* `zabbix_create_proxy`: present (Default) if the proxy needs to be created or absent if you want to delete it. This only works when `zabbix_api_create_proxy` is set to `True`.

* `zabbix_proxy_status`: active (Default) if the proxy needs to be active or passive.

# Dependencies

```text
You'll need to find the correct database role by yourself. I only want to use roles which supports the 3 main operating systems as well and for now I can't find one. If there is an role which supports these 3 operating systems, please let me know and I'll use it as dependency.
```

# Example Playbook

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: zabbix-proxy
      sudo: yes
      roles:
         - { role: dj-wasabi.zabbix-proxy, zabbix_server_host: 192.168.1.1, database_type: pgsql, database_type_long: postgresql }

# License

GPLv3

# Author Information

This is my first attempt to create an ansible role, so please send suggestion or pull requests to make this role better. 

Github: https://github.com/dj-wasabi/ansible-zabbix-proxy

mail: ikben [ at ] werner-dijkerman . nl
