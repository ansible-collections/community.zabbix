Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
  * [Operating Systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
    + [Zabbix 4.4](#zabbix-44)
    + [Zabbix 4.2](#zabbix-42)
    + [Zabbix 4.0](#zabbix-40)
    + [Zabbix 3.4](#zabbix-34)
    + [Zabbix 3.2](#zabbix-32)
    + [Zabbix 3.0](#zabbix-30)
    + [Zabbix 2.4](#zabbix-24)
    + [Zabbix 2.2](#zabbix-22)
- [Installation](#installation)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
    + [Overall Zabbix](#overall-zabbix)
    + [Zabbix Web specific](#zabbix-web-specific)
    + [Zabbix Server](#zabbix-server)
  * [Examples of configuration](#examples-of-configuration)
    + [zabbix_repo_yum](#zabbix-repo-yum)
- [Dependencies](#dependencies)
- [Example Playbook](#example-playbook)
  * [Single instance](#single-instance)
  * [Multi host setup](#multi-host-setup)
  * [Adding Environment Variables for zabbix_web](#adding-environment-variables-for-zabbix-web)
- [Molecule](#molecule)
- [License](#license)
- [Author Information](#author-information)

# Overview

This role is migrated to: https://github.com/ansible-collections/community.zabbix/
In this repository, a read only version is/will be available for those who can not make use of collections (yet). Changes/updates will only be applied to the collection and not in this repository.

# Requirements
## Operating Systems

This role will work on the following operating systems:

 * RedHat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please sent Pull Requests or suggestions when you want to use this role for other Operating Systems.

## Zabbix Versions

See the following list of supported Operating Systems with the Zabbix releases.

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
  * xenserver 6

# Installation

Installing this role is very simple: `ansible-galaxy install dj-wasabi.zabbix-web`

When the Zabbix Web needs to be running on the same host as the Zabbix Server, please also install the Zabbix Server by executing the following command: `ansible-galaxy install dj-wasabi.zabbix-server`

 Default username/password for the Zabbix Web interface is the default.

 Username: Admin
 Password: zabbix

# Role Variables

## Main variables

The following is an overview of all available configuration defaults for this role.

### Overall Zabbix

* `zabbix_web_version`: This is the version of zabbix. Default: 4.4, Can be overridden to 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2. Previously the variable `zabbix_version` was used directly but it could cause [some inconvenience](https://github.com/dj-wasabi/ansible-zabbix-agent/pull/303). That variable is maintained by retrocompativility.
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_web_package_state`: Default: _present_. Can be overridden to "latest" to update packages when needed.

### Zabbix Web specific

* `zabbix_url`: This is the url on which the zabbix web interface is available. Default is zabbix.example.com, you should override it. For example, see "Example Playbook"
* `zabbix_url_aliases`: A list with Aliases for the Apache Virtual Host configuration.
* `zabbix_timezone`: This is the timezone. The Apache Virtual Host needs this parameter. Default: Europe/Amsterdam
* `zabbix_vhost`: True / False. When you don't want to create an Apache Virtual Host configuration, you can set it to False.
* `zabbix_apache_vhost_port`: The port on which Zabbix HTTP vhost is running.
* `zabbix_apache_vhost_tls_port`: The port on which Zabbix HTTPS vhost is running.
* `zabbix_apache_vhost_port`: On which port the Apache Virtual Host is available.
* `zabbix_apache_vhost_listen_ip`: On which interface the Apache Virtual Host is available.
* `zabbix_apache_can_connect_ldap`: True / False. Set SELinux boolean to allow httpd to connect to LDAP. Default is False.
* `zabbix_php_install`: True / False. Switch for extra install of packages for PHP, currently on for Debian/Ubuntu. Default is true.
* `zabbix_web_max_execution_time`:
* `zabbix_web_memory_limit`:
* `zabbix_web_post_max_size`:
* `zabbix_web_upload_max_filesize`:
* `zabbix_web_max_input_time`:
* `zabbix_apache_include_custom_fragment`: True / False. Includes php_value vars max_execution_time, memory_limit, post_max_size, upload_max_filesize, max_input_time and date.timezone in vhost file.. place those in php-fpm configuration. Default is true.
* `zabbix_web_env`: (Optional) A Dictionary of PHP Environments

The following properties are related when TLS/SSL is configured:

* `zabbix_apache_tls`: If the Apache vhost should be configured with TLS encryption or not.
* `zabbix_apache_redirect`: If a redirect should take place from HTTP to HTTPS
* `zabbix_apache_tls_crt`: The path to the TLS certificate file.
* `zabbix_apache_tls_key`: The path to the TLS key file.
* `zabbix_apache_tls_chain`: The path to the TLS certificate chain file.
* `zabbix_apache_SSLPassPhraseDialog`: Type of pass phrase dialog for encrypted private keys.
* `zabbix_apache_SSLSessionCache`: Type of the global/inter-process SSL Session Cache
* `zabbix_apache_SSLSessionCacheTimeout`: Number of seconds before an SSL session expires in the Session Cache
* `zabbix_apache_SSLCryptoDevice`: Enable use of a cryptographic hardware accelerator

When `zabbix_apache_tls_crt`, `zabbix_apache_tls_key` and/or `zabbix_apache_tls_chain` are used, make sure that these files exists before executing this role. The Zabbix-Web role will not install the mentioned files.

See https://httpd.apache.org/docs/current/mod/mod_ssl.html for SSL* configuration options for Apache HTTPD.

### Zabbix Server

* `zabbix_server_name`: The name of the Zabbix Server.
* `zabbix_server_database`: The type of database used. Can be: mysql or pgsql
* `zabbix_server_database_long`: The type of database used, but long name. Can be: mysql or postgresql
* `zabbix_server_hostname`: The hostname on which the zabbix-server is running. Default set to: {{ inventory_hostname }}
* `zabbix_server_listenport`: On which port the Zabbix Server is available. Default: 10051
* `zabbix_server_dbhost`: The hostname on which the database is running.
* `zabbix_server_dbname`: The database name which is used by the Zabbix Server.
* `zabbix_server_dbuser`: The database username which is used by the Zabbix Server.
* `zabbix_server_dbpassword`: The database user password which is used by the Zabbix Server.
* `zabbix_server_dbport`: The database port which is used by the Zabbix Server.

The following properties are related when using Elasticsearch for history storage:

* `zabbix_server_history_url`: String with url to the Elasticsearch server or a list  if the types are stored on different Elasticsearch URLs.
* `zabbix_server_history_types`: List of history types to store in Elasticsearch.

See the following links for more information regarding Zabbix and Elasticsearch
https://www.zabbix.com/documentation/3.4/manual/appendix/install/elastic_search_setup
https://www.zabbix.com/documentation/4.0/manual/appendix/install/elastic_search_setup

## Examples of configuration

### zabbix_repo_yum

Current default configuration and example for specifying a yum repository:

````
zabbix_repo_yum:
  - name: zabbix
    description: Zabbix Official Repository - $basearch
    baseurl: http://repo.zabbix.com/zabbix/{{ zabbix_version }}/rhel/{{ ansible_distribution_major_version }}/$basearch/
    gpgcheck: 0
    gpgkey: file:///etc/pki/rpm-gpg/RPM-GPG-KEY-ZABBIX
    state: present
  - name: zabbix
    description: Zabbix Official Repository non-supported - $basearch
    baseurl: http://repo.zabbix.com/non-supported/rhel/{{ ansible_distribution_major_version }}/$basearch/
    gpgcheck: 0
    gpgkey: file:///etc/pki/rpm-gpg/RPM-GPG-KEY-ZABBIX
    state: present
````

# Dependencies

This role has one dependency for Apache usage: geerlingguy.apache. Via the variable zabbix_websrv != 'apache' this can be skipped.

As it is also possible to run the zabbix-web on a different host than the zabbix-server, the zabbix-server is not configured to be an dependency.

# Example Playbook

There are two ways of using the zabbix-web:

* Single instance
* Multi host setup

## Single instance

When there is one host running both Zabbix Server and the Zabbix Web (Running MySQL as database):

```
- hosts: zabbix-server
  become: yes
  roles:
     - { role: geerlingguy.apache }
     - { role: dj-wasabi.zabbix-server, zabbix_server_database: mysql, zabbix_server_database_long: mysql, zabbix_server_dbport: 3306 }
     - { role: dj-wasabi.zabbix-web, zabbix_url: zabbix.dj-wasabi.nl, zabbix_server_database: mysql, zabbix_server_database_long: mysql, zabbix_server_dbport: 3306}
```

## Multi host setup

This is a two host setup. On one host (Named: "zabbix-server") the Zabbix Server is running, and the other host (Named: zabbix-web) runs Zabbix Web (with MySQL as database):

```
- hosts: zabbix-server
  become: yes
  roles:
     - { role: dj-wasabi.zabbix-server, zabbix_server_database: mysql, zabbix_server_database_long: mysql, zabbix_server_dbport: 3306 }

- hosts: zabbix-web
  become: yes
  roles:
     - { role: geerlingguy.apache }
     - { role: dj-wasabi.zabbix-web, zabbix_server_hostname: zabbix-server, zabbix_url: zabbix.dj-wasabi.nl, zabbix_server_database: mysql, zabbix_server_database_long: mysql, zabbix_server_dbport: 3306 }
```

## Adding Environment Variables for zabbix_web

Sometimes you need to add environment variables to your
zabbix.conf.php, for example to add LDAP CA certificates. To do this add a `zabbix_web_env` dictionary:

```
- { role: dj-wasabi.zabbix-web, zabbix_url: zabbix.dj-wasabi.nl, zabbix_server_database: mysql, zabbix_server_database_long: mysql, zabbix_server_dbport: 3306, zabbix_web_env: {LDAPTLS_CACERT: /etc/ssl/certs/ourcert.pem}
```

## Using Elasticsearch for history storage

To use Elasticsearch for history storage you need to configure the `zabbix_server_history_url` and `zabbix_server_history_types`. You will also need to configure Elasticsearch
in the zabbix-server (https://galaxy.ansible.com/dj-wasabi/zabbix-server/) role.

Zabbix can store the following history types
in Elasticsearch:
* Numeric (unsigned) - `uint`
* Numeric (float) - `dbl`
* Character - `str`
* Log - `log`
* Text - `text`

To store all history types in the same history URL the following variables should be set (make sure history url points to your Elasticsearch cluster):

```
zabbix_server_history_url: "http://localhost:9200"
zabbix_server_history_types:
  - 'str'
  - 'text'
  - 'log'
  - 'uint'
  - 'dbl'
```

# Molecule

This role is configured to be tested with Molecule. Molecule will boot at least 3 different kinds of containers, one for each supported Operating System (Debian, Ubuntu and RedHat).
Pull Requests are only merged when the tests are successful.

For more information, please check the following page: https://www.werner-dijkerman.nl/2016/07/10/testing-ansible-roles-with-molecule-testinfra-and-docker

# License

MIT

# Author Information

Github: https://github.com/dj-wasabi/ansible-zabbix-web

mail: ikben [ at ] werner-dijkerman . nl
