# community.zabbix.zabbix_web role

![Zabbix Web](https://github.com/ansible-collections/community.zabbix/workflows/community.zabbix.zabbix_web/badge.svg)

**Table of Contents**

- [Overview](#overview)
- [Requirements](#requirements)
  - [Operating Systems](#operating-systems)
  - [Zabbix Versions](#zabbix-versions)
- [Installation](#installation)
- [Role Variables](#role-variables)
  - [Main variables](#main-variables)
    - [Overall Zabbix](#overall-zabbix)
    - [Zabbix Web specific](#zabbix-web-specific)
      - [Apache configuration](#apache-configuration)
      - [Nginx configuration](#nginx-configuration)
      - [PHP-FPM](#php-fpm)
    - [Zabbix Server](#zabbix-server)
  * [proxy](#proxy)
- [Example Playbook](#example-playbook)
  - [Single instance](#single-instance)
  - [Multi host setup](#multi-host-setup)
  - [Adding Environment Variables for zabbix_web](#adding-environment-variables-for-zabbixweb)
  - [Using Elasticsearch for history storage](#using-elasticsearch-for-history-storage)
- [Molecule](#molecule)
- [License](#license)
- [Author Information](#author-information)

# Overview

# Requirements
## Operating Systems

This role will work on the following operating systems:

 * RedHat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

## Ansible 2.10 and higher

With the release of Ansible 2.10, modules have been moved into collections.  With the exception of ansible.builtin modules, this means additonal collections must be installed in order to use modules such as seboolean (now ansible.posix.seboolean).  The following collections are now required: `ansible.posix`.  The `community.general` collection is required when defining the `zabbix_web_htpasswd` variable (see variable section below).  Installing the collections:

```sh
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install community.general
```

## Zabbix Versions

See the following list of supported Operating Systems with the Zabbix releases.

| Zabbix              | 5.2 | 5.0 | 4.4 | 4.0 (LTS) | 3.0 (LTS) |
|---------------------|-----|-----|-----|-----------|-----------|
| Red Hat Fam 8       |  V  |  V  | V   |           |           |
| Red Hat Fam 7       |  V  |  V  | V   | V         | V         |
| Red Hat Fam 6       |  V  |  V  |     |           | V         |
| Red Hat Fam 5       |  V  |  V  |     |           | V         |
| Fedora              |     |     | V   | V         |           |
| Ubuntu 20.04 focal  |  V  |  V  | V   |           |           |
| Ubuntu 19.10 eoan   |     |     |     |           |           |
| Ubuntu 18.04 bionic |  V  |  V  | V   | V         |           |
| Ubuntu 16.04 xenial |  V  |  V  | V   | V         |           |
| Ubuntu 14.04 trusty |  V  |  V  | V   | V         | V         |
| Debian 10 buster    |  V  |  V  | V   |           |           |
| Debian 9 stretch    |  V  |  V  | V   | V         |           |
| Debian 8 jessie     |  V  |  V  | V   | V         | V         |
| Debian 7 wheezy     |     |     |     | V         | V         |
| macOS 10.15         |     |     | V   | V         |           |
| macOS 10.14         |     |     | V   | V         |           |

# Installation

Installing this role is very simple: `ansible-galaxy install community.zabbix.zabbix_web`

When the Zabbix Web needs to be running on the same host as the Zabbix Server, please also install the Zabbix Server by executing the following command: `ansible-galaxy install community.zabbix.zabbix_server`

Default username/password for the Zabbix Web interface is the default.

Username: Admin
Password: zabbix

# Role Variables

## Main variables

The following is an overview of all available configuration defaults for this role.

### Overall Zabbix

* `zabbix_web_version`: This is the version of zabbix. Default: 5.2. Can be overridden to 5.0, 4.4, 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2. Previously the variable `zabbix_version` was used directly but it could cause [some inconvenience](https://github.com/dj-wasabi/ansible-zabbix-agent/pull/303). That variable is maintained by retrocompativility.
* `zabbix_repo`: Default: `zabbix`
  * `epel`: install agent from EPEL repo
  * `zabbix`: (default) install agent from Zabbix repo
  * `other`: install agent from pre-existing or other repo
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)
* `zabbix_repo_yum_disabled`: A string with repository names that should be disabled when installing Zabbix component specific packages. Is only used when `zabbix_repo_yum_enabled` contains 1 or more repositories. Default `*`.
* `zabbix_repo_yum_enabled`: A list with repository names that should be enabled when installing Zabbix component specific packages.

* `zabbix_web_package_state`: Default: `present`. Can be overridden to `latest` to update packages when needed.
* `zabbix_web_centos_release`: Default: True. When the `centos-release-scl` repository needs to be enabled. This is required when using Zabbix 5.0 due to installation of a recent version of `PHP`.
* `zabbix_web_rhel_release`: Default: True. When the `scl-utils` repository needs to be enabled. This is required when using Zabbix 5.0 due to installation of a recent version of `PHP`.
* `zabbix_web_doubleprecision`: Default: `False`. For upgraded installations, please read database [upgrade notes](https://www.zabbix.com/documentation/current/manual/installation/upgrade_notes_500) (Paragraph "Enabling extended range of numeric (float) values") before enabling this option.
* `zabbix_web_conf_mode`: Default: `0644`. The "mode" for the Zabbix configuration file.

### Zabbix Web specific

* `zabbix_api_server_url`: This is the url on which the zabbix web interface is available. Default is zabbix.example.com, you should override it. For example, see "Example Playbook"
* `zabbix_url_aliases`: A list with Aliases for the Apache Virtual Host configuration.
* `zabbix_timezone`: Default: `Europe/Amsterdam`. This is the timezone. The Apache Virtual Host needs this parameter.
* `zabbix_vhost`: Default: `true`. When you don't want to create an Apache Virtual Host configuration, you can set it to False.
* `zabbix_web_env`: (Optional) A Dictionary of PHP Environments settings.
* `zabbix_web_conf_web_user`: When provided, the user (which should already exist on the host) will be used for ownership for web/php related processes. (Default set to either `apache` (`www-data` for Debian) or `nginx`).
* `zabbix_web_conf_web_group`: When provided, the group (which should already exist on the host) will be used for ownership for web/php related processes. (Default set to either `apache` (`www-data` for Debian) or `nginx`).
* `zabbix_web_htpasswd`: (Optional) Allow HTTP authentication at the webserver level via a htpasswd file.
* `zabbix_web_htpasswd_file`: Default: `/etc/zabbix/web/htpasswd`. Allows the change the default path to the htpasswd file.
* `zabbix_web_htpasswd_users`: (Optional) Dictionary for creating users via `htpasswd_user` and passphrases via `htpasswd_pass` in htpasswd file.
* `zabbix_web_allowlist_ips`: (Optional) Allow web access at webserver level to a list of defined IPs or CIDR.
* `zabbix_saml_idp_crt`: (Optional) The path to the certificate of the Identity Provider used for SAML authentication
* `zabbix_saml_sp_crt`: (Optional) The path to the public certificate of Zabbix as Service Provider
* `zabbix_saml_sp_key`: (Optional) The path to the private certificate of Zabbix as Service Provider

#### Apache configuration

* `zabbix_apache_vhost_port`: The port on which Zabbix HTTP vhost is running.
* `zabbix_apache_vhost_tls_port`: The port on which Zabbix HTTPS vhost is running.
* `zabbix_apache_vhost_listen_ip`: On which interface the Apache Virtual Host is available.
* `zabbix_apache_can_connect_ldap`: Default: `false`. Set SELinux boolean to allow httpd to connect to LDAP.
* `zabbix_php_install`: Default: `true`. True / False. Switch for extra install of packages for PHP, currently on for Debian/Ubuntu.
* `zabbix_web_max_execution_time`:
* `zabbix_web_memory_limit`:
* `zabbix_web_post_max_size`:
* `zabbix_web_upload_max_filesize`:
* `zabbix_web_max_input_time`:
* `zabbix_apache_include_custom_fragment`: Default: `true`. Includes php_value vars max_execution_time, memory_limit, post_max_size, upload_max_filesize, max_input_time and date.timezone in vhost file.. place those in php-fpm configuration.
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

#### Nginx configuration

* `zabbix_nginx_vhost_port`: The port on which Zabbix HTTP vhost is running.
* `zabbix_nginx_vhost_tls_port`: The port on which Zabbix HTTPS vhost is running.
* `zabbix_nginx_tls`: If the Nginx vhost should be configured with TLS encryption or not.
* `zabbix_nginx_tls_crt`: The path to the TLS certificate file.
* `zabbix_nginx_tls_key`: The path to the TLS key file.
* `zabbix_nginx_tls_dhparam`: The path to the TLS DHParam file.
* `zabbix_nginx_tls_session_cache`: Type of the global/inter-process SSL Session Cache
* `zabbix_nginx_tls_session_timeout`:
* `zabbix_nginx_tls_session_tickets`:
* `zabbix_nginx_tls_protocols`: The TLS Protocols to accept.
* `zabbix_nginx_tls_ciphers`: The TLS Ciphers to be allowed.

When `zabbix_nginx_tls_crt` and `zabbix_nginx_tls_key` are used, make sure that these files exists before executing this role. The Zabbix-Web role will not install the mentioned files.

#### PHP-FPM

The following properties are specific to Zabbix 5.0 and for the PHP(-FPM) configuration:

* `zabbix_php_version`: Either `7.3` or `7.4` (Based on the OS Family). When you want to override the PHP Version.
* `zabbix_php_fpm_session`: The directory where sessions will be stored. If none are provided, defaults are used.
* `zabbix_php_fpm_listen`: The path to a socket file or ipaddress:port combination on which PHP-FPM needs to listen. If none are provided, defaults are used.
* `zabbix_php_fpm_conf_listen`: Default: `true`. If we want to configure the `zabbix_php_fpm_listen` in the PHP-FPM configuration file.
* `zabbix_php_fpm_conf_user`: The owner of the socket file (When `zabbix_php_fpm_listen` contains a patch to a socket file).
* `zabbix_php_fpm_conf_enable_user`: Default: `true`. If we want to configure the owner of the `zabbix_php_fpm_listen` in the PHP-FPM configuration file.
* `zabbix_php_fpm_conf_group`: The group of the owner of the socket file (When `zabbix_php_fpm_listen` contains a patch to a socket file).
* `zabbix_php_fpm_conf_enable_group`: Default: `true`. If we want to configure the group of the `zabbix_php_fpm_listen` in the PHP-FPM configuration file.
* `zabbix_php_fpm_conf_mode`: The mode for the socket file (When `zabbix_php_fpm_listen` contains a patch to a socket file).
* `zabbix_php_fpm_conf_enable_mode`: Default: `true`. If we want to configure the mode of the `zabbix_php_fpm_listen` in the PHP-FPM configuration file.
* `zabbix_php_fpm_dir_etc`: etc HOME root directory of PHP-FPM setup.
* `zabbix_php_fpm_dir_var`: Var HOME root directory of PHP-FPM setup.

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

## proxy

When the target host does not have access to the internet, but you do have a proxy available then the following properties needs to be set to download the packages via the proxy:

* `zabbix_http_proxy`
* `zabbix_https_proxy`

# Example Playbook

There are two ways of using the zabbix-web:

* Single instance
* Multi host setup

## Single instance

When there is one host running both Zabbix Server and the Zabbix Web (Running MySQL as database):

```yaml
- hosts: zabbix-server
  become: yes
  roles:
    - role: geerlingguy.apache
    - role: community.zabbix.zabbix_server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
    - role: community.zabbix.zabbix_web
      zabbix_api_server_url: zabbix.mydomain.com
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
```

## Multi host setup

This is a two host setup. On one host (Named: "zabbix-server") the Zabbix Server is running, and the other host (Named: zabbix-web) runs Zabbix Web (with MySQL as database):

```yaml
- hosts: zabbix-server
  become: yes
  roles:
    - role: community.zabbix.zabbix_server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306

- hosts: zabbix-web
  become: yes
  roles:
    - role: geerlingguy.apache
    - role: community.zabbix.zabbix_web
      zabbix_api_server_url: zabbix.mydomain.com
      zabbix_server_hostname: zabbix-server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
```

## Adding Environment Variables for zabbix_web

Sometimes you need to add environment variables to your
zabbix.conf.php, for example to add LDAP CA certificates. To do this add a `zabbix_web_env` dictionary:

```yaml
- hosts: zabbix-web
  become: yes
  roles:
    - role: geerlingguy.apache
    - role: geerlingguy.php
      php_memory_limit: "128M"
      php_max_execution_time: "300"
      php_upload_max_filesize: "256M"
      php_packages:
        - php
        - php-fpm
        - php-acpu
    - role: geerlingguy.apache-php-fpm
    - role: community.zabbix.zabbix_web
      zabbix_api_server_url: zabbix.mydomain.com
      zabbix_server_hostname: zabbix-server
      zabbix_server_database: mysql
      zabbix_server_database_long: mysql
      zabbix_server_dbport: 3306
      zabbix_web_env:
        LDAPTLS_CACERT: /etc/ssl/certs/ourcert.pem
```

## Using Elasticsearch for history storage

To use Elasticsearch for history storage you need to configure the `zabbix_server_history_url` and `zabbix_server_history_types`. You will also need to configure Elasticsearch
in the zabbix_server role.

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

This role is configured to be tested with Molecule. You can find on this page some more information regarding Molecule:

* http://werner-dijkerman.nl/2016/07/10/testing-ansible-roles-with-molecule-testinfra-and-docker/
* http://werner-dijkerman.nl/2016/07/27/extending-ansible-role-testing-with-molecule-by-adding-group_vars-dependencies-and-using-travis-ci/
* http://werner-dijkerman.nl/2016/07/31/testing-ansible-roles-in-a-cluster-setup-with-docker-and-molecule/

With each Pull Request, Molecule will be executed via travis.ci. Pull Requests will only be merged once these tests run successfully.

# License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

# Author Information

Please send suggestion or pull requests to make this role better. Also let us know if you encounter any issues installing or using this role.

Github: https://github.com/ansible-collections/community.zabbix
