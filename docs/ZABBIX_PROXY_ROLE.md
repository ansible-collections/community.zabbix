# community.zabbix.zabbix_proxy role

Table of Content

- [Overview](#overview)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
    + [Overall Zabbix](#overall-zabbix)
    + [SElinux](#selinux)
    + [Zabbix Proxy](#zabbix-proxy)
    + [Database specific](#database-specific)
    + [TLS Specific configuration](#tls-specific-configuration)
  * [Database](#database)
    + [MySQL](#mysql)
      - [Local Setup](#local-setup)
      - [Separate Setup](#separate-setup)
    + [PostgreSQL](#postgresql)
      - [Local Setup](#local-setup-1)
      - [Separate Setup](#separate-setup-1)
  * [Zabbix API variables](#zabbix-api-variables)
- [Example Playbook](#example-playbook)
- [Molecule](#molecule)
- [License](#license)
- [Author Information](#author-information)

# Overview

## Operating systems

This role will work on the following operating systems:

 * Red Hat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please sent Pull Requests or suggestions when you want to use this role for other Operating systems.

## Zabbix Versions

See the following list of supported Operating systems with the Zabbix releases.

| Zabbix              | 5.0 | 4.4 | 4.0 (LTS) | 3.0 (LTS) |
|---------------------|-----|-----|-----------|-----------|
| Red Hat Fam 8       |  V  | V   |           |           |
| Red Hat Fam 7       |  V  | V   | V         | V         |
| Red Hat Fam 6       |     |     |           | V         |
| Red Hat Fam 5       |     |     |           | V         |
| Fedora              |     | V   | V         |           |
| Ubuntu 20.04 focal  |  V  |     |           |           |
| Ubuntu 19.10 eoan   |  ?  |     |           |           |
| Ubuntu 18.04 bionic |  V  | V   | V         |           |
| Ubuntu 16.04 xenial |  V  | V   | V         |           |
| Ubuntu 14.04 trusty |  V  | V   | V         | V         |
| Debian 10 buster    |  V  | V   |           |           |
| Debian 9 stretch    |  V  | V   | V         |           |
| Debian 8 jessie     |  V  | V   | V         | V         |
| Debian 7 wheezy     |     |     | V         | V         |
| macOS 10.15         |     | V   | V         |           |
| macOS 10.14         |     | V   | V         |           |

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_proxy_version`: This is the version of zabbix. Default: 5.0. Can be overridden to 4.4, 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2. Previously the variable `zabbix_version` was used directly but it could cause [some inconvenience](https://github.com/dj-wasabi/ansible-zabbix-agent/pull/303). That variable is maintained by retrocompativility.
* `zabbix_repo`: Default: `zabbix`
  * `epel`: install agent from EPEL repo
  * `zabbix`: (default) install agent from Zabbix repo
  * `other`: install agent from pre-existing or other repo
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)

### SElinux

* `zabbix_selinux`: Default: `False`. Enables an SELinux policy so that the server will run.

### Zabbix Proxy

* `zabbix_server_host`: The ip or dns name for the zabbix-server machine.
* `zabbix_server_port`: The port on which the zabbix-server is running. Default: 10051
* `*zabbix_proxy_package_state`: Default: `present`. Can be overridden to `latest` to update packages
* `zabbix_proxy_install_database_client`: Default: `True`. False does not install database client.
* `zabbix_proxy_become_on_localhost`: Default: `True`. Set to `False` if you don't need to elevate privileges on localhost to install packages locally with pip.
* `zabbix_proxy_manage_service`: Default: `True`. When you run multiple Zabbix proxies in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-proxy service, because Pacemaker is in control of zabbix-proxy service.
* `zabbix_install_pip_packages`: Default: `True`. Set to `False` if you don't want to install the required pip packages. Useful when you control your environment completely.
* `zabbix_proxy_startpreprocessors`: Number of pre-forked instances of preprocessing workers. The preprocessing manager process is automatically started when a preprocessor worker is started.This parameter is supported since Zabbix 4.2.0.
* `zabbix_proxy_username`: Default: `zabbix`. The name of the account on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_proxy_userid`: The UID of the account on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_proxy_groupname`: Default: `zabbix`. The name of the group of the user on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_proxy_groupid`: The GID of the group on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_proxy_include_mode`: Default: `0755`. The "mode" for the directory configured with `zabbix_proxy_include`.

### Database specific

* `zabbix_proxy_dbhost_run_install`: Default: `True`. When set to `True`, sql files will be executed on the host running the database.
* `zabbix_proxy_database`: Default: `pgsql`. The type of database used. Can be: `mysql` or `pgsql`
* `zabbix_proxy_database_long`: Default: `postgresql`. The type of database used, but long name. Can be: `mysql` or `postgresql`
* `zabbix_proxy_dbhost`: The hostname on which the database is running.
* `zabbix_proxy_real_dbhost`: The hostname of the dbhost that is running behind a loadbalancer/VIP (loadbalancers doesn't accept ssh connections)
* `zabbix_proxy_dbname`: The database name which is used by the Zabbix Server.
* `zabbix_proxy_dbuser`: The database username which is used by the Zabbix Server.
* `zabbix_proxy_dbpassword`: The database user password which is used by the Zabbix Server.
* `zabbix_proxy_dbport`: The database port which is used by the Zabbix Server.
* `zabbix_database_creation`: Default: `True`. When you don't want to create the database including user, you can set it to False.
* `zabbix_proxy_install_database_client`: Default: `True`. False does not install database client. Default true
* `zabbix_database_sqlload`:True / False. When you don't want to load the sql files into the database, you can set it to False.
* `zabbix_proxy_dbencoding`: Default: `utf8`. The encoding for the MySQL database.
* `zabbix_proxy_dbcollation`: Default: `utf8_bin`. The collation for the MySQL database.zabbix_proxy_

### TLS Specific configuration

These variables are specific for Zabbix 3.0 and higher:

* `zabbix_proxy_tlsconnect`: How the agent should connect to server or proxy. Used for active checks.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_proxy_tlsaccept`: What incoming connections to accept.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_proxy_tlscafile`: Full pathname of a file containing the top-level CA(s) certificates for peer certificate verification.
* `zabbix_proxy_tlscrlfile`: Full pathname of a file containing revoked certificates.
* `zabbix_proxy_tlsservercertissuer`: Allowed server certificate issuer.
* `zabbix_proxy_tlsservercertsubject`: Allowed server certificate subject.
* `zabbix_proxy_tlscertfile`: Full pathname of a file containing the agent certificate or certificate chain.
* `zabbix_proxy_tlskeyfile`: Full pathname of a file containing the agent private key.
* `zabbix_proxy_dbtlsconnect`: Setting this option enforces to use TLS connection to database:

`required` - connect using TLS
`verify_ca` - connect using TLS and verify certificate
`verify_full` - connect using TLS, verify certificate and verify that database identity specified by DBHost matches its certificate

On `MySQL` starting from 5.7.11 and `PostgreSQL` the following values are supported: `required`, `verify`, `verify_full`. On MariaDB starting from version 10.2.6 `required` and `verify_full` values are supported.
By default not set to any option and the behaviour depends on database configuration.
This parameter is supported since Zabbix 5.0.0.

* `zabbix_proxy_dbtlscafile`: Full pathname of a file containing the top-level CA(s) certificates for database certificate verification. This parameter is supported since Zabbix 5.0.0.
* `zabbix_proxy_dbtlscertfile`: Full pathname of file containing Zabbix server certificate for authenticating to database. This parameter is supported since Zabbix 5.0.0.
* `zabbix_proxy_dbtlskeyfile`: Full pathname of file containing the private key for authenticating to database. This parameter is supported since Zabbix 5.0.0.
* `zabbix_proxy_dbtlscipher`: The list of encryption ciphers that Zabbix server permits for TLS protocols up through TLSv1.2. Supported only for MySQL.This parameter is supported since Zabbix 5.0.0.
* `zabbix_proxy_dbtlscipher13`: The list of encryption ciphersuites that Zabbix server permits for TLSv1.3 protocol. Supported only for MySQL, starting from version 8.0.16. This parameter is supported since Zabbix 5.0.0.

## Database

With Zabbix Server you can make use of 2 different databases:

* `mysql`
* `postgresql`

In the following paragraphs we dive into both setups.

### MySQL

To make the Zabbix Server work with a `MySQL` database, there are 2 types on setup:

1. Local setup, `MySQL` running on same host as the Zabbix Server;
2. Separate setup, `MySQL` running on a different host than the Zabbix Server.

#### Local Setup

We need to have the following dependencies met:

1. Find an (Ansible) role that will install a `MySQL` instance on the host. Example: `geerlingguy.mysql` can be used, but also others can be used. Please make sure that before installing the Zabbix Server, you have a fully functional `MySQL` instance running.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: mysql
zabbix_proxy_database_long: mysql
zabbix_proxy_dbport: 3306
zabbix_proxy_dbpassword: <SOME_SECRET_STRING>
```

Please generate a value for the `zabbix_proxy_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-proxy role will create an database and username (With the provided value for the password) in `MySQL`.
3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `MySQL` will be running.

#### Separate Setup

We need to have the following dependencies met:

1. We need to either have a `MySQL` instance running somewhere in the environment. If this is the case, we need to have a username/password combination that is allowed to create a database and an user account. If there isn't one, please make sure there is one.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: mysql
zabbix_proxy_database_long: mysql
zabbix_proxy_dbport: 3306
zabbix_proxy_dbhost: mysql-host
zabbix_proxy_dbhost_run_install: false
zabbix_proxy_dbpassword: <SOME_SECRET_STRING>
zabbix_proxy_privileged_host: '%'
zabbix_proxy_mysql_login_host: mysql-host
zabbix_proxy_mysql_login_user: root
zabbix_proxy_mysql_login_password: changeme
zabbix_proxy_mysql_login_port: 3306
```

Please generate a value for the `zabbix_proxy_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-proxy role will create an database and username (With the provided value for the password) in `MySQL`.

The `zabbix_proxy_privileged_host` can be set to the hostname/ip of the host running Zabbix Server for security related purposes. Also make sure that `zabbix_proxy_mysql_login_password` is set to the correct password for the user provided with `zabbix_proxy_mysql_login_host` to create a database and user in the `MySQL` instance.

3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `MySQL` on a different host will be running.

### PostgreSQL

To make the Zabbix Server work with a `PgSQL` database, there are 2 types on setup:

1. Local setup, `PgSQL` running on same host as the Zabbix Server;
2. Separate setup, `PgSQL` running on a different host than the Zabbix Server.

#### Local Setup

We need to have the following dependencies met:

1. Find an (Ansible) role that will install a `PgSQL` instance on the host. Example: `geerlingguy.postgresql` can be used, but also others can be used. Please make sure that before installing the Zabbix Server, you have a fully functional `PgSQL` instance running.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: pgsq;
zabbix_proxy_database_long: postgresql
zabbix_proxy_dbport: 5432
zabbix_proxy_dbpassword: <SOME_SECRET_STRING>
```

Please generate a value for the `zabbix_proxy_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-proxy role will create an database and username (With the provided value for the password) in `PgSQL`.
3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `PgSQL` will be running.

#### Separate Setup

We need to have the following dependencies met:

1. We need to either have a `PgSQL` instance running somewhere in the environment. If this is the case, we need to have a username/password combination that is allowed to create a database and an user account. If there isn't one, please make sure there is one.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: pgsq;
zabbix_proxy_database_long: postgresql
zabbix_proxy_dbport: 5432
zabbix_proxy_dbhost: pgsql-host
zabbix_proxy_dbhost_run_install: false
zabbix_proxy_dbpassword: <SOME_SECRET_STRING>
zabbix_proxy_privileged_host: '%'
zabbix_proxy_pgsql_login_host: pgsql-host
zabbix_proxy_pgsql_login_user: postgres
zabbix_proxy_pgsql_login_password: changeme
zabbix_proxy_pgsql_login_port: 5432
```

Please generate a value for the `zabbix_proxy_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-proxy role will create an database and username (With the provided value for the password) in `PgSQL`.

The `zabbix_proxy_privileged_host` can be set to the hostname/ip of the host running Zabbix Server for security related purposes. Also make sure that `zabbix_proxy_mysql_login_password` is set to the correct password for the user provided with `zabbix_proxy_mysql_login_host` to create a database and user in the `PgSQL` instance.

3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `PgSQL` on a different host will be running.zabbix_proxy_

## Zabbix API variables

These variables need to be overridden when you want to make use of the zabbix-api for automatically creating and or updating hosts. Host encryption configuration will be set to match agent configuration.

When `zabbix_api_create_proxy` is set to `True`, it will install on the host executing the Ansible playbook the `zabbix-api` python module.

* `zabbix_url`: The url on which the Zabbix webpage is available. Example: http://zabbix.example.com
* `zabbix_api_http_user`: The http user to access zabbix url with Basic Auth
* `zabbix_api_http_password`: The http password to access zabbix url with Basic Auth
* `zabbix_api_create_proxy`: When you want to enable the Zabbix API to create/delete the proxy. This has to be set to `True` if you want to make use of `zabbix_create_proxy`. Default: `False`
* `zabbix_api_user`: Username of user which has API access.
* `zabbix_api_pass`: Password for the user which has API access.
* `zabbix_create_proxy`: present (Default) if the proxy needs to be created or absent if you want to delete it. This only works when `zabbix_api_create_proxy` is set to `True`.
* `zabbix_proxy_status`: active (Default) if the proxy needs to be active or passive.

# Example Playbook

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
  - hosts: zabbix-proxy
    roles:
      - role: community.zabbix.zabbix_proxy
        zabbix_server_host: 192.168.1.1
        zabbix_server_database: mysql
        zabbix_server_database_long: mysql
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
