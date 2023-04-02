# community.zabbix.zabbix_server role

![Zabbix Server](https://github.com/ansible-collections/community.zabbix/workflows/community.zabbix.zabbix_server/badge.svg)

**Table of Contents**

- [Overview](#overview)
- [Requirements](#requirements)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Installation](#installation)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
    + [Overall Zabbix](#overall-zabbix)
    + [SElinux](#selinux)
    + [Zabbix Server](#zabbix-server)
    + [Database specific](#database-specific)
    + [TLS Specific configuration](#tls-specific-configuration)
    + [Custom Zabbix Scripts](#custom-zabbix-scripts)
  * [proxy](#proxy)
  * [Database](#database)
    + [MySQL](#mysql)
      - [Local Setup](#local-setup)
      - [Separate Setup](#separate-setup)
    + [PostgreSQL](#postgresql)
      - [Local Setup](#local-setup-1)
      - [Separate Setup](#separate-setup-1)
- [Example Playbook](#example-playbook)
- [Molecule](#molecule)
- [License](#license)
- [Author Information](#author-information)

# Overview

This is a Ansible role for installing and maintaining the zabbix-server. This will only install the Zabbix Server component and not the Zabbix Web.

# Requirements

## Operating systems

This role will work on the following operating systems:

 * Red Hat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

## Ansible 2.10 and higher

With the release of Ansible 2.10, modules have been moved into collections.  With the exception of ansible.builtin modules, this means additonal collections must be installed in order to use modules such as seboolean (now ansible.posix.seboolean).  The following collection is now required: `ansible.posix`.  Installing the collection:

```sh
ansible-galaxy collection install ansible.posix
```

### MySQL

When you are a MySQL user and using Ansible 2.10 or newer, then there is a dependency on the collection named `community.mysql`. This collections are needed as the `mysql_` modules are now part of collections and not standard in Ansible anymmore. Installing the collection:

```sh
ansible-galaxy collection install community.mysql
```

### PostgreSQL

When you are a PostgreSQL user and using Ansible 2.10 or newer, then there is a dependency on the collection named `community.postgresql`. This collections are needed as the `postgresql_` modules are now part of collections and not standard in Ansible anymmore. Installing the collection:

```sh
ansible-galaxy collection install community.postgresql
```

## Zabbix Versions

See the following list of supported Operating systems with the Zabbix releases:

| Zabbix              | 6.4 | 6.2 | 6.0 | 5.4 | 5.2 | 5.0 (LTS) | 4.4 | 4.0 (LTS) | 3.0 (LTS) |
|---------------------|-----|-----|-----|-----|-----|-----------|-----|-----------|-----------|
| Red Hat Fam 9       |  V  |  V  |  V  |     |     |           |     |           |           |
| Red Hat Fam 8       |  V  |  V  |  V  |  V  |  V  |  V        | V   |           |           |
| Red Hat Fam 7       |     |     |     |     |     |  V        | V   | V         | V         |
| Red Hat Fam 6       |     |     |     |     |  V  |  V        |     |           | V         |
| Red Hat Fam 5       |     |     |     |     |  V  |  V        |     |           | V         |
| Fedora              |     |     |     |     |     |           | V   | V         |           |
| Ubuntu 20.04 focal  |  V  |  V  |  V  |  V  |  V  |  V        |     | V         |           |
| Ubuntu 18.04 bionic |     |     |  V  |  V  |  V  |  V        | V   | V         |           |
| Ubuntu 16.04 xenial |     |     |     |     |  V  |  V        | V   | V         |           |
| Ubuntu 14.04 trusty |     |     |     |     |  V  |  V        | V   | V         | V         |
| Debian 10 buster    |     |     |  V  |  V  |  V  |  V        | V   |           |           |
| Debian 9 stretch    |     |     |  V  |  V  |  V  |  V        | V   | V         |           |
| Debian 8 jessie     |     |     |     |     |  V  |  V        | V   | V         | V         |
| Debian 7 wheezy     |     |     |     |     |     |           |     | V         | V         |
| macOS 10.15         |     |     |     |     |     |           | V   | V         |           |
| macOS 10.14         |     |     |     |     |     |           | V   | V         |           |

See https://support.zabbix.com/browse/ZBX-18790 why RHEL7 is not supported anymore.

# Installation

Installing this role is very simple: `ansible-galaxy install community.zabbix.zabbix_server`

Please be aware that this role only installs the Zabbix Server and not the Zabbix Web. If you do want to have a Zabbix Web, please execute the following command: `ansible-galaxy install community.zabbix.zabbix_web`

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_server_version`: This is the version of zabbix. Default: The highest supported version for the operating system. Can be overridden to 6.2, 6.0, 5.4, 5.2, 5.0, 4.4, 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2. Previously the variable `zabbix_version` was used directly but it could cause [some inconvenience](https://github.com/dj-wasabi/ansible-zabbix-agent/pull/303). That variable is maintained by retrocompativility.
* `zabbix_server_version_minor`: When you want to specify a minor version to be installed. RedHat only. Default set to: `*` (latest available)
* `zabbix_repo`: Default: `zabbix`
  * `epel`: install agent from EPEL repo
  * `zabbix`: (default) install agent from Zabbix repo
  * `other`: install agent from pre-existing or other repo
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)
* `zabbix_repo_yum_disabled`: A string with repository names that should be disabled when installing Zabbix component specific packages. Is only used when `zabbix_repo_yum_enabled` contains 1 or more repositories. Default `*`.
* `zabbix_repo_yum_enabled`: A list with repository names that should be enabled when installing Zabbix component specific packages.
* `zabbix_service_state`: Default: `started`. Can be overridden to stopped if needed
* `zabbix_service_enabled`: Default: `True` Can be overridden to `False` if needed

### SElinux

* `zabbix_selinux`: Default: `False`. Enables an SELinux policy so that the server will run.
* `selinux_allow_zabbix_can_network`: Default: `False`. 
* `selinux_allow_zabbix_can_http`: Default: `False`. 

### Zabbix Server

* `zabbix_server_package_state`: Default: `present`. Can be overridden to `latest` to update packages when needed.
* `zabbix_server_listenport`: Default: `10051`. On which port the Zabbix Server is available.
* `zabbix_server_install_recommends`: Default: `True`. `False` does not install the recommended packages that come with the zabbix-server install.
* `zabbix_server_manage_service`: Default: `True`. When you run multiple Zabbix servers in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-server service, because Pacemaker is in control of zabbix-server service and in this case, it needs to be set to `False`.
* `zabbix_proxy_startpreprocessors`: Number of pre-forked instances of preprocessing workers. The preprocessing manager process is automatically started when a preprocessor worker is started. This parameter is supported since Zabbix 4.2.0.
* `zabbix_server_username`: Default: `zabbix`. The name of the account on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_server_userid`: The UID of the account on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_server_groupname`: Default: `zabbix`. The name of the group of the user on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_server_groupid`: The GID of the group on the host. Will only be used when `zabbix_repo: epel` is used.
* `zabbix_server_include_mode`: Default: `0755`. The "mode" for the directory configured with `zabbix_server_include`.
* `zabbix_server_conf_mode`: Default: `0640`. The "mode" for the Zabbix configuration file.
* `zabbix_server_listenbacklog`: The maximum number of pending connections in the queue.
* `zabbix_server_trendcachesize`: Size of trend cache, in bytes.
* `zabbix_server_trendfunctioncachesize`: Size of trend function cache, in bytes.
* `zabbix_server_vaulttoken`: Vault authentication token that should have been generated exclusively for Zabbix server with read only permission
* `zabbix_server_vaulturl`: Vault server HTTP[S] URL. System-wide CA certificates directory will be used if SSLCALocation is not specified.
* `zabbix_server_vaultdbpath`: Vault path from where credentials for database will be retrieved by keys 'password' and 'username'.
* `zabbix_server_startreportwriters`: Number of pre-forked report writer instances.
* `zabbix_server_webserviceurl`: URL to Zabbix web service, used to perform web related tasks.
* `zabbix_server_servicemanagersyncfrequency`: How often Zabbix will synchronize configuration of a service manager (in seconds).
* `zabbix_server_problemhousekeepingfrequency`: How often Zabbix will delete problems for deleted triggers (in seconds).
* `zabbix_server_connectors`: Number of pre-forked instances of preprocessing workers.

### High Availability

These variables are specific for Zabbix 6.0 and higher:

* `zabbix_server_hanodename`: The high availability cluster node name. When empty, server is working in standalone mode; a node with empty name is registered with address for the frontend to connect to. (Default: empty)
* `zabbix_server_nodeaddress`: IP or hostname with optional port to specify how frontend should connect to the server.

### Database specific

* `zabbix_server_dbhost_run_install`: Default: `True`. When set to `True`, sql files will be executed on the host running the database.
* `zabbix_server_database`: Default: `pgsql`. The type of database used. Can be: `mysql` or `pgsql`
* `zabbix_server_database_long`: Default: `postgresql`. The type of database used, but long name. Can be: `mysql` or `postgresql`
* `zabbix_server_dbhost`: The hostname on which the database is running.
* `zabbix_server_real_dbhost`: The hostname of the dbhost that is running behind a loadbalancer/VIP (loadbalancers doesn't accept ssh connections)
* `zabbix_server_dbname`: The database name which is used by the Zabbix Server.
* `zabbix_server_dbuser`: The database username which is used by the Zabbix Server.
* `zabbix_server_dbpassword`: The database user password which is used by the Zabbix Server.
* `zabbix_server_dbport`: The database port which is used by the Zabbix Server.
* `zabbix_server_dbpassword_hash_method`: Default: `md5`. Allow switching postgresql user password creation to `scram-sha-256`, when anything other than `md5` is used then ansible won't hash the password with `md5`.
* `zabbix_database_creation`: Default: `True`. When you don't want to create the database including user, you can set it to False.
* `zabbix_server_install_database_client`: Default: `True`. False does not install database client. Default true
* `zabbix_database_sqlload`:True / False. When you don't want to load the sql files into the database, you can set it to False.
* `zabbix_database_timescaledb`:False / True. When you want to use timescaledb extension into the database, you can set it to True (this option only works for postgreSQL database).
* `zabbix_server_dbencoding`: Default: `utf8`. The encoding for the MySQL database.
* `zabbix_server_dbcollation`: Default: `utf8_bin`. The collation for the MySQL database.
* `zabbix_server_allowunsupporteddbversions`: Allow server to work with unsupported database versions.

### TLS Specific configuration

These variables are specific for Zabbix 3.0 and higher:

* `zabbix_server_tlsconnect`: How the agent should connect to server or proxy. Used for active checks.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_server_tlsaccept`: What incoming connections to accept.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_server_tlscafile`: Full pathname of a file containing the top-level CA(s) certificates for peer certificate verification.
* `zabbix_server_tlscrlfile`: Full pathname of a file containing revoked certificates.
* `zabbix_server_tlsservercertissuer`: Allowed server certificate issuer.
* `zabbix_server_tlsservercertsubject`: Allowed server certificate subject.
* `zabbix_server_tlscertfile`: Full pathname of a file containing the agent certificate or certificate chain.
* `zabbix_server_tlskeyfile`: Full pathname of a file containing the agent private key.
* `zabbix_server_dbtlsconnect`: Setting this option enforces to use TLS connection to database:

`required` - connect using TLS
`verify_ca` - connect using TLS and verify certificate
`verify_full` - connect using TLS, verify certificate and verify that database identity specified by DBHost matches its certificate

On `MySQL` starting from 5.7.11 and `PostgreSQL` the following values are supported: `required`, `verify`, `verify_full`. On MariaDB starting from version 10.2.6 `required` and `verify_full` values are supported.
By default not set to any option and the behaviour depends on database configuration.
This parameter is supported since Zabbix 5.0.0.

* `zabbix_server_dbtlscafile`: Full pathname of a file containing the top-level CA(s) certificates for database certificate verification. This parameter is supported since Zabbix 5.0.0.
* `zabbix_server_dbtlscertfile`: Full pathname of file containing Zabbix server certificate for authenticating to database. This parameter is supported since Zabbix 5.0.0.
* `zabbix_server_dbtlskeyfile`: Full pathname of file containing the private key for authenticating to database. This parameter is supported since Zabbix 5.0.0.
* `zabbix_server_dbtlscipher`: The list of encryption ciphers that Zabbix server permits for TLS protocols up through TLSv1.2. Supported only for MySQL.This parameter is supported since Zabbix 5.0.0.
* `zabbix_server_dbtlscipher13`: The list of encryption ciphersuites that Zabbix server permits for TLSv1.3 protocol. Supported only for MySQL, starting from version 8.0.16. This parameter is supported since Zabbix 5.0.0.

### Custom Zabbix Scripts

Define these variables to copy scripts to your respective scripts path.

* `zabbix_server_alertscripts`: List of alertscripts to be added to `zabbix_server_alertscriptspath`
* `zabbix_server_externalscripts`: List of alertscripts to be added to `zabbix_server_externalscriptspath`

Example:

```yaml
   zabbix_server_alertscripts:
    - path: "{{ lookup('first_found', 'zabbix-scripts/somescript.php') }}"
      name: "somescript.php"
```

## proxy

When the target host does not have access to the internet, but you do have a proxy available then the following properties needs to be set to download the packages via the proxy:

* `zabbix_http_proxy`
* `zabbix_https_proxy`

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
zabbix_server_database: mysql
zabbix_server_database_long: mysql
zabbix_server_dbport: 3306
zabbix_server_dbpassword: <SOME_SECRET_STRING>
```

Please generate a value for the `zabbix_server_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-server role will create an database and username (With the provided value for the password) in `MySQL`.
3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `MySQL` will be running.

#### Separate Setup

We need to have the following dependencies met:

1. We need to either have a `MySQL` instance running somewhere in the environment. If this is the case, we need to have a username/password combination that is allowed to create a database and an user account. If there isn't one, please make sure there is one.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_server_database: mysql
zabbix_server_database_long: mysql
zabbix_server_dbport: 3306
zabbix_server_dbhost: mysql-host
zabbix_server_dbhost_run_install: false
zabbix_server_dbpassword: <SOME_SECRET_STRING>
zabbix_server_privileged_host: '%'
zabbix_server_mysql_login_host: mysql-host
zabbix_server_mysql_login_user: root
zabbix_server_mysql_login_password: changeme
zabbix_server_mysql_login_port: 3306
```

Please generate a value for the `zabbix_server_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-server role will create an database and username (With the provided value for the password) in `MySQL`.

The `zabbix_server_privileged_host` can be set to the hostname/ip of the host running Zabbix Server for security related purposes. Also make sure that `zabbix_server_mysql_login_password` is set to the correct password for the user provided with `zabbix_server_mysql_login_host` to create a database and user in the `MySQL` instance.

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
zabbix_server_database: pgsql
zabbix_server_database_long: postgresql
zabbix_server_dbport: 5432
zabbix_server_dbpassword: <SOME_SECRET_STRING>
```

Please generate a value for the `zabbix_server_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-server role will create an database and username (With the provided value for the password) in `PgSQL`. Set `zabbix_server_dbpassword_hash_method` for PostgreSQL 10 and newer if they default to `scram-sha-256`.
3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `PgSQL` will be running.

#### Separate Setup

We need to have the following dependencies met:

1. We need to either have a `PgSQL` instance running somewhere in the environment. If this is the case, we need to have a username/password combination that is allowed to create a database and an user account. If there isn't one, please make sure there is one.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_server_database: pgsql;
zabbix_server_database_long: postgresql
zabbix_server_dbport: 5432
zabbix_server_dbhost: pgsql-host
zabbix_server_dbhost_run_install: false
zabbix_server_dbpassword: <SOME_SECRET_STRING>
zabbix_server_privileged_host: '%'
zabbix_server_pgsql_login_host: pgsql-host
zabbix_server_pgsql_login_user: postgres
zabbix_server_pgsql_login_password: changeme
zabbix_server_pgsql_login_port: 5432
```

Please generate a value for the `zabbix_server_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-server role will create an database and username (With the provided value for the password) in `PgSQL`.  Set `zabbix_server_dbpassword_hash_methodh` for PostgreSQL 10 and newer if they default to `scram-sha-256`.

The `zabbix_server_privileged_host` can be set to the hostname/ip of the host running Zabbix Server for security related purposes. Also make sure that `zabbix_server_mysql_login_password` is set to the correct password for the user provided with `zabbix_server_mysql_login_host` to create a database and user in the `PgSQL` instance.

3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Server with `PgSQL` on a different host will be running.

# Example Playbook

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
  - hosts: zabbix-server
    roles:
      - role: community.zabbix.zabbix_server
        zabbix_server_database: mysql
        zabbix_server_database_long: mysql
```

# Molecule

This role is configured to be tested with Molecule. You can find on this page some more information regarding Molecule: 

* http://werner-dijkerman.nl/2016/07/10/testing-ansible-roles-with-molecule-testinfra-and-docker/
* http://werner-dijkerman.nl/2016/07/27/extending-ansible-role-testing-with-molecule-by-adding-group_vars-dependencies-and-using-travis-ci/
* http://werner-dijkerman.nl/2016/07/31/testing-ansible-roles-in-a-cluster-setup-with-docker-and-molecule/

With each Pull Request, Molecule will be executed via Github Actions to validate the change on a new installation. Each PR should result into a correct working Zabbix Server installation and PR's will not be merged once this process fails.

# License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

# Author Information

Please send suggestion or pull requests to make this role better. Also let us know if you encounter any issues installing or using this role.

Github: https://github.com/ansible-collections/community.zabbix
