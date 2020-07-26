# community.zabbix.zabbix_server role

Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Installation](#installation)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
    + [Overall Zabbix](#overall-zabbix)
    + [Zabbix Server](#zabbix-server)
    + [Custom Zabbix Scripts](#custom-zabbix-scripts)
    + [TLS Specific configuration](#tls-specific-configuration)
  * [Database](#database)
- [Dependencies](#dependencies)
- [Example Playbook](#example-playbook)
- [Molecule](#molecule)
- [License](#license)
- [Author Information](#author-information)

# Overview

This is a role for installing and maintaining the zabbix-server.

# Requirements

## Operating systems

This role will work on the following operating systems:

 * Red Hat
 * Debian
 * Ubuntu

So, you'll need one of those operating systems.. :-)
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

## Zabbix Versions

See the following list of supported Operating systems with the Zabbix releases:

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

# Installation

Installing this role is very simple: `ansible-galaxy install community.zabbix.zabbix_server`

Please be aware that this role only installs the Zabbix Server and not the Zabbix Web. If you do want to have a Zabbix Web, please execute the following command: `ansible-galaxy install community.zabbix.zabbix_web`

Default username/password for the Zabbix Web interface is the default one installed by Zabbix.

Username: Admin
Password: zabbix

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_server_version`: This is the version of zabbix. Default: 5.0. Can be overridden to 4.4, 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2. Previously the variable `zabbix_version` was used directly but it could cause [some inconvenience](https://github.com/dj-wasabi/ansible-zabbix-agent/pull/303). That variable is maintained by retrocompativility.
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo`: Default: _zabbix_
  * _epel_ install agent from EPEL repo
  * _zabbix_ (default) install agent from Zabbix repo
  * _other_ install agent from pre-existing or other repo
* `zabbix_server_package_state`: Default: _present_. Can be overridden to "latest" to update packages when needed.
* `zabbix_service_state`: Default: `started`. Can be overridden to stopped if needed
* `zabbix_service_enabled`: Default: `True` Can be overridden to `False` if needed
* `zabbix_selinux`: Enables an SELinux policy so that the server will run. Default: False.

### Zabbix Server

* `zabbix_server_name`: The name of the Zabbix Server.
* `zabbix_server_database`: The type of database used. Can be: mysql or pgsql
* `zabbix_server_database_long`: The type of database used, but long name. Can be: mysql or postgresql
* `zabbix_server_hostname`: The hostname on which the zabbix-server is running. Default set to: {{ inventory_hostname }}
* `zabbix_server_listenport`: On which port the Zabbix Server is available. Default: 10051
* `zabbix_server_dbhost`: The hostname on which the database is running.
* `zabbix_server_real_dbhost`: The hostname of the dbhost that is running behind a loadbalancer/VIP (loadbalancers doesn't accept ssh connections)
* `zabbix_server_dbname`: The database name which is used by the Zabbix Server.
* `zabbix_server_dbuser`: The database username which is used by the Zabbix Server.
* `zabbix_server_dbpassword`: The database user password which is used by the Zabbix Server.
* `zabbix_server_dbport`: The database port which is used by the Zabbix Server.
* `zabbix_database_creation`: True / False. When you don't want to create the database including user, you can set it to False.
* `zabbix_server_install_recommends`: True / False. False does not install the recommended packages that come with the zabbix-server install. Default true
* `zabbix_server_install_database_client`: True / False. False does not install database client. Default true
* `zabbix_database_sqlload`:True / False. When you don't want to load the sql files into the database, you can set it to False.
* `zabbix_server_dbencoding`: The encoding for the MySQL database. Default set to `utf8`
* `zabbix_server_dbcollation`: The collation for the MySQL database. Default set to `utf8_bin`
* `zabbix_server_manage_service`: True / False. When you run multiple Zabbix servers in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-server service, because Pacemaker is in control of zabbix-server service.

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

## Database

There are some zabbix-server specific variables which will be used for the zabbix-server configuration file. These can be found in the defaults/main.yml file. There are 3 which need some explanation:
```yaml
  #zabbix_server_database: mysql
  #zabbix_server_database_long: mysql
  zabbix_server_database: pgsql
  zabbix_server_database_long: postgresql
  [...]
  zabbix_server_dbport: 5432
```

There are 2 database_types which will be supported: mysql and postgresql. You'll need to comment or uncomment the database you would like to use and adjust the port number (`server_dbport`) accordingly (`5432` is the default postgresql port). In example from above, the postgresql database is used. If you want to use mysql, uncomment the 2 lines from mysql and comment the 2 lines for postgresql and change the database port to the mysql one (default mysql port is `3306`).

If you use mysql, then you should define mysql username, password and host to prepare zabbix database, otherwise they will be considered as their default value (and therefore, connecting to database will be considered as connecting to localhost with no password). The keys are below:

```yaml
   zabbix_server_mysql_login_host
   zabbix_server_mysql_login_user
   zabbix_server_mysql_login_password
```
If you use pgsql, then you should define pgsql username, password and host to prepare zabbix database, otherwise they will be considered as their default value (and therefore, connecting to database will be considered as connecting to localhost with no password). The keys are below:

```yaml
   zabbix_server_pgsql_login_host
   zabbix_server_pgsql_login_user
   zabbix_server_pgsql_login_password
```

# Dependencies

For the databases you should find a role that suits your needs, as I don't want to force you for using a specific role. Before applying this Zabbix Server role, the database service should already be installed and running, and should be able to handle the modules in Ansible that belong to that database.

This role will **not** install a MySQL or PostgreSQL service.

This role will create a Zabbix user and a Zabbix database in the configured database type.

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

With each Pull Request, Molecule will be executed via travis.ci. Pull Requests will only be merged once these tests run successfully.

# License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

# Author Information

Please send suggestion or pull requests to make this role better. Also let us know if you encounter any issues installing or using this role.

Github: https://github.com/ansible-collections/community.zabbix
