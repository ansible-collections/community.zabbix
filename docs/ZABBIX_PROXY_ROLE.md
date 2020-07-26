# community.zabbix.zabbix_proxy role

Table of Content

- [Overview](#overview)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
  * [TLS Specific configuration](#tls-specific-configuration)
  * [Zabbix API variables](#zabbix-api-variables)
- [Dependencies](#dependencies)
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

There are some variables in de default/main.yml which can (Or needs to) be changed/overriden:

* `zabbix_server_host`: The ip or dns name for the zabbix-server machine.

* `zabbix_server_port`: The port on which the zabbix-server is running. Default: 10051

* `zabbix_version`: This is the version of zabbix. Default it is 5.0, but can be overriden to 4.4/4.2/4.0/3.4/3.2/3.0/2.4/2.2.

* `zabbix_proxy_{rhel,debian,ubuntu}_version`: This is the version of zabbix proxy. For example 4.4.4/4.2.5/4.2.8

* `zabbix_repo`: True / False. When you already have an repository with the zabbix components, you can set it to False.

* `*zabbix_proxy_package_state`: Default: _present_. Can be overridden to "latest" to update packages when needed.

* `zabbix_proxy_install_database_client`: True / False. False does not install database client. Default: True.

* `zabbix_agent_become_on_localhost`: Set to `False` if you don't need to elevate privileges on localhost to install packages locally with pip. Default: True

* `zabbix_proxy_manage_service`: True / False. When you run multiple Zabbix proxies in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-proxy service, because Pacemaker is in control of zabbix-proxy service.

* `zabbix_install_pip_packages`: Set to `False` if you don't want to install the required pip packages. Useful when you control your environment completely. Default: True

There are some zabbix-proxy specific variables which will be used for the zabbix-proxy configuration file, these can be found in the default/main.yml file. There are 2 which needs some explanation:

```yaml
  #zabbix_proxy_database: mysql
  #zabbix_proxy_database_long: mysql
  #zabbix_proxy_database: sqlite3
  #zabbix_proxy_database_long: sqlite3
  zabbix_proxy_database: pgsql
  zabbix_proxy_database_long: postgresql
```

There are 3 database_types which will be supported: mysql/postgresql and sqlite. You'll need to comment or uncomment the database you would like to use. In example from above, the postgresql database is used. If you want to use mysql, uncomment the 2 lines from mysql and comment the 2 lines for postgresql.

If you use mysql, then you should define mysql username, password and host to prepare zabbix database, otherwise they will be considered as their default value (and therefor, connecting to database will be considered as connecting to localhost with no password). the keys are belows:

```yaml
   zabbix_proxy_mysql_login_host
   zabbix_proxy_mysql_login_user
   zabbix_proxy_mysql_login_password
```

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

For the databases you should find a role that suits your needs, as I don't want to force you for using a specific role. Before applying this Zabbix Server role, the database service should already be installed and running, and should be able to handle the modules in Ansible that belong to that database.

This role will **not** install a MySQL or PostgreSQL service.

This role will create a Zabbix user and a Zabbix database in the configured database type.

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
