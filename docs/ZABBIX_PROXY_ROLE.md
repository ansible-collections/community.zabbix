# community.zabbix.zabbix_proxy role

![Zabbix Proxy](https://github.com/ansible-collections/community.zabbix/workflows/community.zabbix.zabbix_proxy/badge.svg)

**Table of Contents**

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
  * [proxy](#proxy)
  * [Database](#database)
    + [MySQL](#mysql)
      - [Local Setup](#local-setup)
      - [Separate Setup](#separate-setup)
    + [PostgreSQL](#postgresql)
      - [Local Setup](#local-setup-1)
      - [Separate Setup](#separate-setup-1)
    + [SQLite3](#sqlite3)
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
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

# Requirements
## Ansible 2.10 and higher

With the release of Ansible 2.10, modules have been moved into collections.  With the exception of ansible.builtin modules, this means additonal collections must be installed in order to use modules such as seboolean (now ansible.posix.seboolean).  The following collection is now required: `ansible.posix`.  Installing the collection:

```sh
ansible-galaxy collection install ansible.posix
```

If you are willing to create proxy in Zabbix via API as a part of this role execution then you need to install `ansible.netcommon` collection too:

```
ansible-galaxy collection install ansible.netcommon
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

See the following list of supported Operating systems with the Zabbix releases.

| Zabbix              | 7.2 | 7.0 | 6.4 | 6.0 |
|---------------------|-----|-----|-----|-----|
| Red Hat Fam 9       |  V  |  V  |  V  |  V  |
| Red Hat Fam 8       |  V  |  V  |  V  |  V  |
| Ubuntu 24.04 noble  |  V  |  V  |  V  |  V  |
| Ubuntu 22.04 jammy  |  V  |  V  |  V  |  V  |
| Ubuntu 20.04 focal  |  V  |  V  |  V  |  V  |
| Debian 12 bookworm  |  V  |  V  |  V  |  V  |
| Debian 11 bullseye  |  V  |  V  |  V  |  V  |
| Suse Fam 15         |  V  |  V  |  V  |  V  |

You can bypass this matrix by setting `enable_version_check: false`

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Zabbix Proxy

* `zabbix_proxy_version`:  Optional. The latest available major.minor version of Zabbix will be installed on the host(s). If you want to use an older version, please specify this in the major.minor format. Example: `zabbix_proxy_version: 6.0`.
* `zabbix_proxy_version_minor`: When you want to specify a minor version to be installed. RedHat only. Default set to: `*` (latest available)
* `zabbix_proxy_ip`: The IP address of the host. When not provided, it will be determined via the `ansible_default_ipv4` fact.
* `zabbix_proxy_server`: The ip or dns name for the zabbix-server machine.
* `zabbix_proxy_install_database_client`: Default: `True`. False does not install database client.
* `zabbix_proxy_manage_service`: Default: `True`. When you run multiple Zabbix proxies in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-proxy service, because Pacemaker is in control of zabbix-proxy service.
* `zabbix_proxy_include_mode`: Default: `0755`. The "mode" for the directory configured with `zabbix_proxy_include`.
* `zabbix_proxy_conf_mode`: Default: `0644`. The "mode" for the Zabbix configuration file.
* `zabbix_manage_repo`: Have the collection install and configure the Zabbix repo Default `true`.

### Database specific

* `zabbix_proxy_dbhost_run_install`: Default: `True`. When set to `True`, sql files will be executed on the host running the database.
* `zabbix_proxy_database`: Default: `mysql`. The type of database used. Can be: `mysql`, `pgsql` or `sqlite3`
* `zabbix_proxy_dbhost`: Default: localhost. The hostname on which the database is running. Will be ignored when `sqlite3` is used as database.
* `zabbix_proxy_real_dbhost`: The hostname of the dbhost that is running behind a loadbalancer/VIP (loadbalancers doesn't accept ssh connections) Will be ignored when `sqlite3` is used as database.
* `zabbix_proxy_dbname`: Default: zabbix_proxy. The database name which is used by the Zabbix Proxy.
* `zabbix_proxy_dbuser`: Default: zabbix_proxy. The database username which is used by the Zabbix Proxy. Will be ignored when `sqlite3` is used as database.
* `zabbix_proxy_dbpassword`: Default: zabbix_proxy. The database user password which is used by the Zabbix Proxy. Will be ignored when `sqlite3` is used as database.
* `zabbix_proxy_dbpassword_hash_method`: Default: `md5`. Allow switching postgresql user password creation to `scram-sha-256`, when anything other than `md5` is used then ansible won't hash the password with `md5`.
* `zabbix_proxy_dbport`: The database port which is used by the Zabbix Proxy. Will be ignored when `sqlite3` is used as database.
* `zabbix_proxy_database_creation`: Default: `True`. When you don't want to create the database including user, you can set it to False.
* `zabbix_proxy_install_database_client`: Default: `True`. False does not install database client. Default true
* `zabbix_proxy_database_sqlload`:True / False. When you don't want to load the sql files into the database, you can set it to False.
* `zabbix_proxy_dbencoding`: Default: `utf8`. The encoding for the MySQL database.
* `zabbix_proxy_dbcollation`: Default: `utf8_bin`. The collation for the MySQL database.zabbix_proxy_


### Yum/APT
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)
* `zabbix_repo_yum_gpgcheck`: Default: `0`.  Should yum perform a GPG check on the repository
* `zabbix_proxy_disable_repo`: A list of repos to disable during install.  Default `epel`.
* `zabbix_proxy_apt_priority`: APT priority for the zabbix repository
* `*zabbix_proxy_package_state`: Default: `present`. Can be overridden to `latest` to update packages
* `zabbix_repo_deb_url`: The URL to the Zabbix repository.  Default `http://repo.zabbix.com/zabbix/{{ zabbix_proxy_version }}/{{ ansible_distribution.lower() }}`
* `zabbix_repo_deb_component`: The repository component for Debian installs. Default `main`.
* `zabbix_repo_deb_gpg_key_url`: The URL to download the Zabbix GPG key from. Default `http://repo.zabbix.com/zabbix-official-repo.key`.
* `zabbix_repo_deb_include_deb_src`: True, if deb-src should be included in the zabbix.sources entry. Default `true`.

### SElinux

Selinux changes will be installed based on the status of selinux running on the target system.

## Proxy

When the target host does not have access to the internet, but you do have a proxy available then the following properties needs to be set to download the packages via the proxy:

* `zabbix_http_proxy`
* `zabbix_https_proxy`

## Database

With Zabbix Proxy you can make use of 2 different databases:

* MySQL
* PostgreSQL
* SQLite3

In the following paragraphs we dive into both setups.

### MySQL

To make the Zabbix Proxy work with a `MySQL` database, there are 2 types on setup:

1. Local setup, `MySQL` running on same host as the Zabbix Proxy;
2. Separate setup, `MySQL` running on a different host than the Zabbix Proxy.

#### Local Setup

We need to have the following dependencies met:

1. Find an (Ansible) role that will install a `MySQL` instance on the host. Example: `geerlingguy.mysql` can be used, but also others can be used. Please make sure that before installing the Zabbix Proxy, you have a fully functional `MySQL` instance running.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: mysql
zabbix_proxy_dbport: 3306
zabbix_proxy_dbpassword: <SOME_SECRET_STRING>
```

Please generate a value for the `zabbix_proxy_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-proxy role will create an database and username (With the provided value for the password) in `MySQL`.

3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Proxy with `MySQL` will be running.

#### Separate Setup

We need to have the following dependencies met:

1. We need to either have a `MySQL` instance running somewhere in the environment. If this is the case, we need to have a username/password combination that is allowed to create a database and an user account. If there isn't one, please make sure there is one.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: mysql
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

The `zabbix_proxy_privileged_host` can be set to the hostname/ip of the host running Zabbix Proxy for security related purposes. Also make sure that `zabbix_proxy_mysql_login_password` is set to the correct password for the user provided with `zabbix_proxy_mysql_login_host` to create a database and user in the `MySQL` instance.

3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Proxy with `MySQL` on a different host will be running.

### PostgreSQL

To make the Zabbix Proxy work with a `PgSQL` database, there are 2 types on setup:

1. Local setup, `PgSQL` running on same host as the Zabbix Proxy;
2. Separate setup, `PgSQL` running on a different host than the Zabbix Proxy.

#### Local Setup

We need to have the following dependencies met:

1. Find an (Ansible) role that will install a `PgSQL` instance on the host. Example: `geerlingguy.postgresql` can be used, but also others can be used. Please make sure that before installing the Zabbix Proxy, you have a fully functional `PgSQL` instance running.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: pgsql
zabbix_proxy_dbport: 5432
zabbix_proxy_dbpassword: <SOME_SECRET_STRING>
```

Please generate a value for the `zabbix_proxy_dbpassword` property (Maybe use `ansible-vault` for this). The zabbix-proxy role will create an database and username (With the provided value for the password) in `PgSQL`.
3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Proxy with `PgSQL` will be running.

#### Separate Setup

We need to have the following dependencies met:

1. We need to either have a `PgSQL` instance running somewhere in the environment. If this is the case, we need to have a username/password combination that is allowed to create a database and an user account. If there isn't one, please make sure there is one.
2. We need to set some variables, either as input for the playbook or set them into the `group_vars` or `host_vars` (Your preference choice). We need to set the following properties:

```yaml
zabbix_proxy_database: pgsql
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

The `zabbix_proxy_privileged_host` can be set to the hostname/ip of the host running Zabbix Proxy for security related purposes. Also make sure that `zabbix_proxy_mysql_login_password` is set to the correct password for the user provided with `zabbix_proxy_mysql_login_host` to create a database and user in the `PgSQL` instance.

3. Execute the role by running the Ansible playbook that calls this role. At the end of this run, the Zabbix Proxy with `PgSQL` on a different host will be running.zabbix_proxy_

### SQLite3

The SQLite3 can only be used on the same host as on which the Zabbix Proxy is running. If you want to use a seperate host for running the database for the proxy, please consider going for MySQL or PostGreSQL.

The following properties needs to be set when using `SQLite3` as the database:

```yaml
zabbix_proxy_database: sqlite3
zabbix_proxy_dbname: /path/to/sqlite3.db
```

NOTE: When using `zabbix_proxy_dbname: zabbix_proxy` (Which is default with this role), it will automatically be stored on `/var/lib/zabbix/zabbix_proxy.db`

## Zabbix API variables

These variables need to be overridden when you want to make use of the Zabbix API for automatically creating and or updating proxies, i.e. when `zabbix_api_create_proxy` is set to `True`.

* `zabbix_api_server_host`: The IP or hostname/FQDN of Zabbix server. Example: zabbix.example.com
* `zabbix_api_use_ssl`: Is SSL required to connect to the Zabbix API server?  Default: `false`
* `zabbix_api_server_port`: 80 if `zabbix_api_use_ssl` is `false` and 443 if `true` (Default) TCP port to use to connect to Zabbix server. Example: 8080
* `zabbix_api_login_user`: Username of user which has API access.
* `zabbix_api_login_pass`: Password for the user which has API access.
* `zabbix_api_http_user`: The http user to access zabbix url with Basic Auth (if your Zabbix is behind a proxy with HTTP Basic Auth).
* `zabbix_api_http_password`: The http password to access zabbix url with Basic Auth (if your Zabbix is behind a proxy with HTTP Basic Auth).
* `zabbix_api_validate_certs`: yes (Default) if we need to validate tls certificates of the API. Use `no` in case self-signed certificates are used.
* `zabbix_api_timeout`: timeout for API calls (default to 30 seconds)
* `ansible_zabbix_url_path`: URL path if Zabbix WebUI running on non-default (zabbix) path, e.g. if http://<FQDN>/zabbixeu then set to `zabbixeu`
* `zabbix_api_create_proxy`: When you want to enable the Zabbix API to create/delete the proxy. This has to be set to `True` if you want to make use of `zabbix_proxy_state`. Default: `False`
* `zabbix_proxy_name`: name of the Zabbix proxy as it is seen by Zabbix server
* `zabbix_proxy_state`: present (Default) if the proxy needs to be created or absent if you want to delete it. This only works when `zabbix_api_create_proxy` is set to `True`.
* `zabbix_proxy_status`: active (Default) if the proxy needs to be active or passive.

## Configuration Variables

The following table lists all variables that are exposed to modify the configuration of the zabbix_proxy.conf file.  Specific details of each variable can be found in the Zabbix documentation.

**NOTE**:  Only variables with a default value appear in the defaults file, all others must be added.

| Zabbix Name | Variable Name | Default Value |Notes |
|-----------|------------------|--------|--------|
| AllowRoot | zabbix_proxy_allowroot | `False` | `True`/`False` |
| AllowUnsupportedDBVersions | zabbix_proxy_allowunsupporteddbversions | `False` | `True`/`False` |
| CacheSize | zabbix_proxy_cachesize | 32M | |
| ConfigFrequency | zabbix_proxy_configfrequency | 3600 | |
| DataSenderFrequency | zabbix_proxy_datasenderfrequency | 1 | |
| DBHost | zabbix_proxy_dbhost | localhost| |
| DBName | zabbix_proxy_dbname | zabbix_proxy| |
| DBPassword | zabbix_proxy_dbpassword | zabbix_proxy| |
| DBPort | zabbix_proxy_dbport | Varies by database | |
| DBSchema | zabbix_proxy_dbschema || |
| DBSocket | zabbix_proxy_dbsocket || |
| DBTLSCAFile | zabbix_proxy_dbtlscafile || |
| DBTLSCertFile | zabbix_proxy_dbtlscertfile || |
| DBTLSCipher | zabbix_proxy_dbtlscipher || |
| DBTLSCipher13 | zabbix_proxy_dbtlscipher13 || |
| DBTLSConnect | zabbix_proxy_dbtlsconnect || |
| DBTLSKeyFile | zabbix_proxy_dbtlskeyfile || |
| DBUser | zabbix_proxy_dbuser | zabbix_proxy| |
| DebugLevel | zabbix_proxy_debuglevel |3| |
| EnableRemoteCommands | zabbix_proxy_enableremotecommands | `False` | `True`/`False` |
| ExternalScripts | zabbix_proxy_externalscripts | /usr/lib/zabbix/externalscripts| |
| Fping6Location | zabbix_proxy_fping6location | OS Specific Value | |
| FpingLocation | zabbix_proxy_fpinglocation | OS Specific Value | |
| HeartbeatFrequency | zabbix_proxy_heartbeatfrequency |60| Version 6.0 |
| HistoryCacheSize | zabbix_proxy_historycachesize | 16M| |
| HistoryIndexCacheSize | zabbix_proxy_historyindexcachesize | 4M| |
| Hostname | zabbix_proxy_hostname | "{{ inventory_hostname }}"| |
| HostnameItem | zabbix_proxy_hostnameitem || |
| HousekeepingFrequency | zabbix_proxy_housekeepingfrequency |1| |
| Include | zabbix_proxy_include | /etc/zabbix/zabbix_proxy.conf.d/*.conf | |
| JavaGateway | zabbix_proxy_javagateway || |
| JavaGatewayPort | zabbix_proxy_javagatewayport |10052| |
| ListenBacklog | zabbix_proxy_listenbacklog || |
| ListenIP | zabbix_proxy_listenip |0.0.0.0 | |
| ListenPort | zabbix_proxy_listenport |10051| |
| LoadModule | zabbix_proxy_loadmodule || |
| LoadModulePath | zabbix_proxy_loadmodulepath | /usr/lib/zabbix/modules| |
| LogFile | zabbix_proxy_logfile | /var/log/zabbix/zabbix_proxy.log| |
| LogFileSize | zabbix_proxy_logfilesize |10| |
| LogRemoteCommands | zabbix_proxy_logremotecommands | `False` | `True`/`False` |
| LogSlowQueries | zabbix_proxy_logslowqueries | 0 | |
| LogType | zabbix_proxy_logtype | file| |
| MaxConcurrentChecksPerPoller | zabbix_proxy_maxconcurrentchecksperpoller | 1000 | Version 7.0 or Greater |
| PidFile | zabbix_proxy_pidfile | /var/run/zabbix/zabbix_proxy.pid| |
| ProxyBufferMode | zabbix_proxy_proxybuffermode | disk | Version 7.0 or Greater |
| ProxyConfigFrequency | zabbix_proxy_proxyconfigfrequency | 10 | Version 6.4 or Lower |
| ProxyLocalBuffer | zabbix_proxy_proxylocalbuffer |0| |
| ProxyMemoryBufferAge | zabbix_proxy_proxymemorybufferage | 0 | Version 7.0 or Greater |
| ProxyMemoryBufferSize | zabbix_proxy_proxymemorybuffersize | 0 | Version 7.0 or Greater |
| ProxyMode | zabbix_proxy_proxymode | 0 | `0`: Active `1`: Passive |
| ProxyOfflineBuffer | zabbix_proxy_proxyofflinebuffer | 1 | |
| Server | zabbix_proxy_server | 192.168.1.1| |
| SNMPTrapperFile | zabbix_proxy_snmptrapperfile | /tmp/zabbix_traps.tmp | |
| SocketDir | zabbix_proxy_socketdir | /var/run/zabbix | |
| SourceIP | zabbix_proxy_sourceip || |
| SSHKeyLocation | zabbix_proxy_sshkeylocation || |
| SSLCALocation | zabbix_proxy_sslcalocation || |
| SSLCertLocation | zabbix_proxy_sslcertlocation || |
| SSLKeyLocation | zabbix_proxy_sslkeylocation || |
| StartAgentPollers | zabbix_proxy_startagentpollers | 1 | Version 7.0 or Greater |
| StartBrowserPollers | zabbix_proxy_startbrowserpollers | 1 | Version 7.0 or Greater |
| StartDBSyncers | zabbix_proxy_startdbsyncers |4| |
| StartDiscoverers | zabbix_proxy_startdiscoverers |1| |
| StartHistoryPollers | zabbix_proxy_starthistorypollers | 1 | Version 6.0 |
| StartHTTPAgentPollers | zabbix_proxy_starthttpagentpollers | 1 | Version 7.0 or Greater |
| StartHTTPPollers | zabbix_proxy_starthttppollers |1| |
| StartIPMIPollers | zabbix_proxy_startipmipollers |0| |
| StartJavaPollers | zabbix_proxy_startjavapollers |0 | |
| StartODBCPollers | zabbix_proxy_startodbcpollers |1| |
| StartPingers | zabbix_proxy_startpingers |1| |
| StartPollers | zabbix_proxy_startpollers |5| |
| StartPollersUnreachable | zabbix_proxy_startpollersunreachable |1| |
| StartPreprocessors | zabbix_proxy_startpreprocessors |3| |
| StartSNMPPollers | zabbix_proxy_startsnmppollers | 1 | Version 7.0 or Greater |
| StartSNMPTrapper | zabbix_proxy_startsnmptrapper | 0 | |
| StartTrappers | zabbix_proxy_starttrappers |5| |
| StartVMwareCollectors | zabbix_proxy_startvmwarecollectors | 0 | |
| StatsAllowedIP | zabbix_proxy_statsallowedip | "127.0.0.1"| |
| Timeout | zabbix_proxy_timeout |3| |
| TLSAccept | zabbix_proxy_tlsaccept || |
| TLSCAFile | zabbix_proxy_tlscafile || |
| TLSCertFile | zabbix_proxy_tlscertfile || |
| TLSCipherAll | zabbix_proxy_tlscipherall || |
| TLSCipherAll13 | zabbix_proxy_tlscipherall13 || |
| TLSCipherCert | zabbix_proxy_tlsciphercert || |
| TLSCipherCert13 | zabbix_proxy_tlsciphercert13 || |
| TLSCipherPSK | zabbix_proxy_tlscipherpsk || |
| TLSCipherPSK13 | zabbix_proxy_tlscipherpsk13 || |
| TLSConnect | zabbix_proxy_tlsconnect || |
| TLSCRLFile | zabbix_proxy_tlscrlfile || |
| TLSKeyFile | zabbix_proxy_tlskeyfile || |
| TLSPSKFile | zabbix_proxy_tlspskfile || |
| TLSPSKIdentity | zabbix_proxy_tlspskidentity || |
| TLSServerCertIssuer | zabbix_proxy_tlsservercertissuer || |
| TLSServerCertSubject | zabbix_proxy_tlsservercertsubject || |
| TmpDir | zabbix_proxy_tmpdir | /tmp| |
| TrapperTimeout | zabbix_proxy_trappertimeout |300| |
| UnavailableDelay | zabbix_proxy_unavailabledelay | 60| |
| UnreachableDelay | zabbix_proxy_unreachabledelay | 15 | |
| UnreachablePeriod | zabbix_proxy_unreachableperiod | 45| |
| User | zabbix_proxy_user | zabbix | |
| Vault | zabbix_proxy_vault || Version 6.2 or Greater |
| VaultDBPath | zabbix_proxy_vaultdbpath || |
| VaultPrefix | zabbix_proxy_vaultprefix || Version 7.0 or Greater |
| VaultTLSCertFile | zabbix_proxy_vaulttlscertfile || Version 6.4 or Greater |
| VaultTLSKeyFile | zabbix_proxy_vaulttlskeyfile || Version 6.4 or Greater |
| VaultToken | zabbix_proxy_vaulttoken || |
| VaultURL | zabbix_proxy_vaulturl |https://127.0.0.1:8200| |
| VMwareCacheSize | zabbix_proxy_vmwarecachesize | 8M| |
| VMwareFrequency | zabbix_proxy_vmwarefrequency |60| |
| VMwarePerfFrequency | zabbix_proxy_vmwareperffrequency | 60 | |
| VMwareTimeout | zabbix_proxy_vmwaretimeout | 10 | |
| WebDriverURL | zabbix_proxy_webdriverurl | | Version 7.0 or Greater |

## Tags

The majority of tasks within this role are tagged as follows:

* `install`:  Tasks associated with the installation of software.
* `dependencies`:  Installation tasks related to dependencies that aren't part of the core zabbix installation.
* `database`: Tasks associated with the installation or configuration of the database.
* `api`:  Tasks associated with using the Zabbix API to connect and modify the Zabbix server.
* `config`:  Tasks associated with the configuration of Zabbix or a supporting service.
* `service`:  Tasks associated with managing a service.

# Example Playbook

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
  - hosts: zabbix-proxy
    roles:
      - role: community.zabbix.zabbix_proxy
        zabbix_proxy_server: 192.168.1.1
        zabbix_proxy_database: mysql
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

