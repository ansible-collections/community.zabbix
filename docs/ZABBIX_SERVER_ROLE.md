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

When you are a MySQL user and using Ansible 2.10 or newer, then there is a dependency on the collection named `community.mysql`. This collections are needed as the `mysql_` modules are now part of collections and not standard in Ansible anymore. Installing the collection:

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

| Zabbix              | 7.4 | 7.2 | 7.0 | 6.0 |
|---------------------|-----|-----|-----|-----|
| Red Hat Fam 9       |  V  |  V  |  V  |  V  |
| Red Hat Fam 8       |  V  |  V  |  V  |  V  |
| Ubuntu 24.04 noble  |  V  |  V  |  V  |  V  |
| Ubuntu 22.04 jammy  |  V  |  V  |  V  |  V  |
| Debian 12 bookworm  |  V  |  V  |  V  |  V  |
| Debian 11 bullseye  |     |     |     |  V  |
| Suse Fam 15         |  V  |  V  |  V  |  V  |

You can bypass this matrix by setting `enable_version_check: false`

# Installation

Installing this role is very simple: `ansible-galaxy install community.zabbix.zabbix_server`

Please be aware that this role only installs the Zabbix Server and not the Zabbix Web. If you do want to have a Zabbix Web, please execute the following command: `ansible-galaxy install community.zabbix.zabbix_web`

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_server_version`: Optional. The latest available major.minor version of Zabbix will be installed on the host(s). If you want to use an older version, please specify this in the major.minor format. Example: `zabbix_server_version: 6.0`.
* `zabbix_server_version_minor`: When you want to specify a minor version to be installed. RedHat only. Default set to: `*` (latest available)
* `zabbix_server_disable_repo`: A list of repos to disable during install.  Default `epel`.
* `zabbix_service_state`: Default: `started`. Can be overridden to stopped if needed
* `zabbix_service_enabled`: Default: `True` Can be overridden to `False` if needed
* `zabbix_manage_repo`: Have the collection install and configure the Zabbix repo Default `true`.


### SElinux

Selinux changes will be installed based on the status of selinux running on the target system.

* `selinux_allow_zabbix_can_network`: Default: `True`.

### Zabbix Server

* `zabbix_server_packages`: List of packages to install, can be overridden for a non-supported/custom setup.
* `zabbix_server_package_state`: Default: `present`. Can be overridden to `latest` to update packages when needed.
* `zabbix_server_install_recommends`: Default: `True`. `False` does not install the recommended packages that come with the zabbix-server install.
* `zabbix_server_manage_service`: Default: `True`. When you run multiple Zabbix servers in a High Available cluster setup (e.g. pacemaker), you don't want Ansible to manage the zabbix-server service, because Pacemaker is in control of zabbix-server service and in this case, it needs to be set to `False`.
* `zabbix_server_include_mode`: Default: `0755`. The "mode" for the directory configured with `zabbix_server_include`.
* `zabbix_server_conf_mode`: Default: `0640`. The "mode" for the Zabbix configuration file.

### Database specific

* `zabbix_server_dbhost_run_install`: Default: `True`. When set to `True`, sql files will be executed on the host running the database.
* `zabbix_server_database`: Default: `pgsql`. The type of database used. Can be: `mysql` or `pgsql`
* `zabbix_server_dbhost`: The hostname on which the database is running.
* `zabbix_server_real_dbhost`: The hostname of the dbhost that is running behind a loadbalancer/VIP (loadbalancers doesn't accept ssh connections)
* `zabbix_server_dbname`: The database name which is used by the Zabbix Server.
* `zabbix_server_dbuser`: The database username which is used by the Zabbix Server.
* `zabbix_server_dbpassword`: The database user password which is used by the Zabbix Server.
* `zabbix_server_dbpassword_hash_method`: Default: `md5`. Allow switching postgresql user password creation to `scram-sha-256`, when anything other than `md5` is used then ansible won't hash the password with `md5`.
* `zabbix_server_dbport`: The database port which is used by the Zabbix Server.
* `zabbix_server_dbpassword_hash_method`: Default: `md5`. Allow switching postgresql user password creation to `scram-sha-256`, when anything other than `md5` is used then ansible won't hash the password with `md5`.
* `zabbix_server_database_creation`: Default: `True`. When you don't want to create the database including user, you can set it to False.
* `zabbix_server_install_database_client`: Default: `True`. False does not install database client. Default true
* `zabbix_server_database_sqlload`:True / False. When you don't want to load the sql files into the database, you can set it to False.
* `zabbix_server_database_timescaledb`:False / True. When you want to use timescaledb extension into the database, you can set it to True (this option only works for postgreSQL database).
* `zabbix_server_database_schemas`: List of schemas to load, can be overridden for a non-supported/custom setup.
* `zabbix_server_dbencoding`: Default: `utf8`. The encoding for the MySQL database.
* `zabbix_server_dbcollation`: Default: `utf8_bin`. The collation for the MySQL database.

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

## Configuration Variables

The following table lists all variables that are exposed to modify the configuration of the zabbix_server.conf file.  Specific details of each variable can be found in the Zabbix documentation.

**NOTE**:  Only variables with a default value appear in the defaults file, all others must be added.

| Zabbix Name | Variable Name | Default Value |Notes |
|-----------|------------------|--------|--------|
|AlertScriptsPath | zabbix_server_alertscriptspath | /usr/lib/zabbix/alertscripts |  |
|AllowRoot | zabbix_server_allowroot | `False` | `True`/`False` |
|AllowSoftwareUpdateCheck | zabbix_server_allowsoftwareupdatecheck | `True` | `True`/`False` Version 7.0 or later |
|AllowUnsupportedDBVersions | zabbix_server_allowunsupporteddbversions | `False` | `True`/`False` |
|CacheSize | zabbix_server_cachesize | 32M |  |
|CacheUpdateFrequency | zabbix_server_cacheupdatefrequency | varies by version |  |
|DBHost | zabbix_server_dbhost | localhost |  |
|DBName | zabbix_server_dbname | zabbix-server |  |
|DBPassword | zabbix_server_dbpassword | zabbix-server |  |
|DBPort | zabbix_server_dbport | varies by database |  |
|DBSchema | zabbix_server_dbschema | |  |
|DBSocket | zabbix_server_dbsocket | |  |
|DBTLSCAFile | zabbix_server_dbtlscafile | |  |
|DBTLSCertFile | zabbix_server_dbtlscertfile | |  |
|DBTLSCipher | zabbix_server_dbtlscipher | |  |
|DBTLSCipher13 | zabbix_server_dbtlscipher13 | |  |
|DBTLSConnect | zabbix_server_dbtlsconnect | |  |
|DBTLSKeyFile | zabbix_server_dbtlskeyfile | |  |
|DBUser | zabbix_server_dbuser | zabbix-server |  |
|DebugLevel | zabbix_server_debuglevel | 3 |  |
|EnableGlobalScripts | zabbix_server_enableglobalscripts | `False` | `True`/`False` Version 7.0 or later |
|ExportDir | zabbix_server_exportdir | |  |
|ExportFileSize | zabbix_server_exportfilesize | 1G |  |
|ExportType | zabbix_server_exporttype | |  |
|ExternalScripts | zabbix_server_externalscriptspath | /usr/lib/zabbix/externalscripts |  |
|Fping6Location | zabbix_server_fping6location | OS Specific Value |  |
|FpingLocation | zabbix_server_fpinglocation | OS Specific Value |  |
|HANodeName | zabbix_server_hanodename | |  |
|HistoryCacheSize | zabbix_server_historycachesize | 16M |  |
|HistoryIndexCacheSize | zabbix_server_historyindexcachesize | 4M |  |
|HistoryStorageDateIndex | zabbix_server_historystoragedateindex | `False` | `True`/`False` |
|HistoryStorageTypes | zabbix_server_historystoragetypes |  uint,dbl,str,log,text |  |
|HistoryStorageURL | zabbix_server_historystorageurl | |  |
|HousekeepingFrequency | zabbix_server_housekeepingfrequency | 1 |  |
|Include | zabbix_server_include | /etc/zabbix/zabbix_server.conf.d/*.conf |  |
|JavaGateway | zabbix_server_javagateway | |  |
|JavaGatewayPort | zabbix_server_javagatewayport | 10052 |  |
|ListenBacklog | zabbix_server_listenbacklog | |  |
|ListenIP | zabbix_server_listenip | 0.0.0.0 |  |
|ListenPort | zabbix_server_listenport | 10051 |  |
|LoadModule | zabbix_server_loadmodule | |  |
|LoadModulePath | zabbix_server_loadmodulepath | ${libdir}/modules |  |
|LogFile | zabbix_server_logfile | /var/log/zabbix/zabbix_server.log |  |
|LogFileSize | zabbix_server_logfilesize | 10 |  |
|LogSlowQueries | zabbix_server_logslowqueries | 0 |  |
|LogType | zabbix_server_logtype | file |  |
|MaxConcurrentChecksPerPoller | zabbix_server_maxconcurrentchecksperpoller | 1000 | Version 7.0 or later |
|MaxHousekeeperDelete | zabbix_server_maxhousekeeperdelete | 5000 |  |
|NodeAddress | zabbix_server_nodeaddress | |  |
|PidFile | zabbix_server_pidfile | /var/run/zabbix/zabbix_server.pid |  |
|ProblemHousekeepingFrequency | zabbix_server_problemhousekeepingfrequency |  |  |
|ProxyConfigFrequency | zabbix_server_proxyconfigfrequency | 10 |  |
|ProxyDataFrequency | zabbix_server_proxydatafrequency | 1 |  |
|ServiceManagerSyncFrequency | zabbix_server_servicemanagersyncfrequency | 60 |  |
|SNMPTrapperFile | zabbix_server_snmptrapperfile | /tmp/zabbix_traps.tmp |  |
|SocketDir | zabbix_server_socketdir | /var/run/zabbix |  |
|SourceIP | zabbix_server_sourceip | |  |
|SSHKeyLocation | zabbix_server_sshkeylocation | |  |
|SSLCALocation | zabbix_server_sslcalocation | |  |
|SSLCertLocation | zabbix_server_sslcertlocation | ${datadir}/zabbix/ssl/certs |  |
|SSLKeyLocation | zabbix_server_sslkeylocation | ${datadir}/zabbix/ssl/keys |  |
|StartAgentPollers | zabbix_server_startagentpollers | 1 | Version 7.0 or later |
|StartAlerters | zabbix_server_startalerters | 3 |  |
|StartBrowserPollers | zabbix_server_startbrowserpollers | 1 | Version 7.0 or later |
|StartConnectors | zabbix_server_connectors | 0 | Version 6.4 or later |
|StartDBSyncers | zabbix_server_startdbsyncers | 4 |  |
|StartDiscoverers | zabbix_server_startdiscoverers | 1 |  |
|StartEscalators | zabbix_server_startescalators | 1 |  |
|StartHistoryPollers | zabbix_server_starthistorypollers | 5 |  |
|StartHTTPAgentPollers | zabbix_server_starthttpagentpollers | 1 | Version 7.0 or later |
|StartHTTPPollers | zabbix_server_starthttppollers | 1 |  |
|StartIPMIPollers | zabbix_server_startipmipollers | 0 |  |
|StartJavaPollers | zabbix_server_startjavapollers | 0 |  |
|StartLLDProcessors | zabbix_server_startlldprocessors | 2 |  |
|StartODBCPollers | zabbix_server_startodbcpollers | 1 |  |
|StartPingers | zabbix_server_startpingers | 1 |  |
|StartPollers | zabbix_server_startpollers | 5 |  |
|StartPollersUnreachable | zabbix_server_startpollersunreachable | 1 |  |
|StartPreprocessors | zabbix_server_startpreprocessors | 3 |  |
|StartProxyPollers | zabbix_server_startproxypollers | 1 |  |
|StartReportWriters | zabbix_server_startreportwriters | 0 |  |
|StartSNMPPollers | zabbix_server_startsnmppollers | 1  | Version 7.0 or later |
|StartSNMPTrapper | zabbix_server_startsnmptrapper | 0 |  |
|StartTimers | zabbix_server_starttimers | 1 |  |
|StartTrappers | zabbix_server_starttrappers | 5 |  |
|StartVMwareCollectors | zabbix_server_startvmwarecollectors | 0 |  |
|StasAllowedIP | zabbix_server_statsallowedip | |  |
|Timeout | zabbix_server_timeout | 3 |  |
|TLSCAFile | zabbix_server_tlscafile | |  |
|TLSCertFile | zabbix_server_tlscertfile | |  |
|TLSCipherAll | zabbix_server_tlscipherall | |  |
|TLSCipherAll13 | zabbix_server_tlscipherall13 | |  |
|TLSCipherCert | zabbix_server_tlsciphercert | |  |
|TLSCipherCert13 | zabbix_server_tlsciphercert13 | |  |
|TLSCipherPSK | zabbix_server_tlscipherpsk | |  |
|TLSCipherPSK13 | zabbix_server_tlscipherpsk13 | |  |
|TLSCRLFile | zabbix_server_tlscrlfile | |  |
|TLSKeyFile | zabbix_server_tlskeyfile | |  |
|TmpDir | zabbix_server_tmpdir | /tmp |  |
|TrapperTimeout | zabbix_server_trappertimeout | 300 |  |
|TrendCacheSize | zabbix_server_trendcachesize | 4M |  |
|TrendFunctionCacheSize | zabbix_server_trendfunctioncachesize | 4M |  |
|UnavailableDelay | zabbix_server_unavailabledelay | 60 |  |
|UnreachableDelay | zabbix_server_unreachabledelay | 15 |  |
|UnreachablePeriod | zabbix_server_unreachableperiod | 45 |  |
|User | zabbix_server_user | zabbix |  |
|ValueCacheSize | zabbix_server_valuecachesize | 8M |  |
|Vault | zabbix_server_vault | | Version 6.2 or later  |
|VaultDBPath | zabbix_server_vaultdbpath | |  |
|VaultPrefix | zabbix_server_vaultdbprefix | | Version 7.0 or later |
|VaultTLSCertFile | zabbix_server_vaulttlscertfile | | Version 6.4 or later |
|VaultTLSKeyFile | zabbix_server_vaulttlskeyfile | | Version 6.4 or later |
|VaultToken | zabbix_server_vaulttoken | |  |
|VaultURL | zabbix_server_vaulturl | https://127.0.0.1:8200 |  |
|VMwareCacheSize | zabbix_server_vmwarecachesize | |  |
|VMwareFrequency | zabbix_server_vmwarefrequency | 60 |  |
|VMwarePerfFrequency | zabbix_server_vmwareperffrequency | 60 |  |
|VMwareTimeout | zabbix_server_vmwaretimeout | 10 |  |
|WebDriverURL | zabbix_server_webdriverurl | | Version 7.0 or later |
|WebServiceURL | zabbix_server_webserviceurl | |  |

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
