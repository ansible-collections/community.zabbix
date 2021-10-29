# community.zabbix.zabbix_agent role

![Zabbix Agent](https://github.com/ansible-collections/community.zabbix/workflows/community.zabbix.zabbix_agent/badge.svg)

**Table of Contents**

- [Requirements](#requirements)
  * [Operating systems](#operating-systems)
    + [Windows](#windows)
  * [Local system access](#local-system-access)
  * [Zabbix Versions](#zabbix-versions)
- [Getting started](#getting-started)
  * [Minimal Configuration](#minimal-configuration)
  * [Issues](#issues)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
    + [Overall Zabbix](#overall-zabbix)
    + [SElinux](#selinux)
    + [Zabbix Agent](#zabbix-agent)
    + [Zabbix Agent vs Zabbix Agent 2 configuration](#zabbix-agent-vs-zabbix-agent-2-configuration)
  * [TLS Specific configuration](#tls-specific-configuration)
  * [Zabbix API variables](#zabbix-api-variables)
  * [Windows Variables](#windows-variables)
  * [macOS Variables](#macos-variables)
  * [Docker Variables](#docker-variables)
  * [FirewallD/Iptables](#firewalld-iptables)
  * [IPMI variables](#ipmi-variables)
  * [proxy](#proxy)
- [Dependencies](#dependencies)
- [Example Playbook](#example-playbook)
  * [zabbix_agent2_plugins](#zabbix-agent2-plugins)
  * [agent_interfaces](#agent-interfaces)
  * [Other interfaces](#other-interfaces)
  * [Vars in role configuration](#vars-in-role-configuration)
  * [Combination of group_vars and playbook](#combination-of-group-vars-and-playbook)
  * [Example for TLS PSK encrypted agent communication](#example-for-tls-psk-encrypted-agent-communication)
- [Molecule](#molecule)
- [Deploying Userparameters](#deploying-userparameters)
- [License](#license)
- [Author Information](#author-information)

# Requirements
## Operating systems
This role will work on the following operating systems:

 * Red Hat
 * Fedora
 * Debian
 * Ubuntu
 * opensuse
 * Windows (Best effort)
 * macOS

So, you'll need one of those operating systems.. :-)
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

## Ansible 2.10 and higher

With the release of Ansible 2.10, modules have been moved into collections.  With the exception of ansible.builtin modules, this means additonal collections must be installed in order to use modules such as seboolean (now ansible.posix.seboolean).  The following collections are now required: `ansible.posix`and `community.general`.  Installing the collections:

```sh
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install community.general
```

### Docker

When you are a Docker user and using Ansible 2.10 or newer, then there is a dependency on the collection named `community.docker`. This collection is needed as the `docker_` modules are now part of collections and not standard in Ansible anymmore. Installing the collection:

```sh
ansible-galaxy collection install community.docker
```

### Windows

When you are a Windows user and using Ansible 2.10 or newer, then there are dependencies on collections named `ansible.windows` and `community.windows`. These collections are needed as the `win_` modules are now part of collections and not standard in Ansible anymmore. Installing the collections:

```sh
ansible-galaxy collection install ansible.windows
ansible-galaxy collection install community.windows
```

For more information, see: https://github.com/ansible-collections/community.zabbix/issues/236

## Local system access

To successfully complete the install the role requires `python-netaddr` on the controller to be able to manage IP addresses. This requires that the library is available on your local machine (or that `pip` is installed to be able to run). This will likely mean that running the role will require `sudo` access to your local machine and therefore you may need the `-K` flag to be able to enter your local machine password if you are not running under root.

## Zabbix Versions

See the following list of supported Operating systems with the Zabbix releases:

| Zabbix              | 5.2 | 5.0 | 4.4 | 4.0 (LTS) | 3.0 (LTS) |
|---------------------|-----|-----|-----|-----------|-----------|
| Red Hat Fam 8       |  V  |  V  | V   |           |           |
| Red Hat Fam 7       |  V  |  V  | V   | V         | V         |
| Red Hat Fam 6       |  V  |  V  |     |           | V         |
| Red Hat Fam 5       |  V  |  V  |     |           | V         |
| Fedora              |     |     | V   | V         |           |
| Ubuntu 20.04 focal  |  V  |  V  |     | V         |           |
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

# Getting started

## Minimal Configuration

In order to get the Zabbix Agent running, you'll have to define the following properties before executing the role:

* `zabbix_agent_version`
* `zabbix_agent(2)_server`
* `zabbix_agent(2)_serveractive` (When using active checks)

The `zabbix_agent_version` is optional. The latest available major.minor version of Zabbix will be installed on the host(s). If you want to use an older version, please specify this in the major.minor format. Example: `zabbix_agent_version: 4.0`, `zabbix_agent_version: 3.4` or `zabbix_agent_version: 2.2`.

The `zabbix_agent(2)_server` (and `zabbix_agent(2)_serveractive`) should contain the ip or fqdn of the host running the Zabbix Server.

## Issues

Due to issue discussed on [#291](https://github.com/dj-wasabi/ansible-zabbix-agent/issues/291), the Ansible Version 2.9.{0,1,2} isn't working correctly on Windows related targets.

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_agent_version`: This is the version of zabbix. Default: 5.2. Can be overridden to 5.0, 4.4, 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2. Previously the variable `zabbix_version` was used directly but it could cause [some inconvenience](https://github.com/dj-wasabi/ansible-zabbix-agent/pull/303). That variable is maintained by retrocompativility.
* `zabbix_repo`: Default: `zabbix`
  * `epel`: install agent from EPEL repo
  * `zabbix`: (default) install agent from Zabbix repo
  * `other`: install agent from pre-existing or other repo
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)
* `zabbix_repo_yum_disabled`: A string with repository names that should be disabled when installing Zabbix component specific packages. Is only used when `zabbix_repo_yum_enabled` contains 1 or more repositories. Default `*`.
* `zabbix_repo_yum_enabled`: A list with repository names that should be enabled when installing Zabbix component specific packages.

### SElinux

* `zabbix_selinux`: Default: `False`. Enables an SELinux policy so that the server will run.

### Zabbix Agent

* `zabbix_agent_ip`: The IP address of the host. When not provided, it will be determined via the `ansible_default_ipv4` fact.
* `zabbix_agent2`: Default: `False`. When you want to install the `Zabbix Agent2` instead of the "old" `Zabbix Agent`.
* `zabbix_agent_listeninterface`: Interface zabbix-agent listens on. Leave blank for all.
* `zabbix_agent_package_remove`: If `zabbix_agent2: True` and you want to remove the old installation. Default: `False`.
* `zabbix_agent_package`: The name of the zabbix-agent package. Default: `zabbix-agent`. In case for EPEL, it is automatically renamed.
* `zabbix_sender_package`: The name of the zabbix-sender package. Default: `zabbix-sender`. In case for EPEL, it is automatically renamed.
* `zabbix_get_package`: The name of the zabbix-get package. Default: `zabbix-get`. In case for EPEL, it is automatically renamed.
* `zabbix_agent_package_state`: If Zabbix-agent needs to be `present` or `latest`.
* `zabbix_agent_interfaces`: A list that configured the interfaces you can use when configuring via API.
* `zabbix_agent_install_agent_only`: Only install the Zabbix Agent and not the `zabbix-sender` and `zabbix-get` packages. Default: `False`
* `zabbix_agent_userparameters`: Default: `[]]`. List of userparameter names and scripts (if any). Detailed description is given in the [Deploying Userparameters](#deploying-userparameters) section.
    * `name`: Userparameter name (should be the same with userparameter template file name)
    * `scripts_dir`: Directory name of the custom scripts needed for userparameters
* `zabbix_agent_userparameters_templates_src`: indicates the relative path (from `templates/`) where userparameter templates are searched
* `zabbix_agent_userparameters_scripts_src`: indicates the relative path (from `files/`) where userparameter scripts are searched
* `zabbix_agent_runas_user`: Drop privileges to a specific, existing user on the system. Only has effect if run as 'root' and AllowRoot is disabled.
* `zabbix_agent_become_on_localhost`: Default: `True`. Set to `False` if you don't need to elevate privileges on localhost to install packages locally with pip.
* `zabbix_install_pip_packages`: Default: `True`. Set to `False` if you don't want to install the required pip packages. Useful when you control your environment completely.
* `zabbix_agent_apt_priority`: Add a weight (`Pin-Priority`) for the APT repository.
* `zabbix_agent_conf_mode`: Default: `0644`. The "mode" for the Zabbix configuration file.
* `zabbix_agent_dont_detect_ip`: Default `false`. When set to `true`, it won't detect available ip addresses on the host and no need for the Python module `netaddr` to be installed.

### Zabbix Agent vs Zabbix Agent 2 configuration

The following provides an overview of all the properties that can be set in the Zabbix Agent configuration file. When `(2)` is used in the name of the property, like `zabbix_agent(2)_pidfile`, it will show that you can configure `zabbix_agent_pidfile` for the Zabbix Agent configuration file and `zabbix_agent2_pidfile` for the Zabbix Agent 2 configuration file.

Otherwise it just for the Zabbix Agent or for the Zabbix Agent 2.

* `zabbix_agent(2)_server`: The ip address for the zabbix-server or zabbix-proxy.
* `zabbix_agent(2)_serveractive`: The ip address for the zabbix-server or zabbix-proxy for active checks.
* `zabbix_agent(2)_allow_key`: list of AllowKey configurations.
* `zabbix_agent(2)_deny_key`: list of DenyKey configurations.
* `zabbix_agent(2)_pidfile`: name of pid file.
* `zabbix_agent(2)_logfile`: name of log file.
* `zabbix_agent(2)_logfilesize`: maximum size of log file in mb.
* `zabbix_agent(2)_logtype`: Specifies where log messages are written to
* `zabbix_agent(2)_debuglevel`: specifies debug level
* `zabbix_agent(2)_sourceip`: source ip address for outgoing connections.
* `zabbix_agent_enableremotecommands`: whether remote commands from zabbix server are allowed.
* `zabbix_agent_logremotecommands`: enable logging of executed shell commands as warnings.
* `zabbix_agent(2)_listenport`: agent will listen on this port for connections from the server.
* `zabbix_agent2_statusport`: Agent will listen on this port for HTTP status requests.
* `zabbix_agent(2)_listenip`: list of comma delimited ip addresses that the agent should listen on.
* `zabbix_agent_startagents`: number of pre-forked instances of zabbix_agentd that process passive checks.
* `zabbix_agent(2)_hostname`: unique, case sensitive hostname.
* `zabbix_agent(2)_hostnameitem`: item used for generating hostname if it is undefined.
* `zabbix_agent(2)_hostmetadata`: optional parameter that defines host metadata.
* `zabbix_agent(2)_hostmetadataitem`: optional parameter that defines an item used for getting the metadata.
* `zabbix_agent(2)_refreshactivechecks`: how often list of active checks is refreshed, in seconds.
* `zabbix_agent(2)_buffersend`: do not keep data longer than n seconds in buffer.
* `zabbix_agent(2)_buffersize`: maximum number of values in a memory buffer. the agent will send all collected data to zabbix server or proxy if the buffer is full.
* `zabbix_agent2_enablepersistentbuffer`: 0 - disabled, in-memory buffer is used (default); 1 - use persistent buffer
* `zabbix_agent2_persistentbufferperiod`: Zabbix Agent2 will keep data for this time period in case of no connectivity with Zabbix server or proxy. Older data will be lost. Log data will be preserved.
* `zabbix_agent2_persistentbufferfile`: Zabbix Agent2 will keep SQLite database in this file	* n is valid if `EnablePersistentBuffer=1`
* `zabbix_agent_maxlinespersecond`: maximum number of new lines the agent will send per second to zabbix server or proxy processing 'log' and 'logrt' active checks.
* `zabbix_agent_allowroot`: allow the agent to run as 'root'. if disabled and the agent is started by 'root', the agent will try to switch to user 'zabbix' instead. has no effect if started under a regular user.
* `zabbix_agent(2)_zabbix_alias`: sets an alias for parameter. it can be useful to substitute long and complex parameter name with a smaller and simpler one.
* `zabbix_agent(2)_timeout`: spend no more than timeout seconds on processing
* `zabbix_agent(2)_include`: you may include individual files or all files in a directory in the configuration file.
* `zabbix_agent(2)_include_mode`: The mode for the directory mentioned above.
* `zabbix_agent(2)_unsafeuserparameters`: allow all characters to be passed in arguments to user-defined parameters.
* `zabbix_agent_loadmodulepath`: Full path to location of agent modules.
* `zabbix_agent_loadmodule`: Module to load at agent startup. Modules are used to extend functionality of the agent.
* `zabbix_agent2_controlsocket`: The control socket, used to send runtime commands with '-R' option.
* `zabbix_agent_allowroot`:  Allow the agent to run as 'root'. 0 - do not allow, 1 - allow
* `zabbix_agent2_plugins`: A list containing plugin configuration.

## TLS Specific configuration

These variables are specific for Zabbix 3.0 and higher. When `(2)` is used in the name of the property, like `zabbix_agent(2)_tlsconnect`, it will show that you can configure `zabbix_agent_tlsconnect` for the Zabbix Agent configuration file and `zabbix_agent2_tlsconnect` for the Zabbix Agent 2 configuration file.

* `zabbix_agent(2)_tlsconnect`: How the agent should connect to server or proxy. Used for active checks.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_agent(2)_tlsaccept`: What incoming connections to accept.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_agent(2)_tlscafile`: Full pathname of a file containing the top-level CA(s) certificates for peer certificate verification.
* `zabbix_agent(2)_tlscrlfile`: Full pathname of a file containing revoked certificates.
* `zabbix_agent(2)_tlsservercertissuer`: Allowed server certificate issuer.
* `zabbix_agent(2)_tlsservercertsubject`: Allowed server certificate subject.
* `zabbix_agent(2)_tlscertfile`: Full pathname of a file containing the agent certificate or certificate chain.
* `zabbix_agent(2)_tlskeyfile`: Full pathname of a file containing the agent private key.
* `zabbix_agent(2)_tlspskidentity`: Unique, case sensitive string used to identify the pre-shared key.
* `zabbix_agent(2)_tlspskidentity_file`: Full pathname of a file containing the pre-shared key identity.
* `zabbix_agent(2)_tlspskfile`: Full pathname of a file containing the pre-shared key.
* `zabbix_agent(2)_tlspsk_secret`: The pre-shared secret key that should be placed in the file configured with `agent_tlspskfile`.
* `zabbix_agent(2)_tlspsk_auto`: Enables auto generation and storing of individual pre-shared keys and identities on clients.

## Zabbix API variables

These variables need to be overridden when you want to make use of the zabbix-api for automatically creating and or updating hosts.

Host encryption configuration will be set to match agent configuration.

When `zabbix_api_create_hostgroup` or `zabbix_api_create_hosts` is set to `True`, it will install on the host executing the Ansible playbook the `zabbix-api` python module.

* `zabbix_api_server_url`: The url on which the Zabbix webpage is available. Example: http://zabbix.example.com
* `zabbix_api_http_user`: The http user to access zabbix url with Basic Auth
* `zabbix_api_http_password`: The http password to access zabbix url with Basic Auth
* `zabbix_api_create_hosts`: Default: `False`. When you want to enable the Zabbix API to create/delete the host. This has to be set to `True` if you want to make use of `zabbix_agent_host_state`.
* `zabbix_api_create_hostgroup`: When you want to enable the Zabbix API to create/delete the hostgroups. This has to be set to `True` if you want to make use of `zabbix_agent_hostgroups_state`.Default: `False`
* `zabbix_api_login_user`: Username of user which has API access.
* `zabbix_api_login_pass`: Password for the user which has API access.
* `zabbix_agent_hostgroups_state`: present (Default) if the hostgroup needs to be created or absent if you want to delete it. This only works when `zabbix_api_create_hostgroup` is set to `True`.
* `zabbix_host_status`: enabled (Default) when host in monitored, disabled when host is disabled for monitoring.
* `zabbix_agent_host_state`: present (Default) if the host needs to be created or absent is you want to delete it. This only works when `zabbix_api_create_hosts` is set to `True`.
* `zabbix_agent_host_update`: yes (Default) if the host should be updated if already present. This only works when `zabbix_api_create_hosts` is set to `True`.
* `zabbix_useuip`: 1 if connection to zabbix-agent is made via ip, 0 for fqdn.
* `zabbix_host_groups`: A list of hostgroups which this host belongs to.
* `zabbix_agent_link_templates`: A list of templates which needs to be link to this host. The templates should exist.
* `zabbix_agent_macros`: A list with macro_key and macro_value for creating hostmacro's.
* `zabbix_agent_inventory_mode`: Configure Zabbix inventory mode. Needed for building inventory data, manually when configuring a host or automatically by using some automatic population options. This has to be set to `automatic` if you want to make automatically building inventory data.
* `zabbix_agent_visible_hostname` : Configure Zabbix visible name inside Zabbix web UI for the node.
* `zabbix_api_validate_certs` : yes (Default) if we need to validate tls certificates of the API. Use `no` in case self-signed certificates are used
* `zabbix_agent_description`: Description of the host in Zabbix.
* `zabbix_agent_inventory_zabbix`: Adds Facts for a zabbix inventory

## Windows Variables

**NOTE**

_Supporting Windows is a best effort (I don't have the possibility to either test/verify changes on the various amount of available Windows instances). PRs specific to Windows will almost immediately be merged, unless someone is able to provide a Windows test mechanism via Travis for Pull Requests._
When `(2)` is used in the name of the property, like `zabbix_agent(2)_win_logfile`, it will show that you can configure `zabbix_agent_win_logfile` for the Zabbix Agent configuration file and `zabbix_agent2_win_logfile` for the Zabbix Agent 2 configuration file.

Otherwise it just for the Zabbix Agent or for the Zabbix Agent 2.

* `zabbix(2)_win_package`: file name pattern (zip only). This will be used to generate the `zabbix(2)_win_download_link` variable.
* `zabbix_version_long`: The long (major.minor.patch) version of the Zabbix Agent. This will be used to generate the `zabbix(2)_win_package` and `zabbix(2)_win_download_link` variables.
* `zabbix(2)_win_download_link`: The download url to the `win.zip` file.
* `zabbix_win_install_dir`: The directory where Zabbix needs to be installed.
* `zabbix_agent(2)_win_logfile`: The full path to the logfile for the Zabbix Agent.
* `zabbix_agent_win_include`: The directory in which the Zabbix Agent specific configuration files are stored.
* `zabbix_agent_win_svc_recovery`: Enable Zabbix Agent service auto-recovery settings.
* `zabbix_win_firewall_management`: Enable Windows firewall management (add service and port to allow rules). Default: `True`

## macOS Variables

* `zabbix_version_long`: The long (major.minor.patch) version of the Zabbix Agent. This will be used to generate the `zabbix_mac_download_link` link.
* `zabbix_mac_download_link`: The download url to the `pkg` file.

## Docker Variables

When you don't want to install the Zabbix Agent on the host, but would like to run it in a container then these properties are useful. When `zabbix_agent_docker` is set to `True`, then a
Docker image will be downloaded and a Container will be started. No other installations will be done on the host, with the exception of the PSK file and the "Zabbix Include Directory".

The following directories are mounted in the Container:

```
  - /etc/zabbix/zabbix_agentd.d:/etc/zabbix/zabbix_agentd.d
  - /:/hostfs:ro
  - /etc:/hostfs/etc:ro
  - /proc:/hostfs/proc:ro
  - /sys:/hostfs/sys:ro
  - /var/run:/var/run
```

Keep in mind that using the Zabbix Agent in a Container requires changes to the Zabbix Template for Linux as `/proc`, `/sys` and `/etc` are mounted in a directory `/hostfs`.

* `zabbix_agent_docker`: Default: `False`. When set to `True`, it will install a Docker container on the target host instead of installation on the target.
* `zabbix_agent_docker_state`: Default: `started`
* `zabbix_agent_docker_name`: The name of the Container. Default: `zabbix-agent`
* `zabbix_agent_docker_image`: The name of the Docker image. Default: `zabbix/zabbix-agent`
* `zabbix_agent_docker_image_tag`: The tag of the Docker image.
* `zabbix_agent_docker_user_gid`: The group id of the zabbix user in the Container.
* `zabbix_agent_docker_user_uid`: The user id of the zabbix user in the Container.
* `zabbix_agent_docker_network_mode`: The name of the (Docker) network that should be used for the Container. Default `host`.
* `zabbix_agent_docker_restart_policy`: Default: `unless-stopped`. The restart policy of the Container.
* `zabbix_agent_docker_privileged`: When set to `True`, the container is running in privileged mode.
* `zabbix_agent_docker_ports`: A list with `<PORT>:<PORT>` values to open ports to the container.
* `zabbix_agent_docker_security_opts`: A list with available security options.
* `zabbix_agent_docker_volumes`: A list with all directories that needs to be available in the Container.
* `zabbix_agent_docker_env`: A dict with all environment variables that needs to be set for the Container.

## FirewallD/Iptables

* `zabbix_agent_firewall_enable`: If IPtables needs to be updated by opening an TCP port for port configured in `zabbix_agent_listenport`.
* `zabbix_agent_firewall_source`: When provided, IPtables will be configuring to only allow traffic from this IP address/range.
* `zabbix_agent_firewalld_enable`: If firewalld needs to be updated by opening an TCP port for port configured in `zabbix_agent_listenport` and `zabbix_agent_jmx_listenport` if defined.
* `zabbix_agent_firewalld_source`: When provided, firewalld will be configuring to only allow traffic for IP configured in `zabbix_agent_server`.
* `zabbix_agent_firewalld_zone`: When provided, the firewalld rule will be attached to this zone (only if zabbix_agent_firewalld_enable is set to true). The default behavior is to use the default zone define by the remote host firewalld configuration.
* `zabbix_agent_firewall_action`: Default: `insert`. When to `insert` the rule or to `append` to IPTables.
* `zabbix_agent_firewall_chain`: Default `INPUT`. Which `chain` to add the rule to IPTables.


## IPMI variables

* `zabbix_agent_ipmi_authtype`: IPMI authentication algorithm. Possible values are 1 (callback), 2 (user), 3 (operator), 4 (admin), 5 (OEM), with 2 being the API default.
* `zabbix_agent_ipmi_password`: IPMI password.
* `zabbix_agent_ipmi_privilege`: IPMI privilege level. Possible values are 1 (callback), 2 (user), 3 (operator), 4 (admin), 5 (OEM), with 2 being the API default.
* `zabbix_agent_ipmi_username`: IPMI username.

## proxy

When the target host does not have access to the internet, but you do have a proxy available then the following properties needs to be set to download the packages via the proxy:

* `zabbix_http_proxy`
* `zabbix_https_proxy`

# Dependencies

There are no dependencies on other roles.

# Example Playbook

## zabbix_agent2_plugins

Specifically for the Zabbix Agent 2, a list of extra plugins can be configured. The following provides an overview of configuring the `SystemRun` plugin by setting the `LogRemoteCommands` to `0`:

```yaml
zabbix_agent2_plugins:
  - name: SystemRun
    options:
      - parameter: LogRemoteCommands
        value: 0
```

In the `zabbix_agent2.conf` an entry will be created with the following content:

```
Plugins.SystemRun.LogRemoteCommands=0
```

## agent_interfaces

This will configure the Zabbix Agent interface on the host.
```yaml
zabbix_agent_interfaces:
  - type: 1
    main: 1
    useip: "{{ zabbix_useuip }}"
    ip: "{{ zabbix_agent_ip }}"
    dns: "{{ ansible_fqdn }}"
    port: "{{ zabbix_agent_listenport }}"
```

## Other interfaces

You can also configure the `zabbix_agent_interfaces` to add/configure snmp, jmx and ipmi interfaces.

You'll have to use one of the following type numbers when configuring it:

| Type Interface  |  Nr   |
|-----------------|-------|
| Zabbix Agent  | 1  |
| snmp | 2  |
| ipmi | 3  |
| jmx | 4  |

Configuring a snmp interface will look like this:

```
zabbix_agent_interfaces:
  - type: 2
    main: 1
    useip: "{{ zabbix_useuip }}"
    ip: "{{ agent_ip }}"
    dns: "{{ ansible_fqdn }}"
    port: "{{ agent_listenport }}"
```

## Vars in role configuration
Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
    - hosts: all
      roles:
         - role: community.zabbix.zabbix_agent
           zabbix_agent_server: 192.168.33.30
           zabbix_agent_serveractive: 192.168.33.30
           zabbix_api_server_url: http://zabbix.example.com
           zabbix_api_use: true # use zabbix_api_create_hosts and/or zabbix_api_create_hostgroup from 0.8.0
           zabbix_api_login_user: Admin
           zabbix_api_login_pass: zabbix
           zabbix_agent_host_state: present
           zabbix_host_groups:
             - Linux Servers
           zabbix_agent_link_templates:
             - Template OS Linux
             - Apache APP Template
           zabbix_agent_macros:
             - macro_key: apache_type
               macro_value: reverse_proxy
```

## Combination of group_vars and playbook
You can also use the group_vars or the host_vars files for setting the variables needed for this role. File you should change: `group_vars/all` or `host_vars/<zabbix_server>` (Where <zabbix_server> is the hostname of the machine running Zabbix Server)

```yaml
    zabbix_agent_server: 192.168.33.30
    zabbix_agent_serveractive: 192.168.33.30
    zabbix_api_server_url: http://zabbix.example.com
    zabbix_api_use: true # use zabbix_api_create_hosts and/or zabbix_api_create_hostgroup from 0.8.0
    zabbix_api_login_user: Admin
    zabbix_api_login_pass: zabbix
    zabbix_agent_host_state: present
    zabbix_host_groups:
      - Linux Servers
    zabbix_agent_link_templates:
      - Template OS Linux
      - Apache APP Template
    zabbix_agent_macros:
      - macro_key: apache_type
        macro_value: reverse_proxy
```

and in the playbook only specifying:

```yaml
    - hosts: all
      roles:
         - role: community.zabbix.zabbix_agent
```

## Example for TLS PSK encrypted agent communication

Variables e.g. in the playbook or in `host_vars/myhost`:

```yaml
    zabbix_agent_tlsaccept: psk
    zabbix_agent_tlsconnect: psk
    zabbix_agent_tlspskidentity: "myhost PSK"
    zabbix_agent_tlspsk_secret: b7e3d380b9d400676d47198ecf3592ccd4795a59668aa2ade29f0003abbbd40d
    zabbix_agent_tlspskfile: /etc/zabbix/zabbix_agent_pskfile.psk
```

# Molecule

This role is configured to be tested with Molecule. You can find on this page some more information regarding Molecule:

* http://werner-dijkerman.nl/2016/07/10/testing-ansible-roles-with-molecule-testinfra-and-docker/
* http://werner-dijkerman.nl/2016/07/27/extending-ansible-role-testing-with-molecule-by-adding-group_vars-dependencies-and-using-travis-ci/
* http://werner-dijkerman.nl/2016/07/31/testing-ansible-roles-in-a-cluster-setup-with-docker-and-molecule/

With each Pull Request, Molecule will be executed via travis.ci. Pull Requests will only be merged once these tests run successfully.

# Deploying Userparameters

The following steps are required to install custom userparameters and/or scripts:

* Put the desired userparameter file in the `templates/userparameters` directory and name it as `<userparameter_name>.j2`. For example: `templates/userparameters/mysql.j2`. You can change the default directory to a custom one modifying `zabbix_agent_userparameters_templates_src` variable.
* Put the scripts directory (if any) in the `files/scripts` directory. For example: `files/scripts/mysql`. You can change the default directory to a custom one modifying `zabbix_agent_userparameters_scripts_src` variable.
* Add `zabbix_agent_userparameters` variable to the playbook as a list of dictionaries and define userparameter name and scripts directory name (if there are no scripts just no not specify the `scripts_dir` variable).

Example:

```yaml
- hosts: mysql_servers
  tasks:
    - include_role:
        name: community.zabbix.zabbix_agent
      vars:
        zabbix_agent_server: zabbix.mydomain.com
        zabbix_agent_userparameters:
          - name: mysql
            scripts_dir: mysql
          - name: galera

```

Example of the "templates/userparameters/mysql.j2" file:

```
UserParameter=mysql.ping_to,mysqladmin -uroot ping | grep -c alive
```

# License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

# Author Information

Please send suggestion or pull requests to make this role better. Also let us know if you encounter any issues installing or using this role.

Github: https://github.com/ansible-collections/community.zabbix
