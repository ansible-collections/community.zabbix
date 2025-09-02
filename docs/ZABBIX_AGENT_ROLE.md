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
 * Debian
 * Ubuntu
 * Windows (Best effort)
 * macOS (Best effort)

## Ansible 2.10 and higher

With the release of Ansible 2.10, modules have been moved into collections.  With the exception of ansible.builtin modules, this means additonal collections must be installed in order to use modules such as seboolean (now ansible.posix.seboolean).  The following collections are now required: `ansible.posix`and `community.general`.  Installing the collections:

```sh
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install community.general
```
If you are wanting to create host_groups and hosts in Zabbix via API as a part of this role execution then you need to install `ansible.netcommon` collection too:

```
ansible-galaxy collection install ansible.netcommon
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

| Zabbix              | 7.4 | 7.2 | 7.0 | 6.0 |
|---------------------|-----|-----|-----|-----|
| Red Hat Fam 9       |  V  |  V  |  V  |  V  |
| Red Hat Fam 8       |  V  |  V  |  V  |  V  |
| Ubuntu 24.04 noble  |  V  |  V  |  V  |  V  |
| Ubuntu 22.04 jammy  |  V  |  V  |  V  |  V  |
| Debian 12 bookworm  |  V  |  V  |  V  |  V  |
| Debian 11 bullseye  |  V  |  V  |  V  |  V  |
| Suse Fam 15         |  V  |  V  |  V  |  V  |

You can bypass this matrix by setting `enable_version_check: false`

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_agent_version`: This is the version of zabbix. Default: The highest supported version for the operating system. Can be overridden to 6.4 or 6.0
* `zabbix_agent_version_minor`: When you want to specify a minor version to be installed. Is also used for `zabbix_sender` and `zabbix_get`. RedHat only. Default set to: `*` (latest available)
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository (http/https)
* `zabbix_agent_disable_repo`: A list of repos to disable during install.  Default `epel`.
* `zabbix_repo_deb_url`: The URL to the Zabbix repository.  Default `http://repo.zabbix.com/zabbix/{{ zabbix_agent_version }}/{{ ansible_distribution.lower() }}`
* `zabbix_repo_deb_component`: The repository component for Debian installs. Default `main`.
* `zabbix_repo_deb_gpg_key_url`: The URL to download the Zabbix GPG key from. Default http://repo.zabbix.com/zabbix-official-repo.key.
* `zabbix_repo_deb_include_deb_src`: True, if deb-src should be included in the zabbix.sources entry. Default `true`.
* `zabbix_manage_repo`: Have the collection install and configure the Zabbix repo. Default `true`.

### SElinux

Selinux changes will be installed based on the status of selinux running on the target system.

* `selinux_allow_zabbix_run_sudo`: Default: `False`.  Enable Zabbix root access on system.

### Zabbix Agent

* `zabbix_agent2`: Default: `False`. When you want to install the `Zabbix Agent2` instead of the "old" `Zabbix Agent`.
* `zabbix_agent_chassis`: Default: `false`. When set to `true`, it will give Zabbix Agent access to the Linux DMI table allowing system.hw.chassis info to populate.
* `zabbix_agent_conf_mode`: Default: `0644`. The "mode" for the Zabbix configuration file.
* `zabbix_agent_detect_ip`: Default `true`. When set to `false`, it won't detect available ip addresses on the host and no need for the Python module `netaddr` to be installed.
* `zabbix_agent_get_package`: The name of the zabbix-get package. Default: `zabbix-get`.
* `zabbix_agent_include_mode`: The mode for the directory mentioned above.
* `zabbix_agent_install_agent_only`: Only install the Zabbix Agent and not the `zabbix-sender` and `zabbix-get` packages. Default: `False`
* `zabbix_agent_package_remove`: If `zabbix_agent2: True` and you want to remove the old installation. Default: `False`.
* `zabbix_agent_package_state`: If Zabbix-agent needs to be `present` (default) or `latest`.
* `zabbix_agent_package`: The name of the zabbix-agent package. Default: `zabbix-agent` if `zabbix_agent2` is false and `zabbix-agent2` if `true`.
* `zabbix_agent_sender_package`: The name of the zabbix-sender package. Default: `zabbix-sender`.
* `zabbix_agent_userparameters`: Default: `[]`. List of userparameter names and scripts (if any). Detailed description is given in the [Deploying Userparameters](#deploying-userparameters) section.
  * `name`: Userparameter name (should be the same with userparameter template file name)
  * `scripts_dir`: Directory name of the custom scripts needed for userparameters
* `zabbix_agent_userparameters_scripts_src`: indicates the relative path (from `files/`) where userparameter scripts are searched
* `zabbix_agent_userparameters_templates_src`: indicates the relative path (from `templates/`) where userparameter templates are searched

## TLS Specific configuration
* `zabbix_agent_tlspsk_auto`: Enables auto generation and storing of individual pre-shared keys and identities on clients. Is false by default. If set to true and if `zabbix_agent_tlspskfile` and `zabbix_agent_tlspsk_secret` are undefined, it generates the files `/etc/zabbix/tls_psk_auto.identity` and `/etc/zabbix/tls_psk_auto.secret`, which are populated by values automatically (identity is set to hostname, underscore and 4 random alphanumeric digits; secret is 64 random alphanumeric digits) in such a way that the values are generated once and are never overwritten.

* `zabbix_agent_tlsconnect`: How the agent should connect to server or proxy. Used for active checks.
    Possible values:
    * unencrypted
    * psk
    * cert
* `zabbix_agent_tlsaccept`: What incoming connections to accept.
    Possible values:
    * unencrypted
    * psk
    * cert

* `zabbix_agent_tlscafile`: Full pathname of a file containing the top-level CA(s) certificates for peer certificate verification.
* `zabbix_agent_tlscertfile`: Full pathname of a file containing the agent certificate or certificate chain.
* `zabbix_agent_tlscrlfile`: Full pathname of a file containing revoked certificates.
* `zabbix_agent_tlskeyfile`: Full pathname of a file containing the agent private key.
* `zabbix_agent_tlspskfile`: Full pathname of a file containing the pre-shared key.
* `zabbix_agent_tlspskidentity`: Unique, case sensitive string used to identify the pre-shared key.
* `zabbix_agent_tlspskidentity_file`: Full pathname of a file containing the pre-shared key identity.
* `zabbix_agent_tlspsk_secret`: The pre-shared secret key for the agent.
* `zabbix_agent_tlsservercertissuer`: Allowed server certificate issuer.
* `zabbix_agent_tlsservercertsubject`: Allowed server certificate subject.
* `zabbix_agent_tls_subject`:  The subject of the TLS certificate.
* `zabbix_agent_visible_hostname` : Configure Zabbix visible name inside Zabbix web UI for the node.

The results are stored in the Ansible variables `zabbix_agent_tlspskidentity` and `zabbix_agent_tlspsk_secret`, so that they may be used later in the code, for example with [zabbix_host](https://docs.ansible.com/ansible/latest/collections/community/zabbix/zabbix_host_module.html) to configure the Zabbix server or with `debug: msg:` to display them to the user.

## Zabbix API variables

These variables need to be overridden when you want to make use of the Zabbix API for automatically creating and or updating hosts.

Host encryption configuration will be set to match agent configuration.

* `zabbix_agent_description`: Description of the host in Zabbix.
* `zabbix_agent_host_state`: present (Default) if the host needs to be created or absent if you want to delete it. This only works when `zabbix_api_create_hosts` is set to `True`.
* `zabbix_agent_host_update`: yes (Default) if the host should be updated if already present. This only works when `zabbix_api_create_hosts` is set to `True`.
* `zabbix_agent_interfaces`: A list of interfaces and their configurations you can use when configuring via API.
* `zabbix_agent_inventory_mode`: Configure Zabbix inventory mode. Needed for building inventory data, manually when configuring a host or automatically by using some automatic population options. This has to be set to `automatic` if you want to make automatically building inventory data.  Default `disabled`
* `zabbix_agent_inventory_zabbix`: Adds Facts for a zabbix inventory.  Default `{}`
* `zabbix_agent_ip`: The IP address of the host. When not provided, it will be determined via the `ansible_default_ipv4` fact.
* `zabbix_agent_link_templates`: A list of templates which needs to be link to this host. The templates should exist.  Default:  "Templated Linux by Zabbix agent"
* `zabbix_agent_macros`: A list with macro_key and macro_value for creating hostmacro's.
* `zabbix_agent_monitored_by`: How the agent is monitored.  Choices are 'zabbix_server', 'proxy', and 'proxy_group'.  (Zabbix 7.0 or greater)
* `zabbix_agent_proxy`:  The name of the Zabbix proxy (if used).  Default `null`
* `zabbix_agent_proxy_group`:  The name of the Zabbix proxy group (if used) (Zabbix 7.0 or later).
* `zabbix_agent_tags`: A list with tag and (optionally) value for creating host tags.
* `zabbix_api_create_hostgroup`: When you want to enable the Zabbix API to create/delete the hostgroups. Default: `False`
* `zabbix_api_create_hosts`: Default: `False`. When you want to enable the Zabbix API to create/delete the host. This has to be set to `True` if you want to make use of `zabbix_agent_host_state`.
* `zabbix_api_http_password`: The http password to access zabbix url with Basic Auth (if your Zabbix is behind a proxy with HTTP Basic Auth).
* `zabbix_api_http_user`: The http user to access zabbix url with Basic Auth (if your Zabbix is behind a proxy with HTTP Basic Auth).
* `zabbix_api_login_pass`: Password for the user which has API access.
* `zabbix_api_login_user`: Username of user which has API access.
* `zabbix_api_server_host`: The IP or hostname/FQDN of Zabbix server. Example: zabbix.example.com
* `zabbix_api_server_port`: 80 if `zabbix_api_use_ssl` is `false` and 443 if `true` (Default) TCP port to use to connect to Zabbix server. Example: 8080
* `zabbix_api_use_ssl`: Is SSL required to connect to the Zabbix API server?  Default: `false`
* `zabbix_api_validate_certs`: `True` if we need to validate tls certificates of the API. Use `False` in case self-signed certificates are used.  Default: `False`
* `zabbix_host_groups`: A list of hostgroups which this host belongs to.  Default:  "Linux Servers"
* `zabbix_host_status`: enabled (Default) when host in monitored, disabled when host is disabled for monitoring.
* `zabbix_useuip`: 1 if connection to zabbix-agent is made via ip, 0 for fqdn.

## Windows Variables

**NOTE**

Supporting Windows is a best effort (We don't have the possibility to either test/verify changes on the various amount of available Windows instances). PRs specific to Windows will almost immediately be merged, unless someone is able to provide a Windows test mechanism via Travis for Pull Requests.
When `` is used in the name of the property, like `zabbix_agent_win_logfile`, it will show that you can configure `zabbix_agent_win_logfile` for the Zabbix Agent configuration file and `zabbix_agent2_win_logfile` for the Zabbix Agent 2 configuration file.

Otherwise it just for the Zabbix Agent or for the Zabbix Agent 2.

* `zabbix_agent_win_include`: The directory in which the Zabbix Agent specific configuration files are stored.
* `zabbix_agent_win_logfile`: The full path to the logfile for the Zabbix Agent.
* `zabbix_agent_version_long`: The long (major.minor.patch) version of the Zabbix Agent. This will be used to generate the `zabbix_win_package` and `zabbix_win_download_link` variables. This takes precedence over `zabbix_agent_version`.
* `zabbix_win_download_link`: The download url to the `win.zip` file.
* `zabbix_win_firewall_management`: Enable Windows firewall management (add service and port to allow rules). Default: `True`
* `zabbix_agent_win_install_dir`: The directory where Zabbix needs to be installed. Default: `C:\Program Files\Zabbix Agent 2` when variable `zabbix_agent2` is true, `C:\Program Files\Zabbix Agent` when `zabbix_agent2` is false.
* `zabbix_agent_win_install_dir_conf`: The directory where Zabbix configuration file needs to be installed. Default: `zabbix_agent_win_install_dir`
* `zabbix_win_package`: file name pattern (zip only). This will be used to generate the `zabbix_win_download_link` variable.

### Tweaking the windows service

There might be times where the service is unpredictable, and rather than
investigating or dealing with it, you can just have it restart upon failure.
Here are some suggested values for tweaking the service.

* `zabbix_agent_service_start_mode:` `auto`, zabbix comes by default with `delayed`.
* ```yaml
  zabbix_agent_service_failure_actions:
      - type: restart
        delay_ms: 10000
      - type: restart
        delay_ms: 20000
      - type: restart
        delay_ms: 40000
  ```
* `zabbix_agent_service_failure_reset_period_sec:` `86400` is probably a reasonable time


## macOS Variables

**NOTE**

_Supporting macOS is a best effort (We don't have the possibility to either test/verify changes on the various amount of available macOS instances). PRs specific to macOS will almost immediately be merged, unless someone is able to provide a macOS test mechanism via Travis for Pull Requests._

* `zabbix_mac_download_link`: The download url to the `pkg` file.
* `zabbix_mac_download_url`: The download url.  Default `https://cdn.zabbix.com/zabbix/binaries/stable`
* `zabbix_mac_package`: The name of the mac install package.  Default `zabbix_agent-{{ zabbix_agent_version_long }}-macos-amd64-openssl.pkg`
* `zabbix_agent_version_long`: The long (major.minor.patch) version of the Zabbix Agent. This will be used to generate the `zabbix_mac_download_link` link.

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
* `zabbix_agent_docker_env`: A dict with all environment variables that needs to be set for the Container.
* `zabbix_agent_docker_image`: The name of the Docker image. Default: `zabbix/zabbix-agent`
* `zabbix_agent_docker_image_tag`: The tag of the Docker image.
* `zabbix_agent_docker_name`: The name of the Container. Default: `zabbix-agent`
* `zabbix_agent_docker_network_mode`: The name of the (Docker) network that should be used for the Container. Default `host`.
* `zabbix_agent_docker_restart_policy`: Default: `unless-stopped`. The restart policy of the Container.
* `zabbix_agent_docker_ports`: A list with `<PORT>:<PORT>` values to open ports to the container.  Default `10050`
* `zabbix_agent_docker_privileged`: When set to `True`, the container is running in privileged mode.  Default `false`
* `zabbix_agent_docker_security_opts`: A list with available security options.
* `zabbix_agent_docker_state`: Default: `started`
* `zabbix_agent_docker_user_gid`: The group id of the zabbix user in the Container.
* `zabbix_agent_docker_user_uid`: The user id of the zabbix user in the Container.
* `zabbix_agent_docker_volumes`: A list with all directories that needs to be available in the Container.

## IPMI variables

* `zabbix_agent_ipmi_authtype`: IPMI authentication algorithm. Possible values are -1 (default), 0 (none), 1 (MD2), 2 (MD5), 4 (straight), 5 (OEM), 6 (RMCP+), with -1 being the API default.
* `zabbix_agent_ipmi_password`: IPMI password.
* `zabbix_agent_ipmi_privilege`: IPMI privilege level. Possible values are 1 (callback), 2 (user), 3 (operator), 4 (admin), 5 (OEM), with 2 being the API default.
* `zabbix_agent_ipmi_username`: IPMI username.

## Configuration Variables
The following table lists all variables that are exposed to modify the configuration of the zabbix_agent.conf file.  Specific details of each variable can be found in the Zabbix documentation.

**NOTE**:  Only variables with a default value appear in the defaults file, all others must be added.

| Zabbix Name | Variable Name | Default Value | Notes |
|-----------|------------------|--------|--------|
| Alias | zabbix_agent_aliases |  | Can be a string or list |
| AllowKey | zabbix_agent_allowkeys |  |  |
| AllowRoot | zabbix_agent_allowroot | `False` | `True`/`False` Agent Linux Systems Only |
| BufferSend | zabbix_agent_buffersend | 5 |  |
| BufferSize | zabbix_agent_buffersize | 100 |  |
| ControlSocket | zabbix_agent_controlsocket | /tmp/agent.sock | Agent 2 Only |
| DebugLevel | zabbix_agent_debuglevel | 3 |  |
| DenyKey | zabbix_agent_denykeys |  | Can be a string or a list |
| EnablePersistentBuffer | zabbix_agent_enablepersistentbuffer | `False` | `True`/`False` Agent 2 Only |
| EnableRemoteCommands | zabbix_agent_enableremotecommands | `False` | `True`/`False` Agent Only |
| ForceActiveChecksOnStart | zabbix_agent_forceactivechecksonstart | `False` | `True`/`False` Agent 2 Only |
| HeartbeatFrequency | zabbix_agent_heartbeatfrequency | 60 | Version >= 6.4 |
| HostInterface | zabbix_agent_hostinterface |  |  |
| HostInterfaceItem | zabbix_agent_hostinterfaceitem |  |  |
| HostMetadata | zabbix_agent_hostmetadata |  |  |
| HostMetadataItem | zabbix_agent_hostmetadataitem |  |  |
| Hostname | zabbix_agent_hostname |  | `{{ inventory_hostname }}` |
| HostnameItem | zabbix_agent_hostnameitem |  |  |
| Include | zabbix_agent_include_dir | /etc/zabbix/`{{ agent version specific }}`.d/*.conf |  |
| ListenBacklog | zabbix_agent_listenbacklog |  | Agent Only |
| ListenIP | zabbix_agent_listenip | 0.0.0.0  |  |
| ListenPort | zabbix_agent_listenport | 10050 |  |
| LoadModule | zabbix_agent_loadmodule |  | Agent On Linux Only |
| LoadModulePath | zabbix_agent_loadmodulepath |  | Agent On Linux Only |
| LogFile | zabbix_agent_logfile | /var/log/zabbix/`{{ agent version specific }}`.log |  |
| LogFileSize | zabbix_agent_logfilesize | 100 |  |
| LogRemoteCommands | zabbix_agent_logremotecommands | `False` | `True`/`False` Agent Only |
| LogType | zabbix_agent_logtype | file |  |
| MaxLinesPerSecond | zabbix_agent_maxlinespersecond | 20 | Agent Only |
| PerfCounter | zabbix_agent_perfcounter |  | Agent Only |
| PerfCounterEn | zabbix_agent_perfcounteren |  | Agent Only |
| PersistentBufferFile | zabbix_agent_persistentbufferfile |  | Agent 2 Only |
| PersistentBufferPeriod | zabbix_agent_persistentbufferperiod | 1h | Agent 2 Only |
| PidFile | zabbix_agent_pidfile | /var/run/zabbix/`{{ agent version specific }}`.pid | Linux Systems Only |
| Plugin | zabbix_agent_plugins |  |  |
| PluginSocket | zabbix_agent_pluginsocket | /tmp/agent.plugin.sock | Agent 2 Only  |
| PluginTimeout | zabbix_agent_plugintimeout | 3 | Agent 2 Only |
| RefreshActiveChecks | zabbix_agent_refreshactivechecks |  |  |
| Server | zabbix_agent_server |  |  |
| ServerActive | zabbix_agent_serveractive |  |  |
| SourceIP | zabbix_agent_sourceip |  |  |
| StartAgents | zabbix_agent_startagents | 3 | Agent Only |
| StatusPort | zabbix_agent_statusport | 9999 | Agent 2 Only |
| Timeout | zabbix_agent_timeout | 3 |  |
| TLSAccept | zabbix_agent_tlsconnect | unencrypted | Is overridden with `zabbix_agent_tlspsk_auto` == True |
| TLSCAFile | zabbix_agent_tlscafile | /etc/zabbix/tls_psk_auto.secret |  |
| TLSCertFile | zabbix_agent_tlscertfile |  |  |
| TLSCipherAll | zabbix_agent_tlscipherall |  | Agent on Linux Only |
| TLSCipherAll13 | zabbix_agent_tlscipherall13 |  | Agent on Linux Only |
| TLSCipherCert | zabbix_agent_tlsciphercert |  | Agent on Linux Only |
| TLSCipherCert13 | zabbix_agent_tlsciphercert13 |  | Agent on Linux Only |
| TLSCipherPSK | zabbix_agent_tlscipherpsk |  | Agent on Linux Only |
| TLSCipherPSK13 | zabbix_agent_tlscipherpsk13 |  | Agent on Linux Only |
| TLSConnect | zabbix_agent_tlsconnect | unencrypted | Is overridden with `zabbix_agent_tlspsk_auto` == True |
| TLSCRLFile | zabbix_agent_tlscrlfile |  |  |
| TLSKeyFile | zabbix_agent_tlskeyfile |  |  |
| TLSPSKFile | zabbix_agent_tlspskfile |  |  |
| TLSPSKIdentity | zabbix_agent_tlspskidentity |  |  |
| TLSServerCertIssuer | zabbix_agent_tlsservercertissuer |  |  |
| TLSServerCertSubject | zabbix_agent_tlsservercertsubject |  |  |
| UnsafeUserParameters | zabbix_agent_unsafeuserparameters | `False` | `True`/`False`  |
| User | zabbix_agent_runas_user | zabbix | Agent on Linux Only |
| UserParameter | zabbix_agent_userparamater | | |
| UserParameterDir | zabbix_agent_userparamaterdir |  |  |


## Proxy

When the target host does not have access to the internet, but you do have a proxy available then the following properties needs to be set to download the packages via the proxy:

* `zabbix_http_proxy`
* `zabbix_https_proxy`

## Tags

The majority of tasks within this role are tagged as follows:

* `install`:  Tasks associated with the installation of software.
* `dependencies`:  Installation tasks related to dependencies that aren't part of the core zabbix installation.
* `database`: Tasks associated with the installation or configuration of the database.
* `api`:  Tasks associated with using the Zabbix API to connect and modify the Zabbix server.
* `config`:  Tasks associated with the configuration of Zabbix or a supporting service.
* `service`:  Tasks associated with managing a service.

# Dependencies

There are no dependencies on other roles.

# Example Playbook

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
          vars:
            zabbix_agent_server: 192.168.33.30
            zabbix_agent_serveractive: 192.168.33.30
            zabbix_api_server_host: zabbix.example.com
            zabbix_api_login_user: Admin
            zabbix_api_login_pass: zabbix
            zabbix_api_create_hostgroup: true
            zabbix_api_create_hosts: true
            zabbix_agent_host_state: present
            zabbix_host_groups:
              - Linux Servers
            zabbix_agent_link_templates:
              - Template OS Linux
              - Apache APP Template
            zabbix_agent_macros:
              - macro_key: apache_type
                macro_value: reverse_proxy
                macro_type: text
            zabbix_agent_tags:
              - tag: environment
                value: production
```

## Combination of group_vars and playbook
You can also use the group_vars or the host_vars files for setting the variables needed for this role. File you should change: `group_vars/all` or `host_vars/<zabbix_server>` (Where <zabbix_server> is the hostname of the machine running Zabbix Server)

```yaml
    zabbix_agent_server: 192.168.33.30
    zabbix_agent_serveractive: 192.168.33.30
    zabbix_api_server_host: zabbix.example.com
    zabbix_api_login_user: Admin
    zabbix_api_login_pass: zabbix
    zabbix_api_create_hostgroup: true
    zabbix_api_create_hosts: true
    zabbix_agent_host_state: present
    zabbix_host_groups:
      - Linux Servers
    zabbix_agent_link_templates:
      - Template OS Linux
      - Apache APP Template
    zabbix_agent_macros:
      - macro_key: apache_type
        macro_value: reverse_proxy
    zabbix_agent_tags:
      - tag: environment
        value: production
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
