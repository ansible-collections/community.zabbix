# Zabbix Web Service Role

This role installs and configures the Zabbix Web Service, a component used for generating scheduled reports in Zabbix. It also handles the necessary prerequisites, such as installing Google Chrome, GPG keys and setting up the required directory structures for report generation.

## Table of Contents

* [Official Documentation](#official-documentation)
* [Requirements](#requirements)
  * [Target OS](#target-os)
  * [Ansible](#ansible)
* [Role Variables](#role-variables)
  * [Main Variables](#main-variables)
  * [Configuration Variables](#configuration-variables)
  * [API Variables (Frontend URL Setup)](#api-variables-frontend-url-setup)
* [Integration with Zabbix Server](#integration-with-zabbix-server)
* [Dependencies](#dependencies)
* [Example Playbook](#example-playbook)
* [License](#license)
* [Author Information](#author-information)

## Official Documentation

For more detailed information about the Zabbix Web Service and its usage, please refer to the official Zabbix documentation:
* [Zabbix Web Service Concept](https://www.zabbix.com/documentation/current/en/manual/concepts/web_service): Detailed explanation of what the Zabbix web service is, its architecture, and how it works.
* [Scheduled Reports Configuration](https://www.zabbix.com/documentation/current/en/manual/config/reports): A comprehensive guide on how to configure, schedule, and manage reports directly within the Zabbix frontend.
* [Setting up Zabbix Web Service](https://www.zabbix.com/documentation/current/en/manual/appendix/install/web_service): Instructions and requirements for setting up the web service, including Google Chrome and font dependencies.
* [Zabbix Web Service Configuration Parameters](https://www.zabbix.com/documentation/current/en/manual/appendix/config/zabbix_web_service): Details all available configuration parameters for the `zabbix_web_service.conf` file.

## Requirements

### Target OS
This role has been **tested** and verified on:
* Enterprise Linux (EL) 8, 9, 10 family (RHEL, AlmaLinux, Rocky Linux, Oracle Linux)

The following operating systems are supported by the role's logic, but are currently **untested** (contributions and test reports are welcome):
* CentOS 8, 9 (Stream)
* Debian 11, 12
* Ubuntu 20.04, 22.04, 24.04
* SUSE Linux Enterprise Server (SLES)

### Ansible
* Ansible 2.10+

## Role Variables

### Main Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `zabbix_web_service_version_check` | `true` | Enables validation to ensure the specified Zabbix version is supported on the target OS. |
| `zabbix_web_service_version` | `7.4` (depends on OS) | The Zabbix version to install. |
| `zabbix_manage_repo` | `true` | When set to `true`, the `community.zabbix.zabbix_repo` role will be included to install the Zabbix repository. |
| `zabbix_os_user` | `zabbix` | The OS user that runs the Zabbix Web Service and owns its directories. |
| `zabbix_service_enabled` | `true` | Enables the `zabbix-web-service` systemd service to start on boot. |
| `zabbix_service_state` | `started` | The state of the `zabbix-web-service` service. |
| `zabbix_web_service_manage_service` | `true` | When set to `true`, the role will manage the service state. |
| `selinux_allow_zabbix_can_network` | `true` | When set to `true` and SELinux is enabled, sets the `zabbix_can_network` boolean. |
| `zabbix_web_service_packages` | `{{ _zabbix_web_service_packages }}` | List of packages to install for the web service. |
| `zabbix_web_service_package_state` | `present` | State of the installed packages (e.g., `present`, `latest`). |

### Configuration Variables

These variables map directly to the parameters in `/etc/zabbix/zabbix_web_service.conf`.

| Variable | Default | Description |
|----------|---------|-------------|
| `zabbix_web_service_logtype` | `file` | Specifies where log messages are written to (`system`, `file`, `console`). |
| `zabbix_web_service_logfile` | `/var/log/zabbix/zabbix_web_service.log` | Log file name for LogType `file`. |
| `zabbix_web_service_logfilesize` | `0` | Maximum size of log file in MB. `0` disables automatic log rotation. |
| `zabbix_web_service_debuglevel` | *None* | Specifies debug level (0-5). |
| `zabbix_web_service_allowedip` | *None* | List of comma-delimited IP addresses allowed to connect to the service. **(Mandatory for service to work)** |
| `zabbix_web_service_listenport` | *None* | Service will listen on this port for connections from the server (Default: 10053). |
| `zabbix_web_service_timeout` | *None* | Spend no more than Timeout seconds on formatting dashboard as PDF. |
| `zabbix_web_service_tlsaccept` | *None* | What incoming connections to accept (`unencrypted`, `cert`). |
| `zabbix_web_service_tlscafile` | *None* | Full pathname of a file containing the top-level CA(s) certificates. |
| `zabbix_web_service_tlscertfile` | *None* | Full pathname of a file containing the service certificate or certificate chain. |
| `zabbix_web_service_tlskeyfile` | *None* | Full pathname of a file containing the service private key. |

### API Variables (Frontend URL Setup)

To automatically configure the `Frontend URL` parameter in Zabbix global settings (required for the web service to fetch dashboards), the following variables can be used:

| Variable | Default | Description |
|----------|---------|-------------|
| `zabbix_api_frontend_url` | `false` | Set to `true` to enable setting the Frontend URL via Zabbix API. |
| `zabbix_frontend_url` | *None* | The actual URL of the Zabbix frontend (e.g., `https://zabbix.example.com/zabbix`). |
| `zabbix_api_server_host` | *None* | The hostname or IP of the Zabbix API server. |
| `zabbix_api_server_port` | *None* | The port of the Zabbix API. |
| `zabbix_api_use_ssl` | *None* | Use SSL/HTTPS for API connection. |
| `zabbix_api_validate_certs` | *None* | Validate SSL certificates. |
| `zabbix_api_login_user` | *None* | Zabbix API username. |
| `zabbix_api_login_pass` | *None* | Zabbix API password. |

## Integration with Zabbix Server

For the Zabbix Web Service to function properly and generate scheduled reports, the Zabbix Server **must** be configured to communicate with it.

If the Zabbix Server is managed using the `community.zabbix.zabbix_server` role, please refer to the [ZABBIX_SERVER_ROLE.md](https://github.com/ansible-collections/community.zabbix/blob/main/docs/ZABBIX_SERVER_ROLE.md) documentation. At least the following two variables must be set in the Zabbix Server configuration:

* `zabbix_server_webserviceurl`: The URL to the Zabbix Web Service (e.g., `http://localhost:10053/report`).
* `zabbix_server_startreportwriters`: The number of pre-forked report writer instances (must be set to `1` or higher).

## Dependencies

* `community.zabbix.zabbix_repo` (Included automatically if `zabbix_manage_repo` is `true`)

## Example Playbook

```yaml
- name: Install and configure Zabbix Web Service
  hosts: zabbix_web_service
  become: true
  vars:
    zabbix_web_service_allowedip: "127.0.0.1,192.168.1.0/24"
    
    # Optional: Automatically set the Frontend URL in Zabbix Server settings
    zabbix_api_frontend_url: true
    zabbix_frontend_url: "https://zabbix.example.com/zabbix"
    zabbix_api_server_host: "127.0.0.1"
    zabbix_api_login_user: "Admin"
    zabbix_api_login_pass: "zabbix"

  roles:
    - role: community.zabbix.zabbix_web_service
```

## License

GNU General Public License v3.0 or later.

## Author Information

This role was created and is maintained by the `community.zabbix` collection contributors.