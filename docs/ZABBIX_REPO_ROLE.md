# community.zabbix.zabbix_server role

![Zabbix Manage Repo](https://github.com/ansible-collections/community.zabbix/workflows/community.zabbix.zabbix_manage_repo/badge.svg)

**Table of Contents**

- [Overview](#overview)
- [Requirements](#requirements)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Installation](#installation)
- [Role Variables](#role-variables)
- [Example Playbook](#example-playbook)
- [License](#license)
- [Author Information](#author-information)

# Overview

This is a Ansible role for installing the yum or apt repository for Zabbix.  This will not install the Zabbix Server or any other component of Zabbix itself.

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

# Installation

Installing this role is very simple: `ansible-galaxy install community.zabbix.zabbix_manage_repo`

Please be aware that this role only installs the repo itself.  It is generally used by the various other Zabbix roles (i.e. server or web) and not normally used by itself.

# Role Variables

* `zabbix_repo_apt_priority`: Option:  An integer value for the priority of the repo.
* `zabbix_repo_deb_component`: The repository component for Debian installs. Default `main`.
* `zabbix_repo_deb_gpg_key_url`: The URL to download the Zabbix GPG key from. Default `http://repo.zabbix.com/zabbix-official-repo.key`.
* `zabbix_repo_deb_include_deb_src`: True, if deb-src should be included in the zabbix.sources entry. Default `true`.
* `zabbix_repo_deb_url`: The URL to the Zabbix repository.  Default `http://repo.zabbix.com/zabbix/{{ zabbix_repo_version }}/{{ ansible_distribution.lower() }}`
* `zabbix_http_proxy`: Optional: HTTP proxy information.
* `zabbix_https_proxy`: Optional: HTTPS proxy information.
* `zabbix_repo_gpg_key`: Optional: The keyring path.  Default: `{{ debian_keyring_path }}zabbix-repo.asc`
* `zabbix_repo_keyring_path`: Optional: The path to store keyrings in Debian distributions.  Default: `/etc/apt/keyrings/`
* `zabbix_repo_package`: The name of the package to lock the apt priority to.
* `zabbix_repo_version`: Optional. The main version (i.e. major.minor) of Zabbix that will be installed on the host(s).  Default: 6.4
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_gpg_check`: Optional.  Yum should check GPG keys.  Default: 0
* `zabbix_repo_yum_gpg_key_url`: The URL to download the Zabbix GPG key from. Default: `http://repo.zabbix.com/RPM-GPG-KEY-ZABBIX-08EFA7DD`
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)
* `zabbix_repo_zypper`: A list with zypper repository configuration.
* `zabbix_repo_zypper_auto_import_keys`: Optional. Zypper should import GPG keys automatically. Default: true
* `zabbix_repo_zypper_disable_gpg_check`: Optional. Zypper shouldn't check GPG keys.  Default: false
* `zabbix_repo_zypper_schema`: Default: `https`. Option to change the web schema for the zypper repository(http/https)

# Example Playbook

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
  - hosts: zabbix-server
    roles:
      - role: community.zabbix.zabbix_repo
```

# License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

# Author Information

Please send suggestion or pull requests to make this role better. Also let us know if you encounter any issues installing or using this role.

Github: https://github.com/ansible-collections/community.zabbix
