# community.zabbix.zabbix_javagateway role

![Zabbix Javagateway](https://github.com/ansible-collections/community.zabbix/workflows/community.zabbix.zabbix_javagateway/badge.svg)

**Table of Contents**

- [Overview](#overview)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Role Variables](#role-variables)
  * [Main variables](#main-variables)
    + [Overall Zabbix](#overall-zabbix)
    + [Java Gatewaty](#java-gatewaty)
    + [proxy](#proxy)
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
Please send Pull Requests or suggestions when you want to use this role for other Operating systems.

## Zabbix Versions

See the following list of supported Operating systems with the Zabbix releases.

| Zabbix              | 6.2 | 6.0 (LTS) | 5.0 (LTS) | 
|---------------------|-----|-----------|-----------|
| Red Hat Fam 8       |  V  |  V        |  V        |
| Red Hat Fam 7       |  V  |  V        |  V        |
| Ubuntu 22.04 jammy  |  V  |  V        |  V        |
| Ubuntu 20.04 focal  |  V  |  V        |  V        |
| Ubuntu 18.04 bionic |  V  |  V        |  V        |
| Debian 11 bullseye  |  V  |  V        |  V        |
| Debian 10 buster    |  V  |  V        |  V        |

# Role Variables

## Main variables

The following is an overview of all available configuration default for this role.

### Overall Zabbix

* `zabbix_javagateway_version`: This is the version of zabbix. Default: The highest supported version for the operating system. Can be overridden to 6.2, 6.0, or 5.0.
* `zabbix_repo`: Default: `zabbix`
  * `epel`: install agent from EPEL repo
  * `zabbix`: (default) install agent from Zabbix repo
  * `other`: install agent from pre-existing or other repo
* `zabbix_repo_yum`: A list with Yum repository configuration.
* `zabbix_repo_yum_schema`: Default: `https`. Option to change the web schema for the yum repository(http/https)
* `zabbix_repo_yum_disabled`: A string with repository names that should be disabled when installing Zabbix component specific packages. Is only used when `zabbix_repo_yum_enabled` contains 1 or more repositories. Default `*`.
* `zabbix_repo_yum_enabled`: A list with repository names that should be enabled when installing Zabbix component specific packages.
* `zabbix_javagateway_package_state`: Default: `present`. Can be overridden to `latest` to update packages when needed.
* `zabbix_javagateway_conf_mode`: Default: `0644`. The "mode" for the Zabbix configuration file.

### Java Gatewaty

* `zabbix_javagateway_pidfile`: Default: `/run/zabbix/zabbix_java_gateway.pid`. The location for the pid file.
* `zabbix_javagateway_listenip`: Default: `0.0.0.0`. The IP address to listen on.
* `zabbix_javagateway_listenport`: Default: `10052`. The port on which Java Gateway is listening on.
* `zabbix_javagateway_startpollers`: Default: `5`. The amount of pollers to start.

### proxy

When the target host does not have access to the internet, but you do have a proxy available then the following properties needs to be set to download the packages via the proxy:

* `zabbix_http_proxy`
* `zabbix_https_proxy`

# Dependencies

The java gateway can be installed on either the zabbix-server or the zabbix-proxy machine. So one of these should be installed. You'll need to provide an parameter in your playbook for using the javagateway.

When using the zabbix-server:
```yaml
  roles:
    - role: community.zabbix.zabbix_server
      zabbix_server_javagateway: 192.168.1.2
```

or when using the zabbix-proxy:
```yaml
  roles:
    - role: community.zabbix.zabbix_proxy
      zabbix_proxy_server: 192.168.1.1
      zabbix_proxy_javagateway: 192.168.1.2
```

# Example Playbook

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
    - hosts: zabbix-server
      sudo: yes
      roles:
        - role: community.zabbix.zabbix_server
          zabbix_server_javagateway: 192.168.1.2
        - role: community.zabbix.zabbix_javagateway
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
