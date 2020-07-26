# community.zabbix.zabbix_javagateway role

Table of Contents

- [Overview](#overview)
  * [Operating systems](#operating-systems)
  * [Zabbix Versions](#zabbix-versions)
- [Role Variables](#role-variables)
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

There are some variables in de default/main.yml which can (Or needs to) be changed/overriden:

* `zabbix_version`: This is the version of zabbix. Default: 5.0. Can be overridden to 4.4, 4.0, 3.4, 3.2, 3.0, 2.4, or 2.2.

* `zabbix_repo`: True / False. When you already have an repository with the zabbix components, you can set it to False.

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
      zabbix_server_host: 192.168.1.1
      zabbix_proxy_javagateway: 192.168.1.2
```

The above is assumed you'll using the 'dj-wasabi' zabbix roles. Don't know how to do this with other zabbix-server (or zabbix-proxy) roles from other members.

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
