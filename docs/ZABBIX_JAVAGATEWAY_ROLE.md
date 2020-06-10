dj-wasabi.zabbix-javagateway
=========

This role is migrated to: https://github.com/ansible-collections/community.zabbix/
In this repository, a read only version is/will be available for those who can not make use of collections (yet). Changes/updates will only be applied to the collection and not in this repository.

Requirements
------------

This role will work on:

* Red Hat
* Debian
* Ubuntu

So, you'll need one of those operating systems.. :-)

Role Variables
--------------

There are some variables in de default/main.yml which can (Or needs to) be changed/overriden:

* `zabbix_version`: This is the version of zabbix. Default it is 2.4, but can be overriden to 2.2 or 2.0.

* `zabbix_repo`: True / False. When you already have an repository with the zabbix components, you can set it to False.

Dependencies
------------

The java gateway can be installed on either the zabbix-server or the zabbix-proxy machine. So one of these should be installed. You'll need to provide an parameter in your playbook for using the javagateway.

When using the zabbix-server:
```
  roles:
     - { role: dj-wasabi.zabbix-server, zabbix_server_javagateway: 192.168.1.2}
```

or when using the zabbix-proxy:
```
  roles:
     - { role: dj-wasabi.zabbix-proxy, zabbix_server_host: 192.168.1.1, zabbix_proxy_javagateway: 192.168.1.2}
```

The above is assumed you'll using the 'dj-wasabi' zabbix roles. Don't know how to do this with other zabbix-server (or zabbix-proxy) roles from other members.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: zabbix-server
      sudo: yes
      roles:
         - { role: dj-wasabi.zabbix-server, zabbix_server_javagateway: 192.168.1.2}
         - { role: dj-wasabi.zabbix-javagateway }

License
-------

GPLv3

Author Information
------------------

This is my first attempt to create an ansible role, so please send suggestion or pull requests to make this role better. 

Github: https://github.com/dj-wasabi/ansible-zabbix-proxy

mail: ikben [ at ] werner-dijkerman . nl
