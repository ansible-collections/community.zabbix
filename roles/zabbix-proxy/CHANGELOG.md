# ansible-zabbix-server Release

Below an overview of all changes in the releases.

Version (Release date)

FINAL and LAST release for this role in this repository. This role will be transferred to: https://github.com/ansible-collections/community.zabbix/

1.7.0   (2020-05-23)

  * Added zabbix_proxy_enableremotecommands variable #57 (By pull request: AleksejsC (Thanks!))
  * Added variable for specifying version Zabbix proxy #58 (By pull request: dmitriy-kharchenko (Thanks!))
  * implement a condition on the SocketDir parameter #59 (By pull request: v (Thanks!))
  * HostnameItem can be set and Hostname is now optional #61 (By pull request: sebedh (Thanks!))
  * Add Proxy creation on through API #62 (By pull request: SimBou (Thanks!))
  * Use the correct naming as suggested in dj-wasabi/ansible-zabbix-agent #301 #63
  * fix SELinux issue : preprocessing.sock permission denied #64 (By pull request: SimBou (Thanks!))
  * ability to manage zabbix-proxy service #65 (By pull request: Vinclame (Thanks!))

1.6.0   (2019-12-01)

  * Added missing "become: yes" statements in tasks/main.yml Redhat.yml #53 (By pull request: elcomtik (Thanks!))
  * SocketDir missing in zabbix_proxy.conf #54 (By pull request: Vinclame (Thanks!))
  * selinux blocks preprocessing workers #55 (By pull request: Vinclame (Thanks!))
  * Update to 4.4 #56 (By pull request: macaddict89 (Thanks!))

1.5.0   (2019-09-27)

  * Fix and refactor SELinux support #47 (By pull request: angystardust (Thanks!))
  * Update Debian.yml #49 (By pull request: giedriusramas (Thanks!))
  * Calling yum and apt using a loop is deprecated #50 (By pull request: Aversiste (Thanks!))
  * fixing issue 48 #51 (By pull request: bbcnt (Thanks!))
  * change default version #52 (By pull request: fabtho (Thanks!))

1.4.0   (2019-04-15)

  * Added property zabbix_proxy_package_state #45
  * Fixed some Ansible Lint issues #46
  * bugfix: "zabbix_proxy_tlspskfile" was not created with content "zabbi… #39 (By pull request: menzelit (Thanks!))
  * Updated to Zabbix 4.2 #41
  * enable upgrade of an existing installation #42 (By pull request: zab35 (Thanks!))

1.3.0   (2019-01-25)

  * Added retries for packages installation #38
  * Adding zabbix_proxy_install_database_client variable #37 (By pull request: rnsc (Thanks!))

1.2.0   (2018-10-19)

  * Make it work with Zabbix 4.0

1.1.0   (2018-06-23)

  * typo in zabbix_proxy_cachesize variable #32 (By pull request: q1x (Thanks!))
  * Updated minimal Ansible version to 2.4 #28
  * Add support for Debian 9 #28
  * Fix for: Mysql database error #21
  * Various fixes #26 (By pull request: hatifnatt (Thanks!))
  * fix DBPort parameter in config template #23 (By pull request: maxim0r (Thanks!))
  * Using correct compare #22
  * set selinux policy to permissive for zabbix_t, needed for CentOS and others #18 (By pull request: andrzejwp (Thanks!))
  * Add TLS connection configuration #17 (By pull request: mgornikov (Thanks!))
  * Add support for sqlite3 DB #16 (By pull request: mgornikov (Thanks!))

1.0.0   (2017-09-10)

  * Changed from ini to yml style
  * Replace shell tasks with modules.
  * Installing default 3.4.
  * Prefixed all properties that started with `proxy_` with the value `zabbix_`.
  * Added upgrade part in documentation.

0.5.0   (2017-07-17)

  * Renaming docker-py to docker #10
  * [!] fix misspelling with property ListenIP #9 (By pull request: lebe-dev (Thanks!))
  * Add Amazon Linux support #7 (By pull request: kostyrev (Thanks!))
  * Add HistoryIndexCacheSize for zabbix 3.2 #6 (By pull request: kostyrev (Thanks!))
  * Molecule test #5
  * Fix bugs with LoadModule & add sqlite3 support #2 (By pull request: splitice (Thanks!))
  * Zabbix proxy 3.0 fixes #1 (By pull request: zbal (Thanks!))

0.4.0   (2016-08-24)

  * ?

0.3.0   (2016-02-08)

  * Added test-kitchen tests
  * Small bug fix for installation on RedHat/Debian

0.2.0   (2016-02-04)

  * Added travis-ci test.

0.1.0   (2015-02-01)

   * Updated readme
   * added double quotes on names
   * added var zabbix_repo
   * added var for database creation and load file

0.0.1   (2014-10-31)

  * Initial Creation
