# ansible-zabbix-web Release

Below an overview of all changes in the releases.

Version (Release date)

FINAL and LAST release for this role in this repository. This role will be transferred to: https://github.com/ansible-collections/community.zabbix/

1.6.0   (2020-05-23)

  * Added installation of selinux package #74
  * 4.4 supports Debian buster #75 (By pull request: lingfish (Thanks!))
  * Avoid conflicts with zabbix_version var #77 (By pull request: santiagomr (Thanks!))
  * adding zabbix_apache_skip_custom_fragment to prevent php_values in conf #79 (By pull request: tobiasehlert (Thanks!))
  * Correcting custom fragment PR 79 #80 (By pull request: tobiasehlert (Thanks!))
  * Adding zabbix_apache_include_custom_fragment to TLS section #81 (By pull request: tobiasehlert (Thanks!))
  * selinux blocking httpd connection to zabbix #82 (By pull request: SimBou (Thanks!))
  * php-fpm, zabbix db schema and apachectl path #85 (By pull request: v (Thanks!))

1.5.0   (2019-12-01)

  * Added vhost interface variable #55 (By pull request: okgolove (Thanks!))
  * Minor changes for molecule #56
  * Make Apache optional but keep as default; Closes dj-wasabi/ansible-zabbix-web#58 #59 (By pull request: kr4ut (Thanks!))
  * Refactor PHP pkg install for Debian/Ubuntu; Closes dj-wasabi/ansible-zabbix-web#57 #60 (By pull request: kr4ut (Thanks!))
  * Add update_cache: yes to tasks/RedHat.yml #64 (By pull request: patsevanton (Thanks!))
  * readme update that default is 4.2 #67 (By pull request: fabtho (Thanks!))
  * Update main.yml #68 (By pull request: Vinclame (Thanks!))
  * SELinux boolean added for httpd -> ldap connections #69 (By pull request: Vinclame (Thanks!))
  * Zabbix 44 #71
  * Using travis envs #72

1.4.0   (2019-04-14)

  * Fixing the rights for config file #39
  * Fixing the require line #40
  * Removed the _type string in various places #42
  * adds support for elasticsearch history storage #43 (By pull request: MartinHell (Thanks!))
  * Always include OS variables #44 (By pull request: jrgoldfinemiddleton (Thanks!))
  * skip repo file when zabbix_repo="other" #45 (By pull request: wschaft (Thanks!))
  * Removal of links to files provided by Zabbix #47
  * Fix apt module deprecation notice #49 (By pull request: logan2211 (Thanks!))
  * fix apache servername regex to support hyphen character #51 (By pull request: wschaft (Thanks!))
  * get the apache version also in check mode #52 (By pull request: wschaft (Thanks!))
  * Updating to Zabbix 4.2 #53

1.3.0   (2018-10-20)

  * Add zabbix 40 #33
  * Modify use of zabbix server packages #35 (By pull request: average-joe (Thanks!))
  * Fix for: update readme to include correct examples #32

1.2.0   (2018-09-11)

  * Updated supported versions #27
  * Readme lang typos grammar #28 (By pull request: dnmvisser (Thanks!))
  * Reflect license change to MIT in README #29 (By pull request: stephankn (Thanks!))
  * Fix for #24 #30
  * Fix for: SSLPassPhraseDialog setting problems - /usr/libexec/httpd-ss… #31

1.1.0   (2018-06-23)

  * added support for HTTPS #25 (By pull request: q1x (Thanks!))
  * Make debian 9 work #22
  * Updated minimal Ansible version to 2.4 #21
  * Changed version_compare operator to avoid deprecation warnings #19 (By pull request: nidr0x (Thanks!))
  * Most of the time php behaves better with leading semicolon. #17 (By pull request: toke (Thanks!))
  * add php7.0-gd #16 (By pull request: scil (Thanks!))
  * Fixed missing attribute iteritems #15 (By pull request: toke (Thanks!))
  * Allow usage of php environment variables #13 (By pull request: toke (Thanks!))
  * Make use of Molecule V2
  * Add support for debian stretch #7 (By pull request: dulin (Thanks!))
  * Fix Zabbix graph legend bug for Debian packages (see ZBX-10467) #6 (By pull request: mgornikov (Thanks!))
  * Split zabbix_url and Apache vhost ServerName #5 (By pull request: eshikhov (Thanks!))

1.0.0   (2017-08-30)

  * Removed tags 'always' on few tasks.
  * Fix for: Installing Zabbix-Web-MySQL Failed #1

0.1.0   (2017-06-16)

  * Initial working version.
