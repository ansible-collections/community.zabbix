# Ansible Zabbix Agent release

Below an overview of all changes in the releases.

Version (Release date)

FINAL and LAST release for this role in this repository. This role will be transferred to: https://github.com/ansible-collections/community.zabbix/

2.3.0  (2020-05-05)

  * Prevent to run multiple time installation on localhost #334 (By pull request: SimBou (Thanks!))
  * Add support for XCP-ng as a dialect of RHEL7 #335 (By pull request: KurtSchluss (Thanks!))
  * Fix: Changed apt state to present from installed. #336 (By pull request: sebedh (Thanks!))
  * Selinux boolean to allow zabbix to run sudo commands #340 (By pull request: Vinclame (Thanks!))
  * Added performance userparameter.yml on Windows #342 (By pull request: ComradeAx0n (Thanks!))
  * Added some missing ubuntu ids #344

2.2.0  (2020-03-07)

  * Add weight for apt #333
  * Added property zabbix_agent_src_reinstall so it will succeed the idem… #332
  * Set the correct until which had a wrong value #330
  * Partly reverting change for Debian #329
  * Added debian #327
  * Reorder task based on issue #326
  * Removing deprication warnings #325
  * Removed the as it will add a proxy line that blocks everything #324
  * adding empty dict to zabbix_agent_inventory_zabbix #323 (By pull request: tobiasehlert (Thanks!))
  * setting value for zabbix_agent_ipmi_authtype and zabbix_agent_ipmi_privilege #319 (By pull request: tobiasehlert (Thanks!))
  * Preventing of adding empty ListenIP= to the config file #318 (By pull request: ddyugaev (Thanks!))
  * Use proxy if defined (Windows) #316 (By pull request: lingfish (Thanks!))
  * RedHat proxy set in repo file #315 (By pull request: lingfish (Thanks!))
  * Windows agent download link fix #313 (By pull request: ddyugaev (Thanks!))
  * Apply proxy settings when installing deb-src repositories #312 (By pull request: KurtSchluss (Thanks!))
  * added additional zabbix_host parameter #307 (By pull request: pugnacity (Thanks!))
  * fix check mode on Windows #305 (By pull request: Poil (Thanks!))
  * Move up task 'Override architecture if 64-bit' #304 (By pull request: Gati0 (Thanks!))
  * Avoid conflicts with the zabbix_version and zabbix_url variables #303 (By pull request: santiagomr (Thanks!))
  * Fix incorrect handler names #299 (By pull request: gunnarbeutner (Thanks!))
  * Implement support for macOS #298 (By pull request: gunnarbeutner (Thanks!))
  * Improving readability and avoiding repeated code #296 (By pull request: santiagomr (Thanks!))
  * 'Template OS Linux' doesn't exist in Zabbix 4.4 #295
  * Add follow_redirects for download Windows-Agent on Windows #294 (By pull request: Gati0 (Thanks!))

2.1.0  (2019-11-25)

  * Fix typos #274 (By pull request: akamch (Thanks!))
  * Added retry for API related tasks #275
  * Added missing task for adding a TLS-PSK file #280
  * Remove the host running Docker from Molecule for now #281
  * Updating to Zabbix 4.4 #282
  * Trying to use a Matrix in Travis and see what happens.. :-)
  * Pass params to Ansible Zabbix modules used by role to allow HTTP Basi… #285 (By pull request: nadley (Thanks!))
  * RHEL8 specific changes for SELinux #286 (By pull request: bdekker-routit (Thanks!))
  * userparameters from parametizable sources #287 (By pull request: santiagomr (Thanks!))
  * Added cosmic to the zabbix.yml vars file.

2.0.0  (2019-09-29)

  * Using Ansible 2.7 as minimal version;
  * fix repository problem #236 (By pull request: kmonticolo (Thanks!))
  * Added ansible_python_interpreter for Fedora #238
  * Allow to use a (http|https) proxy for downloading of packages #239
  * fix repository problem #240 (By pull request: kmonticolo (Thanks!))
  * Add Debian 10 (buster) for Zabbix 4.2,4.0 and 3.0 #243 (By pull request: patede (Thanks!))
  * Add "vars" tag to include variables #247 (By pull request: j8r (Thanks!))
  * Introduce AutoPSK for easy encryption; Closes dj-wasabi/ansible-zabbix-agent#250 #251 (By pull request: kr4ut (Thanks!))
  * Install selinux-policy-targeted (dependency) #255 (By pull request: Maelstrom96 (Thanks!))
  * Add support to FreePBX #261 (By pull request: darco1991 (Thanks!))
  * Add support for firewalld zone #262 (By pull request: darco1991 (Thanks!))
  * Fix group membership zabbix_agent.d dir according to #246 #264
  * According to #263 1100 needs to be added to the sc.exe call #265
  * Changing gpg keys #267
  * Added suggested task for correct installation of Zabbix on Amazon #270
  * Added some properties for configuring iptables #271
  * Bare variable deprecation #272 (By pull request: average-joe (Thanks!))
  * Moving zabbix_agent_ip to Linux.yml and create a new one for Windows.yml #268

1.7.1  (2019-06-04)

  * Revert breaking changes #232 (By pull request: crazikPL (Thanks!))

1.7.0  (2019-05-30)

  * Updated to Zabbix 4.2 to default installations #221
  * Fixed for the default scenario the warnings #222
  * Add Windows Agent update and service auto-recovery #223 (By pull request: pimooss (Thanks!))
  * Added Docker image #224
  * Add details on requiring sudo access for python-netaddr #226 (By pull request: willhallonline (Thanks!))
  * Defining different jmx port number to configuring firewall #227 (By pull request: 0utsider (Thanks!))
  * Update syntax to ansible 2.8 #228 (By pull request: crazikPL (Thanks!))
  * Use EPEL 7 when Amazon 2 #230 (By pull request: bkmeneguello (Thanks!))

1.6.1  (2019-04-12)

  * Update userparameter.yml #215 (By pull request: Jookadin (Thanks!))
  * Pip packages install variable #217 (By pull request: rnsc (Thanks!))
  * Added task that was previously in role #219

1.6.0  (2019-03-13)

  * Added task for installation of the zabbix-api package #191
  * Restart agent when PSK file changes (fixes #193) #194 (By pull request: pigulla (Thanks!))
  * Added a until loop to retry installations as suggested by ansible-lint #195
  * Add fedora 29 support #199 (By pull request: average-joe (Thanks!))
  * Set default values if property is undefined #203
  * Add installation of pip package netaddr #204
  * Add option not to elevate privileges locally #206 (By pull request: dennisse (Thanks!))
  * Windows zabbix agent handler #209 (By pull request: rnsc (Thanks!))
  * Add Bionic to sign keys for zabbix-agent v3.0 and v3.2 #211 (By pull request: mamedin (Thanks!))
  * Fix for: zabbix_agent_tlsconnect and zabbix_agent_tlsaccept are mixed #205
  * Fix for: Role Should NOT Smash Ansible Facts #207

1.5.0  (2018-10-19)

  * Added installation on Windows
  * Firewalld #166 (By pull request: 0utsider (Thanks!))
  * Using same container as with the server #167
  * Zabbix 4.0 now default installation
  * enable support for https enabled zabbix frontends/apis #173 (By pull request: rolfvreijdenberger (Thanks!))

1.4.0  (2018-09-11)

  * Add configuration to prevent host updating via zabbix api #150 (By pull request: sblaisot (Thanks!))
  * Handle encryption when adding host to zabbix server #151 (By pull request: sblaisot (Thanks!))
  * Removed the warning message #156
  * Updating versions to be installed #157
  * Added 2nd Molecule Scenario #158
  * Parameterizing userparameter deployment #159 (By pull request: rubentsirunyan (Thanks!))
  * fix typo #160 (By pull request: kmonticolo (Thanks!))
  * Reflect changed license in README #161 (By pull request: stephankn (Thanks!))
  * remove deprecated loop #162 (By pull request: stephankn (Thanks!))
  * Fix when running ansible in --check mode #163 (By pull request: AlbanAndrieu (Thanks!))

1.3.0  (2018-06-23)

  * fixes issue "Configure iptables task fail" #128 (By pull request: andreagrax (Thanks!))
  * Fix travis docker #131
  * Added several 'become: yes' to tasks #133
  * Added gpg key id for agent version 3.0 in Debian Stretch #135 (By pull request: hatifnatt (Thanks!))
  * Upgrade minimum Ansible version from 1.9 --> 2.4
  * Added a License, Code of Conduct and some more files
  * Fix for Misleading repo name #147
  * fixes for the userparameter task #138 (By pull request: HNKNTA (Thanks!))
  * Support for Debian 9 and Ubuntu 18.04
  * Added fix for: Host autoregistered in zabbix with IP 0.0.0.0 when Lis… #141

1.2.0  (2018-01-25)

  * Fix for: Some RedHat subtask are missing become option #116
  * Delete option "run_once" from task "Create hostgroups" #119 (By pull request: mgornikov (Thanks!))
  * Fix the CI Travis build again.
  * Fix for: Changing zabbix_version breaks role #117
  * Added sonya #120
  * Add clean all #121
  * allow 127.0.0.1 for listenip #124 (By pull request: blodone (Thanks!))
  * Get selinux status #125 (By pull request: andreagrax (Thanks!))
  * Add new variable zabbix_visible_hostname #126 (By pull request: samyscoub (Thanks!))
  * Replaced `yum` with `package` #127  (By pull request: average-joe (Thanks!))

1.1.0  (2017-11-13)

  * Add zabbix_ to agent_serveractive and agent_server #101 (By pull request: asosso (Thanks!))
  * Fix typo #102 (By pull request: asosso (Thanks!))
  * Added support for Zabbix host inventory mode #103 (By pull request: mgornikov (Thanks!))
  * Trying to fix mint #105
  * Do not report as change when update an existing host's info #107 (By pull request: asosso (Thanks!))
  * Add default value for zabbix_inventory_mode #108 (By pull request: asosso (Thanks!))
  * Added IPtables #111
  * Added when for enabling repo when zabbix_repo==zabbix #112
  * Added stretch for Zabbix 3.2 #115

1.0.3  (2017-09-07)

  * Fix attempt two for: zabbix_agent_listenip not working as expected #98
  * Updated Molecule V1 test to Molecule V2. 

1.0.2  (2017-09-03)

  * Fix for: zabbix_agent_listenip not working as expected #98
  * Fix for: s/agent_interfaces/zabbix_agent_interfaces #95 && 'agent_interfaces' is undefined #94
  * Forgot to update documentation with the new variable names (Added the `zabbix_` prefixes.)

1.0.1  (2017-08-31)

  * Fix for: Error in: Create directory for PSK file if not exist

1.0.0  (2017-08-30)

  * From ini to yml style.
  * Used yum instead of apt #78
  * Installing default 3.4.
  * Prefixed all properties that started with `agent_` with the value `zabbix_`.
  * [DOCS] Fix readme for zabbix_api_create_hosts #82 (By pull request: Logan2211 (Thanks!))
  * Workaround https://github.com/ansible/ansible-modules-core/issues/3764 #85 (By pull request: ma-tty (Thanks!))
  * Added Mint #88
  * Include Debian stretch in 3.4 #89  (By pull request: rtgibbons (Thanks!))
  * Add creation of PSK file #90
  * Fix for: Key-dependent repository installed before the key #80
  * Set Molecule to V1 for now since V2 is released.

0.10.0  (2017-07-25)

  * Added run_once to only execute the task once #77
  * Adds zabbix_selinux variable to README #75
  * Adding tasks for selinux #74
  * Fix type number of jmx/ipmi #65 (By pull request: fazelgh (Thanks!))
  * zabbix_hostmacro fix #64 (By pull request: dguihal (Thanks!))
  * Does not confuse with zabbix_api_use setting. #61 (By pull request: i5513 (Thanks!))
  * get gpg key over https #60 (By pull request: sjugge (Thanks!))
  * Using the same version handling as with the zabbix-server #59

0.9.0   (2016-12-30)

  * Fix hostname mistmatch when updating macros #54 (By pull request: tahajahangir (Thanks!))
  * Update main.yml #52 (By pull request: envrm (Thanks!))
  * Added zabbix.yml vars for correct apt_key id #48
  * Updated to Zabbix 3.2.0 #47
  * Fix missed tag #43 (By pull request: leominov (Thanks!))
  * Set everything the same with agent_hostname

0.8.0   (2016-08-24)

  * Added more tests for Molecule
  * Configured Travis to execute the Molecule tests
  * specified become for local tasks #33 (By pull request: kam1kaze (Thanks!))
  * add proxy param to zabbix api #34 (By pull request: kam1kaze (Thanks!))
  * Fix for: zabbix 3 JMX interface Added property `agent_interfaces` to configure the interfaces via the API.
  * Fix for: skip zabbix_group module (Replaced `zabbix_api_use` by the properties `zabbix_api_create_hostgroup` and `zabbix_api_create_hosts`)

0.7.0   (2016-07-11)

  * Fix for: zabbix_repo - inconsistent use between server and agent roles. #17
  * Fix for: apache 2.2. and 2.4 #15
  * Removed Test Kitchen tests and added Molecule tests.
  * remove deprecated py scripts in library dir #32 (By pull request: mescanef (Thanks!))

0.6.0   (2016-05-12)

  * Changed sudo to become. #30 (By pull request: UnderGreen (Thanks!))
  * No reason for zabbix to able to change its own config #25 (By pull request: burner1024 (Thanks!))
  * Updated documentation for Zabbix 3.0
  * Updated Zabbix 3.0 OS list
  * Fixed tests

0.5.0   (2016-02-16)

  * Zabbix 3.0
  * Moved "set_facts" to var files.
  * Added basic travis-si test.

0.4.0   (2016-01-31)

  * zabbix_host_groups not working as expected #4 (By pull request: Pion (Thanks!))
  * set cache_valid_time=0 to ensure an apt-get update after the added repo-key (By pull request: lhoss (Thanks!))
  * Add api tag to set_fact. Fixes #19 (By pull request: kostyrevaa (Thanks!))
  * add sudo, and add zabbix-api dependency to readme.md (By pull request: Savemech (Thanks!))
  * default zabbix_agent to all interfaces #14 (By pull request: dlbewley (Thanks!))
  * enable use of EPEL packages #11 (By pull request: dlbewley (Thanks!))
  * Fixed kitchen test setup
  * Removed zabbix_group (is already in Ansible), updated zabbix_host
  * Added tag: zabbix-agent

0.3.0   (2015-08-25)

  * Fixes for RHEL 6 Server on ansible 1.9.2 #10 (By pull request: bwaters (Thanks!))
  * remove macros from defaults fixes issue #7 (By pull request: kostyrevaa (Thanks!))
  * defaults/main.yml is not in line with the README #5 (By pull request: dhxgit (Thanks!))
  * Added empty dependencies list to meta/main.yml #3 (By pull request: neneko-mun (Thanks!))
  * Ubuntu is uppercase in ansible_distribution #2 (By pull request: wascheck (Thanks!))

0.2.1   (2015-03-20)

  * Create hostgroups requires zabbix_api #1 (By pull request: wascheck (Thanks!))

0.2.0   (2015-03-06)

  * Added some "cove" modules for automatically creating agents in webinterface via api
  * Updated template for correct listeninterface

0.1.0   (2015-02-01)

  * Updated readme; added double quotes on names; added var zabbix_repo;

0.0.2   (2014-11-05)

  * Added suse as operating system
  * Updated documentation
  * Updated the name for the debian repositories for including deb or deb-src


0.0.1   (2014-11-01)

  * Initial Version
