==============================
community.zabbix Release Notes
==============================

.. contents:: Topics


v2.1.0
======

Minor Changes
-------------

- Multiple Roles - Replaced depricated 'include' statements with 'include_tasks'
- Update action_groups variable in runtime.yml
- all roles - Added support for Debian 12 (Bookworm)
- all roles - Delete gpg ids variable.
- all roles - Modified to allow a non-root user to run the role.
- all roles - Updated testing to account for the correct version of Zabbix
- zabbix_hostmacro module - Add description property for Host macro creation/update. Allow to set/update description of Zabbix host macros.
- zabbix_proxy - Added installation of PyMySQL pip package
- zabbix_proxy - Modified installation of Centos 7 MySQL client
- zabbix_proxy - Standardized MySQL client installed on Debian and Ubuntu
- zabbix_regexp module added
- zabbix_settings module added
- zabbix_token module added

Bugfixes
--------

- agent role - Added missing become statement to allow run to role as nonroot
- zabbix_host module - fix updating hosts that were discovered via LLD
- zabbix_proxy role - failed at version validation. Fix adds cast of zabbix_proxy_version to float, similarly to the other roles.
- zabbix_proxy role - undefined vars at updating proxy definition. Fix adds null defaults for zabbix_proxy_tlsaccept and zabbix_proxy_tlsconnect.
- zabbix_web role - removed 'ssl on;' nginx configuration, which is no longer supported since nginx version 1.25.1.

New Modules
-----------

- community.zabbix.zabbix_regexp - Create/update/delete Zabbix regular expression
- community.zabbix.zabbix_settings - Update Zabbix global settings.
- community.zabbix.zabbix_token - Create/Update/Generate/Delete Zabbix token.

v2.0.1
======

Bugfixes
--------

- Proxy and Agent Roles - Added `zabbix_api_use_ssl` variable to allow secure API connections
- Web Role - Added defaults and documentation for `zabbix_apache_custom_includes`
- agent - Handled undefined variable error for Windows default versions
- all roles - Added option to selectively disable a repo on Redhat installs

v2.0.0
======

Minor Changes
-------------

- Replaced usage of deprecated apt key management in Debian based distros - See https://wiki.debian.org/DebianRepository/UseThirdParty
- Standardized tags across all roles.
- Updated all roles to default to version 6.4 for install.
- all roles - removed unused variables from defaults
- all roles - standardized testing matrix to check all supported versions and operating systems.
- all roles - temporarily disable epel repo on zabbix installation tasks
- all roles - updated documentation.
- inventory plugin - switched from using zabbix-api to custom implementation adding authentication with tokens
- inventory script - re-coded to stop using zabbix-api. API tokens support added.
- web role - removed support for htpasswd

Breaking Changes / Porting Guide
--------------------------------

- agent role - removed support for Darwin, Amazon, Fedora, XCP-ng, Suse, Mint, and Sangoma operating systems
- agent role - removed support for zabbix_create_host and replaced it with zabbix_agent_host_state
- agent role - removed support for zabbix_create_hostgroup and replaced it with zabbix_agent_hostgroups_state
- agent role - removed support for zabbix_http_password, zabbix_api_http_password, zabbix_api_pass, and zabbix_api_login_pass and replaced it with zabbix_api_login_pass
- agent role - removed support for zabbix_http_user, zabbix_api_http_user, zabbix_api_user, and zabbix_api_login_user and replaced it with zabbix_api_login_user
- agent role - removed support for zabbix_inventory_mode and replaced it with zabbix_agent_inventory_mode
- agent role - removed support for zabbix_link_templates adn replaced it with zabbix_agent_link_templates
- agent role - removed support for zabbix_macros and replaced it with zabbix_agent_macros
- agent role - removed support for zabbix_proxy and replaced it with zabbix_agent_proxy
- agent role - removed support for zabbix_update_host and replaced it with zabbix_agent_host_update
- all modules - dropped support of Zabbix versions < 6.0
- all roles  - removed support for the zabbix_version variable.
- all roles - removed support for all versions of Zabbix < 6.0.
- all roles - removed support for installation from epel and non-standard repositories
- dropped support of zabbix-api to make REST API calls to Zabbix
- proxy role - removed support for zabbix_database_creation  and replaced it with zabbix_proxy_database_creation
- proxy role - removed support for zabbix_database_sqlload  and replaced it with zabbix_proxy_database_sqlload
- proxy role - removed support for zabbix_selinux  and replaced it with zabbix_proxy_selinux
- server role - removed support for zabbix_server_mysql_login_password and replaced with zabbix_server_dbpassword
- server role - removed support for zabbix_server_mysql_login_user and replaced with zabbix_server_dbuser
- stopped supporting Ansible < 2.12
- stopped supporting Python < 3.9
- zabbix_action - message parameter renamed to op_message
- zabbix_group_facts module - removed in favour of zabbix_group_info
- zabbix_host_facts module - removed in favour of zabbix_host_info

Removed Features (previously deprecated)
----------------------------------------

- agent role - removed support to configure firewall
- web role - removed installation of apache, debian, and php

v1.9.3
======

Minor Changes
-------------

- httpapi plugin - updated to work with Zabbix 6.4.
- zabbix_action, zabbix_authentication, zabbix_discovery_rule, zabbix_mediatype, zabbix_user, zabbix_user_directory, zabbix_usergroup - updated to work with Zabbix 6.4.
- zabbix_agent role - Add support for SUSE Linux Enterprise Server for SAP Applications ("SLES_SAP").
- zabbix_host - add missing variants for SNMPv3 authprotocol and privprotocol introduced by Zabbix 6
- zabbix_proxy role - Add variable zabbix_proxy_dbpassword_hash_method to control whether you want postgresql user password to be hashed with md5 or want to use db default. When zabbix_proxy_dbpassword_hash_method is set to anything other than md5 then do not hash the password with md5 so you could use postgresql scram-sha-256 hashing method.
- zabbix_server role - Add variable zabbix_server_dbpassword_hash_method to control whether you want postgresql user password to be hashed with md5 or want to use db default. When zabbix_server_dbpassword_hash_method is set to anything other than md5 then do not hash the password with md5 so you could use postgresql scram-sha-256 hashing method.
- zabbix_usergroup module - userdirectory, hostgroup_rights and templategroup_rights parameters added (Zabbix >= 6.2)
- zabbix_web role - possibility to add custom includes in apache vhost config

Bugfixes
--------

- compatibility with ansible.netcommon 5.0.0
- treat sendto parameter in module zabbix_user according to real media type, do not rely on media name
- zabbix-proxy role - fix tags for postgresql task.
- zabbix_agent role - Fix MacOS install never executed because of the missing include_tasks "Darwin.yml" in the "main.yml" task file and wrong user permission on folder/files.
- zabbix_user module - ability to specify several e-mail addresses in Zabbix User's  media

v1.9.2
======

Bugfixes
--------

- zabbix_agent and zabbix_proxy roles - fixed a bug whith ansible_python_interpreter not being set correctly in some corner cases
- zabbix_agent role - Fix MacOS install never executed because of the missing include_tasks "Darwin.yml" in the "main.yml" task file and wrong user permission on folder/files.
- zabbix_agent, zabbix_proxy and zabbix_server roles - make Ansible 2.14 compatible by removing warn parameter

v1.9.1
======

Minor Changes
-------------

- zabbix suport for rhel 9

Bugfixes
--------

- all modules - remove deprecation warnings for modules parameters related to zabbix-api when these parapmeters are not explicetely defined
- all roles and modules integration tests - replace deprecated include module whith include_tasks
- zabbix_agent, zabbix_proxy roles, all modules - make httpapi connection work with HTTP Basic Authorization
- zabbix_proxy - do not set ServerPort config parameter which was removed in Zabbix 6.0
- zabbix_server role Debian.yml task - remove warn: arg for shell module as the arg is deprecated since ansible-core above 2.13
- zabbix_user_role module - creation of a User Role with Super Admin type

v1.9.0
======

Major Changes
-------------

- all modules are opting away from zabbix-api and using httpapi ansible.netcommon plugin. We will support zabbix-api for backwards compatibility until next major release. See our README.md for more information about how to migrate
- zabbix_agent and zabbix_proxy roles are opting away from zabbix-api and use httpapi ansible.netcommon plugin. We will support zabbix-api for backwards compatibility until next major release. See our README.md for more information about how to migrate

Minor Changes
-------------

- ansible_zabbix_url_path introduced to be able to specify non-default Zabbix WebUI path, e.g. http://<FQDN>/zabbixeu
- collection now supports creating ``module_defaults`` for ``group/community.zabbix.zabbix`` (see https://github.com/ansible-collections/community.zabbix/issues/326)
- fixed ``zabbix_server`` role failure running in check_mode (see https://github.com/ansible-collections/community.zabbix/issues/804)
- zabbix_agent - give Zabbix Agent access to the Linux DMI table allowing system.hw.chassis info to populate.
- zabbix_template - add support for template tags
- zabbix_user_role module added
- zabbix_web - add support for Ubuntu 22.04 jammy

Bugfixes
--------

- The inventory script had insufficient error handling in case the Zabbix API provided an empty interfaces list. This bugfix checks for an exisiting interfaces element, then for the minimal length of 1 so that the first interface will only be accessed when it really exists in the api response. (https://github.com/ansible-collections/community.zabbix/issues/826)
- zabbix-proxy - updated to install correct sources for Debian arm64 family
- zabbix_agent - Filter IPv6 addresses from list of IP as Zabbix host creation expects IPv4
- zabbix_agent - installation on Windows will no longer fail when zabbix_agent2 is used
- zabbix_host - fix updating of host without interfaces
- zabbix_proxy - correctly provision tls_accept and tls_connect on Zabbix backend
- zabbix_proxy - updated the datafiles_path fact for the zabbix_proxy and zabbix_server roles due to upstream change
- zabbix_server - move location of the fping(6) variables to distribution specific files (https://github.com/ansible-collections/community.zabbix/issues/812)
- zabbix_server - updated the datafiles_path fact for the zabbix_proxy and zabbix_server roles due to upstream change

v1.8.0
======

Minor Changes
-------------

- roles - Minimized the config templates for the zabbix_agent, zabbix_javagateway, zabbix_proxy, and zabbix_server roles to make them version independent.
- roles - Support for Zabbix 6.2 has been added
- roles - Updated the version defaults to select the latest version supported by an operating system.
- zabbix_action - added another condition operator naming options (contains, does not contain,...)
- zabbix_agent - Set a ansible_python_interpreter to localhost based on the env the playbook is executed from.
- zabbix_agent - add option to set host tags using ``zabbix_agent_tags``.
- zabbix_agent - add possiblity to set include file pattern using ``zabbix_agent(2)_include_pattern`` variable.
- zabbix_agent - is now able to manage directories and upload files for TLS PSK configuration used with Windows operating systems
- zabbix_agent - new options for Windows installations zabbix_win_install_dir_conf/bin
- zabbix_agent - when configuring firewalld, make sure the new rule is applied immediately
- zabbix_authentication - module updated to support Zabbix 6.2
- zabbix_host - using ``tls_psk_identity`` or ``tls_psk`` parameters with Zabbix >= 5.4 makes this module non-idempotent
- zabbix_host - will no longer wipe tls_connect en tls_accept settings when not specified on update
- zabbix_mediatype - added support for time units in ``attempt_interval`` parameter
- zabbix_template - added support for template groups (Zabbix >= 6.2)
- zabbix_template_info - add template_id return value
- zabbix_template_info - add yaml and none formats
- zabbix_user_directory - added new module to support multiple sources for LDAP authentication

Bugfixes
--------

- zabbix_host - fixed idempotency of the module when hostmacros or snmp interfaces are used
- zabbix_script - fix compatibility with Zabbix <5.4.
- zabbix_script - should no longer fail when description is not set

v1.7.0
======

Minor Changes
-------------

- helpers.helper_compare_lists() changed logic to not consider the order of elements in lists. (https://github.com/ansible-collections/community.zabbix/pull/683)
- zabbix_action, zabbix_maintenance, zabbix_mediatype, zabbix_proxy, zabbix_service - updated to work with Zabbix 6.0. (https://github.com/ansible-collections/community.zabbix/pull/683)
- zabbix_script module added (https://github.com/ansible-collections/community.zabbix/issues/634)

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.
- zabbix_action - will no longer wipe `esc_step_to` and `esc_step_from` (https://github.com/ansible-collections/community.zabbix/issues/692)
- zabbix_agent - added support for zabbix-agent on Ubuntu 22.04 (https://github.com/ansible-collections/community.zabbix/pull/681)
- zabbix_agent - now properly creates webroot for issuing LE certificates (https://github.com/ansible-collections/community.zabbix/pull/677, https://github.com/ansible-collections/community.zabbix/pull/682)
- zabbix_proxy (module) - passive proxy should be now correctly created in Zabbix 6.0 (https://github.com/ansible-collections/community.zabbix/pull/697)
- zabbix_proxy (role) - fixed accidental regression of TLS psk file being generated for passive agent (#528) caused in (#663) (https://github.com/ansible-collections/community.zabbix/issues/680)

New Modules
-----------

- community.zabbix.zabbix_script - Create/update/delete Zabbix scripts

v1.6.0
======

Minor Changes
-------------

- all modules - prepare for deprecation of distutils LooseVersion.
- collection - Add dependencies to other collections. This helps Ansible Galaxy automatically downloading collections that this collection relies on to run.
- connection.httpapi (plugin) - add initial httpapi connection plugin.
- httpapi.jsonrpc (plugin) - add initial httpapi for future handling of json-rpc.
- new module zabbix authentication for configuring global authentication settings in Zabbix Server's Settings section of GUI.
- new module zabbix_autoregister for configuring global autoregistration settings in Zabbix Server's Settings section of GUI.
- new module zabbix_housekeeping for configuring global housekeeping settings in Zabbix Server's Settings section of GUI.
- test_zabbix_host_info - fix Template/Group names for 5.4
- test_zabbix_screen - disable testing for screen in 5.4 (deprecated)
- zabbix_action - additional fixes to make module work with Zabbix 6.0 (https://github.com/ansible-collections/community.zabbix/pull/664)
- zabbix_action - module ported to work with Zabbix 6.0 (https://github.com/ansible-collections/community.zabbix/pull/648, https://github.com/ansible-collections/community.zabbix/pull/653)
- zabbix_action - should now correctly actions with maintenance_status conditions (https://github.com/ansible-collections/community.zabbix/pull/667)
- zabbix_agent - Check if 'firewalld' exist and is running when handler is executed.
- zabbix_agent - Fixed use of bare variables in conditions (https://github.com/ansible-collections/community.zabbix/pull/663)
- zabbix_agent - Install the correct Python libxml2 package on SLES15
- zabbix_agent - Move inclusion of the apache.yml tasks to later stage during execution of role.
- zabbix_agent - Prepare for Zabbix 6.0.
- zabbix_agent - Specify a minor version with zabbix_agent_version_minor for RH systems.
- zabbix_agent - There was no way to configure a specific type for the macro.
- zabbix_agent - Use multiple aliases in the configuration file with ``zabbix_agent_zabbix_alias`` or ``zabbix_agent2_zabbix_alias``.
- zabbix_maintenance - added new module parameter `tags`, which allows configuring Problem Tags on maintenances.
- zabbix_maintenance - fixed to work with Zabbix 6.0+ and Python 3.9+ (https://github.com/ansible-collections/community.zabbix/pull/665)
- zabbix_proxy - Prepare for Zabbix 6.0.
- zabbix_proxy - Specify a minor version with zabbix_proxy_version_minor for RH systems.
- zabbix_proxy - Support for Sangoma and treat it like a RHEL system.
- zabbix_server - Check the 'zabbix_server_install_database_client' variable in RedHat tasks.
- zabbix_server - Prepare for Zabbix 6.0.
- zabbix_server - Specify a minor version with zabbix_server_version_minor for RH systems.
- zabbix_user - change alias property to username (changed in 5.4) (alias is now an alias for username)
- zabbix_user_info - change alias property to username (changed in 5.4) (alias is now an alias for username)
- zabbix_web - Change format ENCRYPTION, VERIFY_HOST from string to boolean.
- zabbix_web - Specify a minor version with zabbix_web_version_minor for RH systems.

Bugfixes
--------

- Various modules and plugins - use vendored version of ``distutils.version`` instead of the deprecated Python standard library ``distutils`` (https://github.com/ansible-collections/community.zabbix/pull/603). This superseedes #597.
- ZapiWrapper (module_utils) - fix only partial zabbix version is returned.
- zabbix_agent - Install Zabbix packages when zabbix_repo == other is used with yum.
- zabbix_agent - Install the Agent for MacOSX sooner than its configuration.
- zabbix_agent - The ``Install gpg key`` task for Debian did not work when a http proxy is configured.
- zabbix_agent - Use the correct URL with correct version.
- zabbix_agent - Use the correct path to determine Zabbix Agent 2 installation on Windows.
- zabbix_agent - Using the correct hostgroup as default now.
- zabbix_agent - fix for the autopsk, incl. tests with Molecule.
- zabbix_host - Added small notification that an user should have read access to get hostgroups overview.
- zabbix_host - adapter changed properties for interface comparisson
- zabbix_maintenance - should now work when creating maintenace on Zabbix 6.0 server
- zabbix_proxy - 'zcat' the zipped sql files to /tmp before executing it.
- zabbix_proxy - Check MySQL version before settings mysql_innodb_default_row_format value.
- zabbix_proxy - Install Zabbix packages when zabbix_repo == other is used with yum.
- zabbix_server - 'zcat' the zipped sql files to /tmp before executing it.
- zabbix_server - Check MySQL version before settings mysql_innodb_default_row_format value.
- zabbix_server - Install Zabbix packages when zabbix_repo == other is used with yum.
- zabbix_template - setting correct null values to fix unintentional changes
- zabbix_web - Added some default variables if the geerlingguys apache role is not used.
- zabbix_web - Specified the correct versions for php.

New Plugins
-----------

Connection
~~~~~~~~~~

- community.zabbix.httpapi - Use httpapi to run command on network appliances

Httpapi
~~~~~~~

- community.zabbix.jsonrpc - HttpApi Plugin for Zabbix

New Modules
-----------

- community.zabbix.zabbix_authentication - Update Zabbix authentication
- community.zabbix.zabbix_autoregister - Update Zabbix autoregistration
- community.zabbix.zabbix_housekeeping - Update Zabbix housekeeping

v1.5.1
======

Minor Changes
-------------

- Enabled usage of environment variables for modules by adding a fallback lookup in the module_utils/helpers.py - zabbix_common_argument_spec

Bugfixes
--------

- template - use templateid property when linking templates for ``template.create`` and ``template.update`` API calls.
- zabbix inventory - Moved ZABBIX_VALIDATE_CERTS to correct option, validate_certs.
- zabbix_agent - Create the actual configuration file for Windows setups.
- zabbix_agent - Fix typo for correct using the zabbix_windows_service.exists
- zabbix_agent - tlspsk_auto to support become on Linux and ignore on windows
- zabbix_user - fix zabbix_user require password only on internal.

v1.5.0
======

Minor Changes
-------------

- Added requirements.txt to collection root to be used with Ansible Builder. See https://ansible-builder.readthedocs.io/en/latest/collection_metadata.html
- some roles are now using new naming for API connection parameters (https://github.com/ansible-collections/community.zabbix/pull/492 and https://github.com/ansible-collections/community.zabbix/pull/495).
- some roles can now utilize an option `zabbix_repo_yum_gpgcheck` to enable/disable GPG check for YUM repository (https://github.com/ansible-collections/community.zabbix/pull/438).
- zabbix inventory - Enabled the usage of environment variables in zabbix inventory plugin.
- zabbix inventory plugin - can now use environment variables ZABBIX_SERVER, ZABBIX_USERNAME and ZABBIX_PASSWORD for connection purposes to the Zabbix API.
- zabbix_agent - `zabbix_agent_loadmodule` can also be configured with a list.
- zabbix_agent - new `zabbix_api_timeout` option.
- zabbix_agent - now supports DenyKeys configuration.
- zabbix_hostmacro - now supports creating macros of type secret and vault.
- zabbix_proxy (role) - new `zabbix_api_timeout` option.
- zabbix_proxy_info - new module that allows to retrieve information about configured Zabbix Proxies.
- zabbix_server - added support for TimescaleDB (https://github.com/ansible-collections/community.zabbix/pull/428).

Breaking Changes / Porting Guide
--------------------------------

- all roles now reference other roles and modules via their fully qualified collection names, which makes Ansible 2.10 minimum supported version for roles (See https://github.com/ansible-collections/community.zabbix/pull/477).

Bugfixes
--------

- all roles now support installing zabbix 4.0 version on Ubuntu 20.04.
- all roles now supports installations on Debian 11.
- zabbix inventory - Change default value for host_zapi_query from list "[]" to dict "{}".
- zabbix_action - should no longer fail with Zabbix version 5.4.
- zabbix_agent - `zabbix_win_install_dir` no longer ignored for zabbix_agentd.d and zabbix log directories.
- zabbix_agent - auto-recovery for Windows installation has been fixed (https://github.com/ansible-collections/community.zabbix/pull/470).
- zabbix_agent - deploying zabbix_agent2 under Windows should now be possible (Thanks to https://github.com/ansible-collections/community.zabbix/pull/433 and https://github.com/ansible-collections/community.zabbix/pull/453).
- zabbix_agent - fixed AutoPSK for Windows deployments (https://github.com/ansible-collections/community.zabbix/pull/450).
- zabbix_host - Fix error when updating hosts caused by Zabbix bug not returning the inventory_mode field for hosts(https://github.com/ansible-collections/community.zabbix/issues/385).
- zabbix_host - will not break when `tls_psk*` parameters are set with Zabbix version 5.4.
- zabbix_proxy (module) - now supports configuring `tls_psk*` parameters.
- zabbix_proxy (role) - TLS config should now properly configure certificates.
- zabbix_proxy (role) - should no longer fail on permission problems wren configured to use SQLite database and now installs correct package sqlite3 on Debian systems.
- zabbix_web - `zabbix_nginx_vhost_*` parameters are no longer ignored.
- zabbix_web - executing role with `--tags` should now correctly include distribution specific variables (https://github.com/ansible-collections/community.zabbix/pull/448).
- zabbix_web - now correctly restarts php-fpm service (https://github.com/ansible-collections/community.zabbix/pull/427).
- zabbix_web - permissions for accesing php-fpm socket has been fixed (See https://github.com/ansible-collections/community.zabbix/pull/426).

New Modules
-----------

- community.zabbix.zabbix_proxy_info - Gather information about Zabbix proxy

v1.4.0
======

Minor Changes
-------------

- all roles were updated to support Zabbix 5.4 release (https://github.com/ansible-collections/community.zabbix/pull/405)
- new inventory plugin zabbix_inventory (https://github.com/ansible-collections/community.zabbix/pull/373)
- new module plugin zabbix_globalmacro (https://github.com/ansible-collections/community.zabbix/pull/377)
- zabbix_agent - `zabbix_agent_src_reinstall` now defaults to `False` (https://github.com/ansible-collections/community.zabbix/pull/403)
- zabbix_agent - now supports setting AllowKey (https://github.com/ansible-collections/community.zabbix/pull/358)
- zabbix_globalmacros - it is now possible to create global macros using this module (https://github.com/ansible-collections/community.zabbix/pull/377).
- zabbix_inventory - Created Ansible - Zabbix inventory plugin to create dynamic inventory from Zabbix.
- zabbix_maintenance - it is now possible to target hosts by their technical name if it differs from the visible name
- zabbix_proxy - Add MySQL Python 3 package installation.
- zabbix_server - Add MySQL Python 3 package installation.
- zabbix_server - now supports setting StartLLDProcessors (https://github.com/ansible-collections/community.zabbix/pull/361)
- zabbix_user - now supports parameter `username` as an alternative to `alias` (https://github.com/ansible-collections/community.zabbix/pull/406)
- zabbix_user - removed some of the default values because a configuration should be changed only if specified as a parameter (https://github.com/ansible-collections/community.zabbix/pull/382).
- zabbix_web - now supports setting SAML certificates (https://github.com/ansible-collections/community.zabbix/pull/408)

Bugfixes
--------

- zabbix_agent - StatusPort will be configured only when `zabbix_agent2_statusport` is defined (https://github.com/ansible-collections/community.zabbix/pull/378)
- zabbix_agent - fixed issue preventing installation of zabbix-agent 4.2 on Ubuntu Focal 20.04 (https://github.com/ansible-collections/community.zabbix/pull/390)
- zabbix_agent - role will now configure correct port for hostinterface in Zabbix Server if `zabbix_agent2_listenport` is defined (https://github.com/ansible-collections/community.zabbix/pull/400)
- zabbix_agent - should no longer be failing on Windows platform due to re-running all of the tasks for the 2nd time (https://github.com/ansible-collections/community.zabbix/pull/376)
- zabbix_agent - should no longer fail while cleaning up zabbix_agent installation if Zabbix Agent2 is being used (https://github.com/ansible-collections/community.zabbix/pull/409)
- zabbix_agent - will no longer install zabbix_get package on Debian systems when `zabbix_agent_install_agent_only` is defined (https://github.com/ansible-collections/community.zabbix/pull/363)
- zabbix_host - fixed issue where module was idempotent when multiple host interfaces of the same type were present (https://github.com/ansible-collections/community.zabbix/pull/391)
- zabbix_proxy (role) - will no longer fail on proxy creation in Zabbix Server when TLS parameters are used (https://github.com/ansible-collections/community.zabbix/pull/388)
- zabbix_server - Removed the removal everything from /tmp directory command as it removes things that it shouldnt do.
- zabbix_template - first time import of template now works with Zabbix 5.4 (https://github.com/ansible-collections/community.zabbix/pull/407), please note that rerunning the task will fail as there are breaking changes in Zabbix 5.4 API that module not yet covers.
- zabbix_user - now works with Zabbix 5.4 (https://github.com/ansible-collections/community.zabbix/pull/406)

New Plugins
-----------

Inventory
~~~~~~~~~

- community.zabbix.zabbix_inventory - Zabbix Inventory Plugin

New Modules
-----------

- community.zabbix.zabbix_globalmacro - Create/update/delete Zabbix Global macros

v1.3.0
======

Release Summary
---------------

| Release date: 2021-03-20 | Last major release to support Zabbix server 3.X versions in plugins.

Minor Changes
-------------

- zabbix_agent - added support for installations on arm64 systems (https://github.com/ansible-collections/community.zabbix/pull/320).
- zabbix_proxy - now supports configuring StatsAllowedIP (https://github.com/ansible-collections/community.zabbix/pull/337).
- zabbix_server - added support for installtions on arm64 systems (https://github.com/ansible-collections/community.zabbix/pull/320).
- zabbix_web - added support for installtions on arm64 systems (https://github.com/ansible-collections/community.zabbix/pull/320).

Security Fixes
--------------

- zabbix_action - no longer exposes remote SSH command password used in operations, recovery & acknowledge operations to system logs (https://github.com/ansible-collections/community.zabbix/pull/345).
- zabbix_discovery_rule - no longer exposes SNMPv3 auth and priv passphrases to system logs (https://github.com/ansible-collections/community.zabbix/pull/345).
- zabbix_host - no longer exposes SNMPv3 auth and priv passphrases to system logs (https://github.com/ansible-collections/community.zabbix/pull/345).

Bugfixes
--------

- zabbix_action - now properly filters discovery rule checks by name (https://github.com/ansible-collections/community.zabbix/pull/349).
- zabbix_agent - corrected version for Windows agents (https://github.com/ansible-collections/community.zabbix/pull/316).
- zabbix_agent - fixed download URL for MacOS (https://github.com/ansible-collections/community.zabbix/pull/325).
- zabbix_server - now installs correct MySQL client packages on RHEL8 systems (https://github.com/ansible-collections/community.zabbix/pull/343).
- zabbix_template - fixed an issue with Python2 where module wouldn't decode Unicode characters (https://github.com/ansible-collections/community.zabbix/pull/322).
- zabbix_web - fixed installation of python3-libsemanage package RHEL7 and older systems (https://github.com/ansible-collections/community.zabbix/pull/330).
- zabbix_web - role should now correctly determine naming of PHP packages on older systems (https://github.com/ansible-collections/community.zabbix/pull/344).
- zabbix_web - updated default PHP version for Debian10 (https://github.com/ansible-collections/community.zabbix/pull/323).

v1.2.0
======

Release Summary
---------------

| Release date: 2021-01-11 | Last major release to support Zabbix server 3.X versions in plugins.

Minor Changes
-------------

- Updated the roles to support Zabbix 5.2.
- zabbix_agent - Added a new property `zabbix_agent_dont_detect_ip` when set to true, it won't detect the ips and no need to install the python module `netaddr`.
- zabbix_agent - Added parameter `zabbix_agent_package_remove` when set to `true` and `zabbix_agent2` is set to `true` it will uninstall the `zabbix-agent` service and package.
- zabbix_agent - added `zabbix_agent_install_agent_only` Will only install the Zabbix Agent package and not the `zabbix-sender` or `zabbix-get` packages.
- zabbix_template - Fixed to decode Unicode Escape of multibyte strings in an importing template data(https://github.com/ansible-collections/community.zabbix/pull/226).
- zabbix_user - added new parameters to set timezone and role_name for users (https://github.com/ansible-collections/community.zabbix/pull/260).
- zabbix_user - user_medias now defaults to None and is optional (https://github.com/ansible-collections/community.zabbix/pull/264).
- zabbix_web - added `zabbix_web_rhel_release` which enable scl on RHEL (https://github.com/ansible-collections/community.zabbix/pull/266).
- zabbix_web - quality of life improvements when using Nginx (https://github.com/ansible-collections/community.zabbix/pull/304).

Bugfixes
--------

- When installing the Zabbix packages, we disable all other yum repositories except the one for the Zabbix.
- zabbix_agent - Agent 2 also be able to use userparameters file.
- zabbix_agent - Also work on SLES 12 sp5
- zabbix_agent - Documented the property 'zabbix_proxy_ip' in the documentation.
- zabbix_agent - There was an task that wasn't able to use an http(s)_proxy environment while installing an package.
- zabbix_agent - Windows - Able to create PSK file
- zabbix_agent - Windows - Fixing download links to proper version/url
- zabbix_agent - Windows - Removal of not working property
- zabbix_agent - Zabbix packages were not able to install properly on Fedora. When the packages are installed, the version will be appended to the package name. This is eofr all RedHat related OS'es.
- zabbix_agent - fixed issue with zabbix_agent2_tlspsk_auto having no effect when using zabbix_agent2
- zabbix_agent - fixed issue with zabbix_api_create_hosts and TLS configuration when using zabbix_agent2, where zabbix_agent_tls* settings were used instead of zabbix_agent2_tls*
- zabbix_host - module will no longer require ``interfaces`` to be present when creating host  with Zabbix 5.2 (https://github.com/ansible-collections/community.zabbix/pull/291).
- zabbix_host - should no longer fail with 'host cannot have more than one default interface' error (https://github.com/ansible-collections/community.zabbix/pull/309).
- zabbix_proxy (role) - Added missing paragraph for the SQLite3 as database.
- zabbix_proxy (role) - The become option was missing in some essential tasks when installing the Zabbix Proxy with SQLite3 as database.
- zabbix_proxy (role) - Various documentation fixes removing the Zabbix Server and replaced it with actual Zabbix Proxy information.
- zabbix_proxy - Added new property 'zabbix_proxy_ip' to determine ip for host running the Zabbix Proxy.
- zabbix_proxy - The 'interface' option was missing when creating an Proxy via the API.
- zabbix_template - fixed documentation for ``macros`` argument (https://github.com/ansible-collections/community.zabbix/pull/296).
- zabbix_template - fixed encode error when using Python2 (https://github.com/ansible-collections/community.zabbix/pull/297).
- zabbix_template - fixed issue when importing templates to zabbix version. >= 5.2
- zabbix_template_info - fixed encode error when using Python2 (https://github.com/ansible-collections/community.zabbix/pull/297).
- zabbix_user - disable no_log warning for option override_password.
- zabbix_user - fixed issue where module couldn't create a user since Zabbix 5.2 (https://github.com/ansible-collections/community.zabbix/pull/260).
- zabbix_web - fixed issue Role cannot install Zabbix web 5.0 on RHEL 7 (https://github.com/ansible-collections/community.zabbix/issues/202).

v1.1.0
======

Release Summary
---------------

| Release date: 2020-10-22


Minor Changes
-------------

- all roles - added ``zabbix_{agent,web,server,proxy,javagateway}_conf_mode`` option for configuring a mode of the configuration file for each Zabbix service.
- zabbix_proxy (role) - added an option ``innodb_default_row_format`` for MariaDB/MySQL if it isn't set to ``dynamic``.
- zabbix_server - fixed installation output when using MySQL database to not print PostgreSQL.
- zabbix_user - ``passwd`` no longer required when ALL groups in ``usrgrps`` use LDAP as ``gui_access`` (see `#240 <https://github.com/ansible-collections/community.zabbix/issues/232>`_).
- zabbix_user - no longer requires ``usrgrps`` when ``state=absent`` (see `#240 <https://github.com/ansible-collections/community.zabbix/issues/232>`_).
- zabbix_web - added several configuration options for the PHP-FPM setup to configure the listen (socket) file.
- zabbix_web - added support for configuring Zabbix Web with Nginx, same way as with Apache.

Bugfixes
--------

- all roles - missing ``become`` set to ``true`` was added to each task that requires admin privleges.
- zabbix_agent - added new properties and updated documentation to allow for correct Zabbix Agent2 configuration.
- zabbix_agent - fixed bug where Nginx prevented Apache from working as it was part of the FPM configuration.

v1.0.0
======

Release Summary
---------------

| Release date: 2020-08-16


Minor Changes
-------------

- Added the possibility to configure the ``mode`` for the ``zabbix_{agent,server,proxy}_include`` directories.
- all roles - added the possibility to configure the ``mode`` for the ``yum`` repositories files in case it contains credentials.
- zabbix_agent - ``zabbix-sender`` and ``zabbix-get`` will not be installed when ``zabbix_repo`` is set to ``epel``, as they are not part of the repository.
- zabbix_agent - added option to change between HTTP/HTTPS with ``zabbix_repo_yum_schema``.
- zabbix_agent - can also install the zabbix-agent2 application when ``zabbix_agent2`` is set to ``true``.
- zabbix_proxy (role) - a user and group are created on the host when ``zabbix_repo`` is set to ``epel``.
- zabbix_proxy (role) - now supports ``startpreprocessors`` setting and encryption when connecting to database (see `#164 <https://github.com/ansible-collections/community.zabbix/pull/164>`_).
- zabbix_server - a user and group are created on the host when ``zabbix_repo`` is set to ``epel``.
- zabbix_server - added option to change between HTTP/HTTPS with ``zabbix_repo_yum_schema``.
- zabbix_server - now supports ``startpreprocessors`` setting and encryption when connecting to database (see `#164 <https://github.com/ansible-collections/community.zabbix/pull/164>`_).
- zabbix_web - a property is added ``zabbix_web_doubleprecision`` which currently is set to ``false`` for default installations. For new installations this should be set to ``True``. For upgraded installations, please read database `upgrade notes <https://www.zabbix.com/documentation/current/manual/installation/upgrade_notes_500>`_ (Paragraph "Enabling extended range of numeric (float) values") before enabling this option.
- zabbix_web - added option to change between HTTP/HTTPS with ``zabbix_repo_yum_schema``.
- zabbix_web - don't remove the files that Zabbix will install during installation when you don't want to configure a virtual host configuration.

Breaking Changes / Porting Guide
--------------------------------

- zabbix_javagateway - options ``javagateway_pidfile``, ``javagateway_listenip``, ``javagateway_listenport`` and ``javagateway_startpollers`` renamed to ``zabbix_javagateway_xyz`` (see `UPGRADE.md <https://github.com/ansible-collections/community.zabbix/blob/main/docs/UPGRADE.md>`_).

Bugfixes
--------

- all roles - a ``handler`` is configured when ``zabbix_http(s)_proxy`` is defined which will remove the proxy line from the repository files. This results that execution of the roles are not idempotent anymore.
- zabbix_proxy (role) - ``StartPreprocessors`` only works with version 4.2 or higher. When a lower version is used, it will not be added to the configuration.
- zabbix_proxy (role) - only install the sql files that needs to be executed for when ``zabbix_repo`` is set to ``epel``.
- zabbix_server - ``StartPreprocessors`` only works with version 4.2 or higher. When a lower version is used, it will not be added to the configuration.
- zabbix_server - only install the sql files that needs to be executed for when ``zabbix_repo`` is set to ``epel``.

v0.3.0
======

Release Summary
---------------

| Release date: 2020-07-26


Minor Changes
-------------

- All roles now **support Zabbix 5.0** and by default install this version (see `#131 <https://github.com/ansible-collections/community.zabbix/pull/131>`_ and `#121 <https://github.com/ansible-collections/community.zabbix/pull/121>`_).
- Roles will now install gnupg on Debian OS family if not present.
- zabbix_action - no longer requires ``password`` and ``ssh_*key_file`` parameters at the same time for ``remote_command`` operations of type SSH.
- zabbix_action - parameter ``ssh_auth_type`` for SSH ``remote_command`` operation now correctly identifies which other parameters are required.
- zabbix_discovery_rule - refactoring module to use ``module_utils`` classes and functions, adjust return values on success, add documentation for return values.
- zabbix_discovery_rule - refactoring the module to remove unnecessary variables and fix a variable typo.
- zabbix_mediatype - new options ``message_templates``, ``description`` and many more related to ``type=webhook``.
- zabbix_mediatype - now supports new ``webhook`` media type.

Bugfixes
--------

- zabbix_action - choices for the ``inventory`` paramter sub option in ``*operations`` arguments have been clarified to ``manual`` and ``automatic``.
- zabbix_action - fixed error on changed API fields ``*default_message`` and ``*default_subject`` for Zabbix 5.0 (see `#92 <https://github.com/ansible-collections/community.zabbix/pull/92>`_).
- zabbix_action - module will no longer fail when searching for global script provided to ``script_name`` parameter.
- zabbix_action - now correctly selects mediatype for the (normal|recovery|update) operations with Zabbix 4.4 and newer.
- zabbix_agent - fixed installation of agent on Windows to directories with spaces.
- zabbix_agent - role should no longer fail when looking for ``getenforce`` binary.
- zabbix_host - module will no longer convert context part of user macro to upper case.
- zabbix_proxy (role) - will now correctly install python3-libsemanage on RHEL OS family.
- zabbix_service - fixed the zabbix_service has no idempotency with Zabbix 5.0.
- zabbix_web - now no longer fails when rendering apache vhost template.

New Modules
-----------

- community.zabbix.zabbix_discovery_rule - Create/delete/update Zabbix discovery rules
- community.zabbix.zabbix_usergroup - Create/delete/update Zabbix user groups

v0.2.0
======

Release Summary
---------------

| Release date: 2020-06-15 

Minor Changes
-------------

- Documentation for roles moved to ``docs/`` sub-directory in the collection.
- New **role zabbix_agent** - previously known as dj-wasabi/zabbix-agent (also see `UPGRADE.md <https://github.com/ansible-collections/community.zabbix/blob/main/docs/UPGRADE.md>`_ for each role).
- New **role zabbix_javagateway** - previously known as dj-wasabi/zabbix-javagateway.
- New **role zabbix_proxy** - previously known as dj-wasabi/zabbix-proxy.
- New **role zabbix_server** - previously known as dj-wasabi/zabbix-server.
- New **role zabbix_web** - previously known as dj-wasabi/zabbix-web.
- zabbix_action - new alias ``update_operations`` for ``acknowledge_operations`` parameter.
- zabbix_host - ``macros`` now support new macro types ``text`` and ``secret``.
- zabbix_host - new option ``details`` (additional SNMP details) for ``interfaces`` parameter.
- zabbix_host - now supports Zabbix 5.0.
- zabbix_proxy (module) - now supports Zabbix 5.0.
- zabbix_screen - ``host_group`` parameter now accepts multiple groups.

Bugfixes
--------

- zabbix_action - documented ``value2`` parameter and ``notify_all_involved`` option.
- zabbix_maintenance - changing value of ``description`` parameter now actually updates maintenance's description.
- zabbix_template - is now able to perform ``state=dump`` when using ``ansible-playbook --check``.
- zabbix_template - no longer imports template from ``template_json`` or ``template_xml`` when using ``ansible-playbook --check``.

v0.1.0
======

Release Summary
---------------

| Release date: 2020-06-15


Minor Changes
-------------

- zabbix inventory plugin now no longer prints DeprecationWarning when used with Python3 due to SafeConfigParser.
- zabbix_action - arguments ``event_source`` and ``esc_period`` no longer required when ``state=absent``.
- zabbix_host - fixed inventory_mode key error, which occurs with Zabbix 4.4.1 or more (see `#65304 <https://github.com/ansible/ansible/issues/65304>`_).
- zabbix_host - was not possible to update a host where visible_name was not set in zabbix.
- zabbix_mediatype - Fixed to support zabbix 4.4 or more and python3 (see `#67693 <https://github.com/ansible/ansible/pull/67693>`_).
- zabbix_template - fixed error when providing empty ``link_templates`` to the module (see `#66417 <https://github.com/ansible/ansible/issues/66417>`_).
- zabbix_template - fixed invalid (non-importable) output provided by exporting XML (see `#66466 <https://github.com/ansible/ansible/issues/66466>`_).
- zabbix_user - Fixed an issue where module failed with zabbix 4.4 or above (see `#67475 <https://github.com/ansible/ansible/pull/67475>`_).

Deprecated Features
-------------------

- zabbix_proxy (module) - deprecates ``interface`` sub-options ``type`` and ``main`` when proxy type is set to passive via ``status=passive``. Make sure these suboptions are removed from your playbook as they were never supported by Zabbix in the first place.

Bugfixes
--------

- zabbix_action - allow str values for ``esc_period`` options (see `#66841 <https://github.com/ansible/ansible/pull/66841>`_).
- zabbix_action - no longer requires ``esc_period`` and ``event_source`` arguments when ``state=absent``.
- zabbix_host - now supports configuring user macros and host tags on the managed host (see `#66777 <https://github.com/ansible/ansible/pull/66777>`_).
- zabbix_host_info - ``host_name`` based search results now include host groups.
- zabbix_hostmacro - ``macro_name`` now accepts macros in zabbix native format as well (e.g. ``{$MACRO}``).
- zabbix_hostmacro - ``macro_value`` is no longer required when ``state=absent``.
- zabbix_proxy (module) - ``interface`` sub-options ``type`` and ``main`` are now deprecated and will be removed in community.general 3.0.0. Also, the values passed to ``interface`` are now checked for correct types and unexpected keys.
- zabbix_proxy (module) - added option proxy_address for comma-delimited list of IP/CIDR addresses or DNS names to accept active proxy requests from.
- zabbix_template - add new option omit_date to remove date from exported/dumped template (see `#67302 <https://github.com/ansible/ansible/pull/67302>`_).
- zabbix_template - adding new update rule templateLinkage.deleteMissing for newer zabbix versions (see `#66747 <https://github.com/ansible/ansible/pull/66747>`_).
- zabbix_template_info - add new option omit_date to remove date from exported/dumped template (see `#67302 <https://github.com/ansible/ansible/pull/67302>`_).
