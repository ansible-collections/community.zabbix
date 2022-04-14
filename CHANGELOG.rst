==============================
community.zabbix Release Notes
==============================

.. contents:: Topics


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
- zabbix_agent - Check if 'firewalld' exist and is running when handler is executed.
- zabbix_agent - Install the correct Python libxml2 package on SLES15
- zabbix_agent - Move inclusion of the apache.yml tasks to later stage during execution of role.
- zabbix_agent - Prepare for Zabbix 6.0.
- zabbix_agent - Specify a minor version with zabbix_agent_version_minor for RH systems.
- zabbix_agent - There was no way to configure a specific type for the macro.
- zabbix_agent - Use multiple aliases in the configuration file with ``zabbix_agent_zabbix_alias`` or ``zabbix_agent2_zabbix_alias``.
- zabbix_maintenance - added new module parameter `tags`, which allows configuring Problem Tags on maintenances.
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
