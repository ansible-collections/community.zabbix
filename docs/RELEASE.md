# Release cycle and versioning

## Versioning
Versioning is using SemVer (X.Y.Z):
- The X is a **major version** and is incremented when:
    - Support for older Zabbix versions is removed.
    - Support for older Ansible versions is removed.
    - Support for older Python versions is removed.
    - Modules, roles or plugins are removed.
    - Module or role functionality is removed.
    - Other breaking changes or backward-incompatible changes are introduced.

- The Y is a **minor version** and is incremented when:
    - Support for new Zabbix versions is added.
    - Support for new Ansible versions is added.
    - Support for new Python versions is added.
    - A new module, role, plugin, etc., is added.
    - New features are introduced to modules, roles, plugins.
    - A functionality of components is adjusted in a backward-compatible way.

- The Z is a **patch version** and is incremented when:
    - Bugs are fixed in a backward-compatible way.
    - Documentation fixes and smaller changes are introduced.
## Releases
Release dates are not fixed. Instead, they will be discussed at the beginning of each month following this guideline:
- The version increment will depend on the content that will be included in the release, as discussed in the *Versioning* section.
- New collection releases may be a result of this discussion if necessary.
- There may be several releases during the month if needed.
## Collection support
The latest release of the community.zabbix is always supported.
Older releases, which are included in the still supported Ansible versions, may obtain occasional backports or bug fixes when necessary. [1]

[1] [Collection versioning requirements](https://github.com/ansible-collections/overview/blob/main/collection_requirements.rst#versioning-and-deprecation)
## Branches
Branch *main* always holds the code for the latest supported release.
New branch *stable-X.Y* is pushed before starting a new *major (X+1)* version development in the main branch.

The *stable-X.Y* branch provides a way to merge any necessary backports and release bug fixes for older major versions of this collection while they are still included in currently supported ansible releases.
> For example, if the current version of the collection is *1.3.2* and a new version *2.0.0* is being released, the branch *stable-1.Y* should be pushed prior to the release, matching the last commit that was included with the *1.3.2* release.

## Merging
Merging follows this guideline:
- *Main branch* (previously master branch) is the current branch.
- *stable-X.Y* is a separate branch used to fix issues in older supported collection releases.
- There should be a separate branch for each contribution.
- There should be a separate pull request for each version increment.
