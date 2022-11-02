# Contribution guidelines

**Table of contents**

- [Contribution guidelines](#contribution-guidelines)
  * [Contributing](#contributing)
  * [Coding guidelines](#coding-guidelines)
    + [Zabbix roles](#zabbix-roles)
    + [Zabbix modules](#zabbix-modules)
  * [Testing and Development](#testing-and-development)
    + [Testing Zabbix roles](#testing-zabbix-roles)
    + [Testing Zabbix modules](#testing-zabbix-modules)
- [Additional information](#additional-information)
  * [Virtualenv](#virtualenv)
  * [Links](#links)

Thank you very much for taking time to improve this Ansible collection. We appreciate your every contribution. Please make sure you are familiar with the content presented in this document to avoid any delays during reviews or merge.

Please note that this project is released with following codes of conduct and by participating in the project you agree to abide by them:
* [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md)
* [Community Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html)

If you are interested in joining us as a maintainer, please open an issue.

## Contributing

1. Fork this repository with community Zabbix collection.
2. Create a new branch and apply your changes to it. In addition to that:
    1. Ensure that any changes you introduce to this collection are reflected in the documentation.
    2. Ensure that your PR contains valid [changelog fragment](https://docs.ansible.com/ansible/devel/community/development_process.html#changelogs).
    3. Include tests with your contribution to ensure that future pull requests will not break your functionality.
    4. Make sure that tests succeed.
3. Push the branch to your forked repository.
4. Submit a new pull request into this collection.

*Notes:*
* Pull requests that fail during the tests will not be merged. If you have trouble narrowing down cause of a failure and would like some help, do not hesitate to ask for it in comments.
* If you plan to propose an extensive feature or breaking change, please open an issue first. This allows collection maintainers to comment on such change in advance and avoid possible rejection of such contribution.

## Coding guidelines

Style guides are important because they ensure consistency in the content, look, and feel of a book or a website. Any contributions to this collection must adhere to the following rules:

* [Ansible style guide](http://docs.ansible.com/ansible/latest/dev_guide/style_guide/).
* Use "Ansible" when referring to the product and ``ansible`` when referring to the command line tool, package and so on.

### Zabbix roles

* Playbooks should be written in multi-line YAML format using ``key: value``.
  * The form ``key=value`` is suitable for ``ansible`` ad-hoc execution, not for ``ansible-playbook``.
* Every task should always have a ``name:`` keyword associated with it.

### Zabbix modules

These rules are required for any contributions proposing a new Zabbix module or updating an existing one. Modules should:

* Be compatible with [currently supported Zabbix releases](https://www.zabbix.com/life_cycle_and_release_policy).
* Include the same set of general options as other Zabbix modules:
  * In `DOCUMENTATION` block via `extends_documentation_fragment` keyword.
  * In module `argument_spec` as a set of module parameters.
* Implement proper logout mechanism as other modules do.
* Use the same version of `zabbix-api` library as defined in collection requirements.
* Comply with [Ansible module best practices](https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_best_practices.html).

## Testing and Development

It is recommended to use Docker for the testing as this repository is utilizing it for its own CI. Read [Docker installation guide](https://docs.docker.com/install/) for more information.

Make sure you start your work on the current state of the repository with `main` branch up to date. The best way to both try new changes and run shipped tests is by cloning the repository to Ansible project:

```bash
cd <ANSIBLE-PROJECT>/
mkdir -p collections/ansible_collections/community
git clone git@github.com:<USERNAME>/community.zabbix.git collections/ansible_collections/community/zabbix
```

Functionality can be verified by looking at the documentation of a module:
```bash
ansible-doc community.zabbix.zabbix_host
```

Once this is done, you can reference modules and roles from testing playbook likes this:

```yaml
- hosts: myserver
  roles:
    - role: community.zabbix.zabbix_agent
      zabbix_agent_server: 10.0.0.1
      ...

  tasks:
    - name: Configure Zabbix host
      community.zabbix.zabbix_host:
        server_url: http://10.0.0.1/
        ...
      delegate_to: localhost
```

### Testing Zabbix roles

*This section is subject to change as our CI regarding roles is being reworked and may not work for you right now!*

Roles make use of [Molecule](https://molecule.readthedocs.io/en/latest/) to verify and test the execution of each role. In order to start testing with Molecule, you need to install the required dependencies. Requirements file can be found in the root of the [dj-wasabi/ansible-ci-base](https://github.com/dj-wasabi/ansible-ci-base) repository.

It is recommended to create a [new Python virtual environment](#virtualenv) for this to not clutter your global Python installation. First, install the dependencies:

```bash
pip install -r requirements.txt
```

Note that Docker is required when testing roles as Molecule is configured to use it. Once everything is installed, validate your role changes with:

```bash
molecule test
```

### Testing Zabbix modules

Modules are tested via `ansible-test` command. Configurations for integration and sanity tests for the command are contained within `tests` directory. Refer to the [official documentation](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html) for introduction to module integration testing within Ansible. Please note that this may fail if you get your directory structure wrong. If this happens, please see the start of [Testing and Development](#testing-and-development) regarding the placement of the collection.

Running test suites locally requires a few dependencies to be installed. Same as for the roles, it is recommended to use [Python virtual environment](#virtualenv):

```bash
pip install docker-compose
```

Integration test suite for modules can be run with the commands below:

```bash
export zabbix_version=X.Y
docker-compose up -d
ansible-test integration -v --color --continue-on-error --diff [test_zabbix_xyz]
docker-compose down
```
*Notes*:
* `zabbix_version=X.Y` will be expanded to Docker image `ubuntu-X.Y-latest`
* Details for both variables and values that are in use can be read from [ansible-test.yml](.github/workflows/ansible-test.yml).

Sanity test suite for the modules can be run with the commands:

```bash
ansible-test sanity -v --color --docker --python 3.6
```

# Additional information

## Virtualenv

It is recommended to use virtualenv for development and testing work to prevent any conflicting dependencies with other projects.

A few resources describing virtualenvs:

* http://thepythonguru.com/python-virtualenv-guide/
* https://realpython.com/python-virtual-environments-a-primer/
* https://www.dabapps.com/blog/introduction-to-pip-and-virtualenv-python/

## Links

* [Ansible](https://www.ansible.com/)
* [Ansible style guide](http://docs.ansible.com/ansible/latest/dev_guide/style_guide/)
* [Ansible module best practices](https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_best_practices.html)
* [Integration testing with `ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html)
* [Docker installation guide](https://docs.docker.com/install/)
* [Molecule](https://molecule.readthedocs.io/)
* [Molecule V2 with your own role](https://werner-dijkerman.nl/2017/09/05/using-molecule-v2-to-test-ansible-roles/)
* [dj-wasabi/ansible-ci-base](https://github.com/dj-wasabi/ansible-ci-base)
* [Current Zabbix releases](https://www.zabbix.com/life_cycle_and_release_policy)

**End note**: Have fun making changes. If a feature helps you, others may find it useful as well and we will be happy to merge it.
