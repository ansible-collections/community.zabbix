# Contributing to this role

**Table of content**

- [Contributing to this role](#contributing-to-this-role)
  * [Contributing](#contributing)
  * [(local) Development](#-local--development)
    + [Requirements](#requirements)
    + [Execution](#execution)
- [Other](#other)
  * [Virtualenv](#virtualenv)
  * [Links](#links)

Thank you very much for making time to improve this Ansible role.

## Contributing

Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms. [Contributor Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

1. Fork the repo

2. Create a branch and apply your changes to this branch.

    a. Make sure you have updated the documentation when adding new variables;
    
    b. Don't forget to add/update tests so we can test the functionality during each Pull Request;
    
    c. Make sure the tests will succeed.

3. Push the branch to your fork and submit a pull request.

**Note**

Pull Requests that fails during the tests will not be merged.

## Coding Guidelines

Style guides are important because they ensure consistency in the content, look, and feel of a book or a website.

* [Ansible Style Guide](http://docs.ansible.com/ansible/latest/dev_guide/style_guide/)
* It's "Ansible" when referring to the product and ``ansible`` when referring to the command  line tool, package, etc
* Playbooks should be written in multi-line YAML with ``key: value``. The form ``key=value`` is only for ``ansible`` ad-hoc, not for ``ansible-playbook``.
* Tasks should always have a ``name:``

## (local) Development

This role make use of Molecule to test the execution of the role and verificate it. In the root of the repository, a file named `requirements.txt` exists and contains the versions used by the tests.

### Requirements

You can install them with the following command:

```
pip install -r requirements.txt
```

Once the dependencies are installed, please install Docker as Molecule is configured in this repository to create Docker containers. See [this](https://docs.docker.com/install/) link to install Docker on your system.

### Execution

Once everything is installed, you can validate your changes by executing:
```
molecule test
```

It should run without any issues.

# Other

## Virtualenv

Suggestion is to create a virtualenv so you won't have issues with other projects.

Some web pages describing for virtual env:

* http://thepythonguru.com/python-virtualenv-guide/
* https://realpython.com/python-virtual-environments-a-primer/
* https://www.dabapps.com/blog/introduction-to-pip-and-virtualenv-python/

## Links

[Molecule](https://molecule.readthedocs.io/)

[Ansible](https://www.ansible.com/)

[Molecule V2 with your own role](https://werner-dijkerman.nl/2017/09/05/using-molecule-v2-to-test-ansible-roles/)

**End note**: Have fun making changes. If a feature helps you, then others find it helpful too and I will happily have it merged. 
