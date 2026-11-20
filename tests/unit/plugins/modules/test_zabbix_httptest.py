# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
import json
from unittest.mock import MagicMock

import pytest

from ansible.module_utils import basic
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.community.zabbix.plugins.module_utils import base
from ansible_collections.community.zabbix.plugins.modules import zabbix_httptest


class ModuleFailure(Exception):
    pass


@pytest.fixture
def httptest():
    def fail_json(**kwargs):
        raise ModuleFailure(kwargs['msg'])

    instance = zabbix_httptest.Httptest.__new__(zabbix_httptest.Httptest)
    instance._module = MagicMock()
    instance._module.check_mode = False
    instance._module.fail_json.side_effect = fail_json
    instance._zbx_api_version = '7.0.32'
    instance._zapi = MagicMock()
    return instance


def validated(params):
    result = ArgumentSpecValidator(dict(params=dict(type='dict', options=zabbix_httptest.httptest_argument_spec()))).validate(dict(params=params))
    assert not result.error_messages, result.error_messages
    return result.validated_parameters['params']


@pytest.mark.parametrize('codes,expected', [
    (['200', '201'], '200,201'), (['200-299', '301'], '200-299,301'),
    ([200, 201], '200,201'), (['200', '300-399'], '200,300-399'), ([], ''),
])
def test_status_code_lists_are_converted_to_api_strings(httptest, codes, expected):
    params = validated(dict(steps=[dict(name='Test', url='https://example.com', status_codes=codes)]))
    httptest.sanitize_params('Scenario', params)
    assert params['steps'][0]['status_codes'] == expected


@pytest.mark.parametrize('value', [{}, [None]])
def test_invalid_status_codes_are_rejected_before_api_access(run_module, value):
    result, api = run_module(dict(steps=[dict(name='Test', url='https://example.com', status_codes=value)]))
    assert result['failed']
    assert 'status_codes' in result['msg']
    api.api_version.assert_not_called()
    api.httptest.create.assert_not_called()
    api.httptest.update.assert_not_called()


@pytest.mark.parametrize('value,expected', [('none', 0), ('basic', 1), ('ntlm', 2), ('kerberos', 3), ('digest', 4)])
def test_authentication_choices_are_converted_to_api_values(httptest, value, expected):
    params = validated(dict(authentication=value))
    httptest.sanitize_params('Scenario', params)
    assert params['authentication'] == expected


@pytest.mark.parametrize('value', ['kerberos', 'digest'])
def test_new_authentication_is_rejected_on_older_api(httptest, value):
    httptest._zbx_api_version = '6.4.21'
    with pytest.raises(ModuleFailure, match='require Zabbix 7.0'):
        httptest.sanitize_params('Scenario', validated(dict(authentication=value)))
    httptest._zapi.httptest.create.assert_not_called()
    httptest._zapi.httptest.update.assert_not_called()


@pytest.mark.parametrize('field', ['status', 'authentication', 'retrieve_mode'])
@pytest.mark.parametrize('value', ['unsupported', 0, '4', False, True, 1.0, {}, []])
def test_invalid_enum_choices_are_rejected_before_api_access(run_module, field, value):
    params = {field: value} if field != 'retrieve_mode' else dict(steps=[dict(name='Test', url='https://example.com', retrieve_mode=value)])
    result, api = run_module(params)
    assert result['failed']
    assert field in result['msg']
    api.api_version.assert_not_called()
    api.httptest.create.assert_not_called()
    api.httptest.update.assert_not_called()


@pytest.mark.parametrize('value,expected', [('only_body', 0), ('only_headers', 1), ('headers_and_body', 2)])
def test_retrieve_mode_choices_are_converted_to_api_values(httptest, value, expected):
    params = validated(dict(steps=[dict(name='Test', url='https://example.com', retrieve_mode=value)]))
    httptest.sanitize_params('Scenario', params)
    assert params['steps'][0]['retrieve_mode'] == expected


@pytest.mark.parametrize('value,expected', [('enabled', 0), ('disabled', 1)])
def test_status_choices_are_converted_to_api_values(httptest, value, expected):
    params = validated(dict(status=value))
    httptest.sanitize_params('Scenario', params)
    assert params['status'] == expected


@pytest.mark.parametrize('enabled,expected', [(True, 0), (False, 1)])
def test_legacy_enabled_option_still_overrides_status(httptest, enabled, expected):
    params = validated(dict(enabled=enabled, status='disabled' if enabled else 'enabled'))
    httptest.sanitize_params('Scenario', params)
    assert params['status'] == expected
    assert 'enabled' not in params


@pytest.mark.parametrize('spelling', ['query_field', 'query_fields'])
def test_query_fields_alias(httptest, spelling):
    fields = [dict(name='query', value='')]
    params = validated(dict(steps=[dict(name='Test', url='https://example.com', **{spelling: fields})]))
    httptest.sanitize_params('Scenario', params)
    assert params['steps'][0]['query_fields'] == fields
    assert 'query_field' not in params['steps'][0]


@pytest.mark.parametrize('posts', ['{"key":"value"}', '', [dict(name='key', value='')], []])
def test_raw_and_form_posts_are_preserved(httptest, posts):
    params = validated(dict(steps=[dict(name='Test', url='https://example.com', posts=posts)]))
    httptest.sanitize_params('Scenario', params)
    assert params['steps'][0]['posts'] == posts


@pytest.mark.parametrize('posts', [123, {}, [dict(name='missing_value')]])
def test_invalid_posts_fail_cleanly(httptest, posts):
    with pytest.raises(ModuleFailure, match='posts must be'):
        httptest.sanitize_params('Scenario', dict(steps=[dict(name='Test', url='https://example.com', posts=posts)]))


def test_unset_options_are_omitted_without_dropping_empty_values(httptest):
    params = validated(dict(steps=[dict(name='Test', url='https://example.com', posts='', required='')]))
    httptest.sanitize_params('Scenario', params)
    assert set(params) == {'name', 'steps'}
    assert params['steps'][0] == dict(name='Test', url='https://example.com', no=1, posts='', required='')


def test_native_names_and_false_values_survive_validation(httptest):
    params = validated(dict(delay='0', retries=3, http_user='', http_password='', status='enabled',
                            verify_peer=False, verify_host=False,
                            steps=[dict(name='Test', url='https://example.com', retrieve_mode='headers_and_body')]))
    httptest.sanitize_params('Scenario', params)
    assert params['delay'] == '0'
    assert params['retries'] == 3
    assert params['http_user'] == params['http_password'] == ''
    assert params['status'] == params['verify_host'] == params['verify_peer'] == 0
    assert params['steps'][0]['retrieve_mode'] == 2


def test_unknown_parameters_are_rejected():
    result = ArgumentSpecValidator(dict(params=dict(type='dict', options=zabbix_httptest.httptest_argument_spec()))).validate(
        dict(params=dict(not_an_api_parameter=True))
    )
    assert result.error_messages


def test_comparison_ignores_server_metadata_but_detects_step_changes(httptest):
    desired = dict(steps=[dict(no=1, name='Step', url='https://example.com', retrieve_mode=0)])
    current = dict(httptestid='1', steps=[dict(no='1', name='Step', url='https://example.com', retrieve_mode='0', httpstepid='2')])
    assert httptest.params_equal(desired, current)
    desired['steps'][0]['url'] = 'https://example.org'
    assert not httptest.params_equal(desired, current)


def test_tag_order_is_ignored_but_values_and_removal_are_detected(httptest):
    desired = dict(tags=[dict(tag='a', value=''), dict(tag='b', value='two')])
    current = dict(tags=[dict(tag='b', value='two'), dict(tag='a', value='')])
    assert httptest.params_equal(desired, current)
    current['tags'][0]['value'] = 'changed'
    assert not httptest.params_equal(desired, current)
    assert not httptest.params_equal(dict(tags=[]), current)


def test_header_order_and_duplicate_fields_are_preserved(httptest):
    first = dict(name='X-Header', value='first')
    second = dict(name='X-Header', value='second')
    assert not httptest.params_equal(dict(headers=[first, second]), dict(headers=[second, first]))


def test_explicit_step_numbers_and_partial_step_updates(httptest):
    params = validated(dict(steps=[
        dict(httpstepid='12', no=2, required='new text'),
        dict(name='First', url='https://example.com', no=1),
    ]))
    httptest.sanitize_params('Scenario', params)
    assert params['steps'][0] == dict(httpstepid='12', no=2, required='new text')
    current = dict(steps=[dict(name='First', url='https://example.com', no='1'),
                          dict(httpstepid='12', name='Second', url='https://example.org', no='2', required='new text')])
    assert httptest.params_equal(params['steps'], current['steps'], 'steps')


@pytest.mark.parametrize('numbers', [[0], [1, 1]])
def test_invalid_step_numbers_fail_cleanly(httptest, numbers):
    params = validated(dict(steps=[
        dict(name='Step %s' % index, url='https://example.com', no=number)
        for index, number in enumerate(numbers)
    ]))
    with pytest.raises(ModuleFailure, match='positive and unique'):
        httptest.sanitize_params('Scenario', params)


@pytest.fixture
def run_module(monkeypatch, capsys):
    def run(params, current=None, check_mode=False):
        api = MagicMock()
        api.api_version.return_value = '7.0.32'
        api.host.get.return_value = [dict(hostid='10')]
        api.template.get.return_value = [dict(templateid='20')]
        api.httptest.get.side_effect = lambda query: (
            [deepcopy(current)] if current is not None and query['filter']['name'] == current['name'] else []
        )
        api.httptest.create.return_value = dict(httptestids=['1'])
        api.httptest.update.return_value = dict(httptestids=['1'])
        monkeypatch.setattr(base, 'ZabbixApiRequest', lambda module: api)
        args = dict(name='Scenario', host_name='Host', params=params, _ansible_check_mode=check_mode)
        monkeypatch.setattr(basic, '_ANSIBLE_ARGS', json.dumps(dict(ANSIBLE_MODULE_ARGS=args)).encode())
        with pytest.raises(SystemExit):
            zabbix_httptest.main()
        return json.loads(capsys.readouterr().out), api
    return run


@pytest.mark.parametrize('check_mode', [False, True])
def test_unchanged_run_never_updates_api(run_module, check_mode):
    result, api = run_module(dict(interval='1m'), dict(httptestid='1', name='Scenario', delay='1m'), check_mode)
    assert not result['changed']
    assert result['result'] == [dict(httptestids=['1'])]
    api.httptest.update.assert_not_called()


@pytest.mark.parametrize('params,current', [
    (dict(tags=[dict(tag='service', value='new')]), dict(tags=[dict(tag='service', value='old')])),
    (dict(steps=[dict(name='Step', url='https://example.org')]), dict(steps=[dict(no='1', name='Step', url='https://example.com')])),
])
@pytest.mark.parametrize('check_mode', [False, True])
def test_related_object_changes_are_predicted_before_writing(run_module, params, current, check_mode):
    current.update(httptestid='1', name='Scenario')
    result, api = run_module(params, current, check_mode)
    assert result['changed']
    assert api.httptest.update.call_count == (0 if check_mode else 1)
    request = api.httptest.get.call_args.args[0]
    assert request['selectSteps'] == request['selectTags'] == 'extend'


@pytest.mark.parametrize('password_option', ['http_password', 'password'])
def test_credentials_are_masked_in_validation_errors(run_module, password_option):
    result, api = run_module({password_option: 'private-secret', 'authentication': 'invalid'})
    assert result['failed']
    assert 'private-secret' not in json.dumps(result)
    api.httptest.create.assert_not_called()


@pytest.mark.parametrize('legacy', [False, True])
def test_api_names_and_legacy_aliases_create_identical_payloads(run_module, legacy):
    options = ('interval', 'attempts', 'username', 'password') if legacy else ('delay', 'retries', 'http_user', 'http_password')
    params = dict(zip(options, ('5m', 2, 'scenario-user', 'scenario-secret')))
    params['steps'] = [dict(name='Step', url='https://example.com')]
    result, api = run_module(params)
    assert result['changed']
    api.httptest.create.assert_called_once_with(dict(
        name='Scenario', hostid='10', delay='5m', retries=2, http_user='scenario-user', http_password='scenario-secret',
        steps=[dict(name='Step', url='https://example.com', no=1)],
    ))


@pytest.mark.parametrize('name_option', ['name', 'new_name'])
@pytest.mark.parametrize('check_mode', [False, True])
def test_native_and_legacy_rename_options(run_module, name_option, check_mode):
    result, api = run_module({name_option: 'Renamed'}, dict(httptestid='1', name='Scenario'), check_mode)
    assert result['changed']
    if check_mode:
        api.httptest.update.assert_not_called()
    else:
        api.httptest.update.assert_called_once_with(dict(name='Renamed', httptestid='1'))


@pytest.mark.parametrize('name_option', ['name', 'new_name'])
def test_repeated_rename_is_unchanged(run_module, name_option):
    result, api = run_module({name_option: 'Renamed'}, dict(httptestid='1', name='Renamed'))
    assert not result['changed']
    api.httptest.create.assert_not_called()
    api.httptest.update.assert_not_called()


def test_uuid_requires_a_template(run_module):
    result, api = run_module(dict(uuid='a' * 32))
    assert result['failed']
    assert 'uuid is only supported' in result['msg']
    api.httptest.create.assert_not_called()
