from unittest.mock import MagicMock
from plugins.httpapi.zabbix import HttpApi


def test_password_changed_for_user_should_login_for_api_user():
    # Given a Zabbix httpapi
    connection = MagicMock()
    httpapi = HttpApi(connection=connection)
    # And the API user is "remote"
    api_username = "remote"
    connection.get_option.side_effect = {'remote_user': api_username}.get
    # And the new password is "mynewpassword"
    new_pass = "mynewpassword"
    httpapi.login = MagicMock()

    # When calling password_changed_for_user() with the API user
    httpapi.password_changed_for_user(api_username, new_pass)

    # Then the login method should be called
    httpapi.login.assert_called_once_with(api_username, new_pass)


def test_password_changed_for_user_should_not_login_for_non_api_user():
    # Given a Zabbix httpapi
    connection = MagicMock()
    httpapi = HttpApi(connection=connection)
    # And the API user is "remote"
    api_username = "remote"
    connection.get_option.side_effect = {'remote_user': api_username}.get
    httpapi.login = MagicMock()

    # When calling password_changed_for_user() with a user
    # other than the API user
    httpapi.password_changed_for_user("not_the_mamaaaa", "mynewpassword")

    # Then the login method should not be called
    httpapi.login.assert_not_called()
