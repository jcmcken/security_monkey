import security_monkey.login_managers
from security_monkey.tests import SecurityMonkeyTestCase

class LoginProviderTestCase(SecurityMonkeyTestCase):
    def test_default_manager(self):
        assert security_monkey.login_managers.get(None) is None

    def test_header_manager(self):
        assert security_monkey.login_managers.get('header') == \
            security_monkey.login_managers.create_header_login_manager
