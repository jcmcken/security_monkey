import security_monkey.login
from security_monkey.tests import SecurityMonkeyTestCase

class LoginProviderTestCase(SecurityMonkeyTestCase):
    def test_default_provider(self):
        assert security_monkey.login.get_provider(None) is None

    def test_header_provider(self):
        assert security_monkey.login.get_provider('header') == \
            security_monkey.login.create_header_login_manager
