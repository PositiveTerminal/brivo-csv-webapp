import os
import shutil
import unittest
from datetime import datetime as DateTime
from datetime import timedelta as TimeDelta

import lxml
import lxml.html

from app.util import EnvKeys, MISSING_ENV_VALUE, random_string
from app.webapp import create_app


def get_flash(rsp):
    h = lxml.html.fromstring(rsp.text)
    pars = h.xpath('.//div[@id="flashes"]//ul/li')
    texts = [p.text.strip() for p in pars]
    return texts


class WebAppTestBase(unittest.TestCase):
    def _login(self, sess):
        sess["username"] = "testuser"
        sess["token_object"] = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_after": DateTime.now() + TimeDelta(seconds=60),
        }

    def _logout(self, sess):
        sess.pop("username", None)
        sess.pop("password", None)

    def _reset_config(self):
        for var in EnvKeys.all():
            self.app.config[var] = MISSING_ENV_VALUE

    def _create_config(self):
        self.app.config[EnvKeys.APIKEY] = "test-apikey-123"
        self.app.config[EnvKeys.CLIENT_ID] = "test-client-id-456"
        self.app.config[EnvKeys.CLIENT_SECRET] = "test-client-secret-789"
        self.app.config[EnvKeys.REDIRECT_URI] = "http://some.random.url/callback"

    def tearDown(self):
        if (path := self.app.config[EnvKeys.WRITABLE_BASE_PATH]) != MISSING_ENV_VALUE:
            shutil.rmtree(path)

    def setUp(self):
        # self.test_client.testing = True
        self._writable_dir = os.path.join("/tmp", random_string(8))
        self.app = create_app()
        self.app.config["TESTING"] = True

        self.test_client = self.app.test_client()
        self._create_config()
