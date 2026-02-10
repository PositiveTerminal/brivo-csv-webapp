import os
import time
import unittest
from random import randint
from unittest.mock import MagicMock, patch

from flask import session
from mock import AsyncMock

from app.processing import remove_old_processed_files
from app.util import EnvKeys, MISSING_ENV_VALUE, PathNames, valid_config_found
from app.webapp import writable_path
from tests.webapp_base import WebAppTestBase, get_flash


class WebAppTestCase(WebAppTestBase):
    def test_no_valid_config_found(self):
        # push app context so current_app is available
        with self.app.test_request_context('/'), self.app.test_client() as _:
            self._reset_config()
            self.assertFalse(valid_config_found())

    def test_valid_config_found(self):
        # push app context so current_app is available
        with self.app.test_request_context('/'), self.app.test_client() as _:
            self.assertTrue(valid_config_found())

    def test_index_route_config_missing(self):
        # Simulate the condition where valid_config_found is False
        self._reset_config()
        response = self.test_client.get('/', follow_redirects=True)
        self.assertEqual(response.request.path, "/login")
        self.assertTrue(get_flash(response)[0].startswith("Missing config variables"))

    def test_index_without_login(self):

        response = self.test_client.get('/', follow_redirects=True)
        self.assertEqual(response.request.path, "/login")
        self.assertEqual(response.history[0].status_code, 302)
        self.assertEqual(response.history[0].headers["Location"], "/login")
        self.assertIn(b'Login', response.data)
        self.assertNotIn("Missing config variables", response.text)

    def test_index(self):
        with self.app.test_request_context('/'), self.app.test_client() as c:
            with c.session_transaction() as sess:
                self._login(sess)
            response = c.get('/', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Upload', response.data)

    @patch("app.webapp.BrivoApiContext", return_value=AsyncMock())
    def test_selftest(self, mock_get_brivo):
        mock_get_brivo.return_value.__aenter__.return_value.healthcheck.return_value = MagicMock(status=200)

        with self.app.test_request_context('/'), self.app.test_client() as c:
            with c.session_transaction() as sess:
                self._login(sess)
                sess["username"] = "test"
                sess["password"] = "testpass"

            response = c.get("/test_api", follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("API Test passed - code: 200", response.text)
            self.assertIn("<li>Uploads writable</li>", response.text)
            self.assertIn("<li>Sessions writable</li>", response.text)
            self.assertIn("<li>Processing writable</li>", response.text)

    def test_logout(self):
        with self.app.test_request_context('/'), self.app.test_client() as c:
            with c.session_transaction() as _:
                pass
            response = c.get('/logout', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Login', response.data)
            self.assertIn("Logged out", get_flash(response)[0])
            self.assertNotIn("username", session)
            self.assertNotIn("password", session)

    @patch("app.blueprints.auth.BrivoApiContext")
    def test_login(self, mock_get_brivo):
        mock_get_brivo.return_value.__aenter__.return_value.get_access_token.return_value = MagicMock(status=200)

        with self.app.test_request_context('/'), self.app.test_client() as c:
            with c.session_transaction() as _:
                pass
            response = c.get('/login', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_remove_old_processed_files(self):
        def _create_n_files(n, atime, mtime):
            ret = []
            for i in range(n):
                path = os.path.join(writable_path(PathNames.PROCESSED_DIR), f"testfile{i}-{randint(0,1024)}.csv")
                with open(path, "w") as f:
                    f.write("1")
                os.utime(path, (int(atime), int(mtime)))
                ret.append(os.path.basename(path))
            return set(ret)

        t = time.time()
        # push app context so current_app is available
        with self.app.test_request_context('/'), self.app.test_client() as _:

            _create_n_files(10, t - 30000, t - 86400 * 2)
            keep = _create_n_files(2, t - 30000, t - 30000)

            lst = os.listdir(os.path.join(writable_path(PathNames.PROCESSED_DIR)))
            self.assertEqual(12, len(lst))
            remove_old_processed_files()
            lst = os.listdir(os.path.join(writable_path(PathNames.PROCESSED_DIR)))

            self.assertEqual(2, len(lst))
            self.assertEqual(keep, set(lst))

    def test_brivo_api_context_init(self):
        with self.app.test_request_context('/'), self.app.test_client() as _:
            for var in EnvKeys.all():
                self.assertIsNotNone(self.app.config[var])
                self.assertNotEqual(self.app.config[var], MISSING_ENV_VALUE)


if __name__ == '__main__':
    unittest.main()
