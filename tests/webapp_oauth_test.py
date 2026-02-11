import unittest
from unittest.mock import AsyncMock, patch

from flask import session

from tests.webapp_base import WebAppTestBase, get_flash


class OAuthTestCase(WebAppTestBase):

    @patch("app.blueprints.auth.BrivoApiContext", return_value=AsyncMock())
    def test_oauth_callback_success(self, mock_brivo_context):
        token_value = {
            "access_token": "mock_token",
            "refresh_token": "mock_refresh_token",
            "expires_after": 11,
        }
        mock_brivo_context.return_value.__aenter__.return_value.exchange_oauth_code_for_token.return_value = (
            token_value
        )

        with self.app.test_request_context(
            "/oauth_callback?code=mock_code"
        ), self.app.test_client() as c:
            response = c.get("/oauth_callback?code=mock_code", follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("authorized_by_oauth", session["username"])
            self.assertIn("token_object", session)
            self.assertEqual(session["token_object"], token_value)
            self.assertIn("Login successful!", get_flash(response)[0])

    @patch("app.blueprints.auth.BrivoApiContext", return_value=AsyncMock())
    def test_oauth_callback_failure(self, mock_brivo_context):
        mock_brivo_context.return_value.__aenter__.return_value.exchange_oauth_code_for_token.side_effect = Exception(
            "mock_error"
        )

        with self.app.test_request_context(
            "/oauth_callback?code=mock_code"
        ), self.app.test_client() as c:
            response = c.get("/oauth_callback?code=mock_code", follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Error during oauth callback: mock_error", get_flash(response)[0]
            )
            self.assertEqual(response.request.path, "/login")


if __name__ == "__main__":
    unittest.main()
