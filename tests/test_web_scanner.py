import unittest
from unittest.mock import Mock, patch

import requests

from modules.web.web_scanner import scan_web_target


class TestWebScanner(unittest.TestCase):

    @patch(
        "modules.web.web_scanner._validate_public_url",
        return_value=True,
    )
    @patch("modules.web.web_scanner.requests.Session")
    def test_successful_http_scan(
        self, mock_session_class, mock_validate
    ):
        response = Mock()
        response.url = "http://127.0.0.1:8000"
        response.status_code = 200
        response.headers = {}
        response.cookies = []

        session = (
            mock_session_class.return_value
            .__enter__.return_value
        )
        session.get.return_value = response

        result = scan_web_target("http://127.0.0.1:8000")

        self.assertNotIn("error", result)
        self.assertEqual(result["status_code"], 200)
        self.assertFalse(result["https"])
        self.assertIn("findings", result)
        mock_validate.assert_called_once()
        session.get.assert_called_once()

    @patch(
        "modules.web.web_scanner._validate_public_url",
        return_value=True,
    )
    @patch("modules.web.web_scanner.requests.Session")
    def test_connection_error(
        self, mock_session_class, mock_validate
    ):
        session = (
            mock_session_class.return_value
            .__enter__.return_value
        )
        session.get.side_effect = requests.exceptions.ConnectionError(
            "Connection refused"
        )

        result = scan_web_target("https://example.com")

        self.assertIn("error", result)
        self.assertIn("Connection refused", result["error"])

    def test_invalid_scheme_is_rejected(self):
        result = scan_web_target("ftp://example.com")

        self.assertIn("error", result)
        self.assertIn("Only HTTP and HTTPS", result["error"])

    def test_empty_url_is_rejected(self):
        result = scan_web_target("")

        self.assertIn("error", result)

    def test_embedded_credentials_are_rejected(self):
        result = scan_web_target("https://user:pass@example.com")

        self.assertIn("error", result)
        self.assertIn("credentials", result["error"])

    def test_invalid_timeout_is_rejected(self):
        result = scan_web_target("https://example.com", timeout=0)

        self.assertIn("error", result)
        self.assertIn("Timeout", result["error"])

    @patch("modules.web.web_scanner._validate_public_url")
    @patch("modules.web.web_scanner.requests.Session")
    def test_private_destination_is_rejected(
        self, mock_session_class, mock_validate
    ):
        mock_validate.return_value = False

        session = (
            mock_session_class.return_value
            .__enter__.return_value
        )

        result = scan_web_target("http://127.0.0.1:8000")

        self.assertIn("error", result)
        session.get.assert_not_called()


if __name__ == "__main__":
    unittest.main()