import unittest
from unittest.mock import Mock, patch

from modules.web.web_scanner import scan_web_target


class TestWebScanner(unittest.TestCase):

    @patch("modules.web.web_scanner.requests.get")
    def test_successful_http_scan(self, mock_get):
        response = Mock()
        response.url = "http://127.0.0.1:8000"
        response.status_code = 200
        response.headers = {}
        response.cookies = []

        mock_get.return_value = response

        result = scan_web_target("http://127.0.0.1:8000")

        self.assertNotIn("error", result)
        self.assertEqual(result["status_code"], 200)
        self.assertFalse(result["https"])
        self.assertIn("findings", result)
        mock_get.assert_called_once()

    @patch(
        "modules.web.web_scanner.requests.get",
        side_effect=__import__(
            "requests"
        ).exceptions.ConnectionError("Connection refused"),
    )
    def test_connection_error(self, mock_get):
        result = scan_web_target("http://127.0.0.1:8000")

        self.assertIn("error", result)
        self.assertIn("url", result)


if __name__ == "__main__":
    unittest.main()