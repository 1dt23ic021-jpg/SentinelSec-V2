from modules.web.web_scanner import scan_web_target


result = scan_web_target("http://127.0.0.1:8000")


assert "error" not in result
assert result["status_code"] == 200
assert result["https"] is False

print("Web scanner test passed.")
print(f"Status: {result['status_code']}")
print(f"HTTPS: {result['https']}")
print(f"Findings: {len(result['findings'])}")