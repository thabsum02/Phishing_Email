import unittest
from phishing_analyzer import analyze_email, extract_urls


class PhishingAnalyzerTests(unittest.TestCase):
    def test_extracts_url(self):
        urls = extract_urls("Please visit https://example.com/account")
        self.assertEqual(urls, ["https://example.com/account"])

    def test_flags_urgent_credential_request(self):
        result = analyze_email(
            "URGENT: verify your account immediately and provide your password"
        )
        self.assertIn(result.risk_level, {"MEDIUM", "HIGH"})
        self.assertTrue(result.indicators)

    def test_no_obvious_indicators_message(self):
        result = analyze_email("The team meeting starts at 10 AM on Monday.")
        self.assertEqual(result.risk_level, "LOW")
        self.assertTrue(result.indicators)


if __name__ == "__main__":
    unittest.main()
