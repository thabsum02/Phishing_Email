# Phishing Email Analyzer

A beginner-friendly Python cybersecurity project that checks pasted email text or a text file for common phishing indicators.

## Features

- Checks for urgency, credential requests, prize lures, and suspicious attachment language.
- Extracts URL-like strings for review.
- Flags a few warning signs such as known URL shorteners and IP-address-based links.
- Produces a simple LOW, MEDIUM, or HIGH rule-based risk label.
- Optionally saves the result as `analysis_report.json`.
- Uses only Python's standard library; no `pip install` is required.

## Project structure

```text
Phishing_Email_Analyzer/
├── phishing_analyzer.py
├── README.md
├── .gitignore
├── sample_emails/
│   ├── suspicious_email.txt
│   └── ordinary_email.txt
└── tests/
    └── test_analyzer.py
```

## Requirements

- Python 3.9 or newer
- Visual Studio Code (recommended) or another Python editor

## Run in VS Code

1. Extract the downloaded ZIP file.
2. Open VS Code.
3. Select **File → Open Folder** and choose `Phishing_Email_Analyzer`.
4. Open **Terminal → New Terminal**.
5. Run:

   ```bash
   python phishing_analyzer.py
   ```

   On some Windows systems, use:

   ```bash
   py phishing_analyzer.py
   ```

6. Choose `1` to paste email text, or `2` to analyze a text file.
7. If you choose option 1, paste the email and type `END` on its own line when finished.
8. Choose `y` if you want to save a JSON report.

### Try the included sample

When the program asks for a file path, enter:

```text
sample_emails/suspicious_email.txt
```

Then run it again and try:

```text
sample_emails/ordinary_email.txt
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

On Windows, `py -m unittest discover -s tests -v` also works.

## How it works

The program searches email text for a set of configured phrases and reviews extracted URLs for a few basic warning signs. Each matching rule adds points to a score, which maps to a LOW, MEDIUM, or HIGH label.

## Limitations

- This is a learning prototype, not a production email security gateway.
- It does not verify sender identity, inspect email headers, check domain reputation, or safely detonate attachments.
- Legitimate emails can be flagged, and phishing emails can evade these rules.
- A LOW score does **not** mean an email is safe.
- Do not paste real confidential emails, passwords, OTPs, or personal information into a project or public repository.

## Future improvements

- Parse `.eml` files and inspect email headers.
- Add sender-domain and SPF/DKIM/DMARC explanations.
- Add a local web interface.
- Build a labeled test dataset and evaluate false positives/false negatives.
- Integrate reputable threat-intelligence services only after understanding their privacy and API requirements.

## Disclaimer

For educational and defensive cybersecurity learning only. The output is advisory and should not replace careful verification or an organization's security process.
