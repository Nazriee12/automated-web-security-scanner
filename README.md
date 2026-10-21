# Automated Web Security Scanner

## Project overview
The Automated Web Security Scanner is a beginner-friendly Python web application that inspects selected HTTP response security headers and gives recommendations when expected headers are absent.

## Objectives
- Learn how HTTP response headers support web security.
- Automate checks for common security headers.
- Display results in a clear interface.
- Export scan results as a CSV report.
- Practice documenting and publishing a software project with GitHub.

## Features
- Accepts HTTP or HTTPS URLs.
- Checks six response headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-Frame-Options
- Displays HTTP status code, header results, and recommendations.
- Exports the results as CSV.
- Validates the URL, applies a timeout, blocks private/local/reserved destinations, and does not follow redirects.

## Technologies used
- Python
- Streamlit
- Requests
- Pandas
- GitHub

## Installation and run instructions
1. Install Python 3.10 or newer.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Run the application:

   ```bash
   streamlit run Nazrin_AutomatedWebSecurityScanner.py
   ```

6. Open the local address shown in the terminal.

## Replit instructions
Create a Python project in Replit and upload the Python file and `requirements.txt`. Install the dependencies, then run:

```bash
streamlit run Nazrin_AutomatedWebSecurityScanner.py --server.address 0.0.0.0 --server.port 3000
```

Replit interface and port settings may vary.

## Dataset
This project does not use a machine-learning dataset. It checks the live HTTP response headers of a URL entered by the user. Only assess websites you own or have explicit permission to test.

## Limitations
This is a security-header checker, not a comprehensive vulnerability scanner. It does not test for SQL injection, cross-site scripting, authentication flaws, or other application vulnerabilities. A missing header does not by itself prove a website is vulnerable. Some hosting environments may restrict outbound network access.

## Ethical use
Use the tool only for educational and authorized defensive testing.

## Suggested reference
OWASP Secure Headers Project: https://owasp.org/projects/secure-headers-project

## Author
Nazrin
