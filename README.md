# Oracle Database Security Assessment Tool

Academic Flask application for running configurable Oracle database security assessments.

## Features
- Manage assessment tests with Critical / High / Medium / Low severity.
- Execute enabled tests against an Oracle database.
- HTML report with PASS / FAIL / ERROR, risk score, summary, severity matrix and remediation output.
- Weighted failure risk score: `100 * failed_weight / total_weight`, with severity weights Critical=4, High=3, Medium=2, Low=1. Only PASS/FAIL tests count towards the denominator; errors are excluded.

## Setup
1. Install Python and have access to MySQL 8 and Oracle Database.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and enter **your local** MySQL connection details and a random Flask secret. Do not publish `.env`.
4. Create the MySQL database `app_data`. The app creates the `assessment_tests` table on initial startup; add assessment tests through the UI.
5. Start from `app/`:
   ```bash
   cd app
   python app.py
   ```
6. Open `http://127.0.0.1:5000` on the local machine.

## Security and public-repository notes
- Never commit actual credentials, generated assessment reports, database dumps, or confidential network details.
- The source archive's previous reports and PDF have been excluded from this public package.
- The MySQL password and Flask secret are loaded from `.env` (which Git ignores).
- The Oracle password is supplied at runtime through the web form, and passed to the child process over stdin instead of as a command-line argument. **It is still present transiently in the application process and in a hidden form field on the preview page.**
- This is a student demonstration application, **not hardened for direct exposure to the public Internet**. In particular it has no user authentication or CSRF protection; run it on a trusted network only.
- Repository visibility (Public) does **not** mean the application server should be public.

## Submission
Course identifier: 20COMP1019.
