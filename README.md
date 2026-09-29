# CloudShield
# CloudShield

**Secure Your Cloud. Detect Risks Before They Become Threats.**

CloudShield is a Flask-based cloud security analysis web application that analyzes AWS-style IAM policies and cloud configuration JSON files for common security risks.

It provides:
- IAM policy risk analysis
- Cloud configuration misconfiguration checks
- Severity-based findings
- Security score and overall risk level
- Detailed remediation recommendations
- User registration and login
- Persistent report history
- Downloadable PDF security reports
- A simple dashboard for reviewing previous assessments

> **Project status:** Educational/demo project. The analyzer uses pattern-based checks and is not a replacement for a production CSPM (Cloud Security Posture Management) platform or a complete AWS security audit.

## Tech Stack

- **Python 3**
- **Flask**
- **Flask-Login**
- **Flask-SQLAlchemy**
- **SQLite**
- **ReportLab**
- HTML/CSS/JavaScript

## Project Structure

```text
cloudshield/
├── app.py
├── auth.py
├── analyzer.py
├── misconfiguration_checker.py
├── models.py
├── report_generator.py
├── requirements.txt
├── sample_data/
│   ├── sample_cloud_config.json
│   └── sample_iam_policy.json
├── static/
│   ├── css/
│   └── js/
├── templates/
│   ├── analyze.html
│   ├── base.html
│   ├── dashboard.html
│   ├── forgot_password.html
│   ├── login.html
│   ├── profile.html
│   ├── register.html
│   ├── report_detail.html
│   ├── reports.html
│   ├── security_guide.html
│   └── settings.html
└── reports/
    └── .gitkeep
```

## Features

### 1. IAM Policy Analysis

CloudShield checks AWS-style IAM policy JSON for patterns such as:
- Full administrative access (`Action: "*"`, `Resource: "*"`)
- Wildcard actions
- Wildcard resources
- Sensitive IAM/STS permissions
- Broad permissions without conditions

### 2. Cloud Configuration Analysis

The configuration checker looks for common issues including:
- Public S3 buckets
- Missing encryption at rest
- Missing access logging
- Security groups exposed to the internet
- SSH/RDP exposure
- Disabled MFA
- Weak password policy
- Missing CloudTrail logging
- Missing monitoring/alerting
- Publicly exposed resources

### 3. Security Scoring

Findings are weighted by severity and converted into a score from 0–100.

| Score | Risk Level |
|---:|---|
| 90–100 | LOW |
| 70–89 | MEDIUM |
| 40–69 | HIGH |
| 0–39 | CRITICAL |

This scoring model is a project-specific heuristic, not an industry-standard security rating.

### 4. PDF Reports

After analysis, CloudShield generates a PDF containing:
- Security score
- Risk level
- Finding counts
- Detailed findings
- Risk impact
- Recommendations
- Remediation steps
- Improvement plan

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/cloudshield.git
cd cloudshield
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the application secret

Copy `.env.example` to `.env` and set a strong secret key.

Example:

```env
CLOUDSHIELD_SECRET_KEY=replace-with-a-long-random-secret
```

Do **not** commit `.env` to GitHub.

### 5. Run the application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

The application creates the SQLite database when it starts.

## Using CloudShield

1. Register a user account.
2. Log in.
3. Open **Analyze**.
4. Upload an IAM policy JSON and/or cloud configuration JSON.
5. Run the analysis.
6. Review the security score and findings.
7. Open **Reports** to view previous assessments.
8. Download a PDF report when required.

Sample input files are available in `sample_data/`.

## Example IAM Policy

The repository includes a deliberately insecure sample policy for demonstrating detection:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

Use the sample files only for testing the analyzer. Do not use deliberately insecure policies in real AWS environments.

## Security Notes

- The development fallback secret in `app.py` should never be used for a real deployment.
- Set `CLOUDSHIELD_SECRET_KEY` through an environment variable in real deployments.
- Do not upload `.env`, databases containing real user information, generated reports containing personal information, or virtual-environment files.
- This project accepts uploaded JSON files and performs pattern-based analysis; it does not connect directly to AWS accounts.
- Before deploying publicly, add production security controls such as HTTPS, secure cookies, CSRF protection, rate limiting, upload validation/size limits, stronger password policy, secret management, and production-grade database/storage configuration.

## Important GitHub Upload Rule

Do **not** upload your local `venv/` folder. GitHub repositories should contain source code and project configuration, not the installed Python environment.

Do not upload:
- `venv/`
- `__pycache__/`
- `*.pyc`
- `.env`
- `database.db` if it contains your local account/report data
- generated PDF reports containing personal information
- IDE/editor folders such as `.vscode/` or `.idea/`
- OS files such as `.DS_Store` or `Thumbs.db`

Keep:
- Python source files
- HTML/CSS/JavaScript
- `requirements.txt`
- `sample_data/`
- `.gitignore`
- `.env.example`
- `README.md`
- `reports/.gitkeep`

## Limitations

CloudShield is an educational/demo security analyzer. Its checks are intentionally focused on a limited set of common patterns. A clean result does not prove that a cloud environment is secure.

For production security assessment, combine this project with provider-native security services, logging, vulnerability management, IAM review, infrastructure-as-code scanning, and human security review.

## License

This project is released under the MIT License. See `LICENSE`.

## Author

**Dixit**

If you publish this project, replace the author/repository placeholders with your GitHub username and repository URL.
