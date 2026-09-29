# CloudShield

**Secure Your Cloud. Detect Risks Before They Become Threats.**

CloudShield analyzes IAM policy and cloud configuration JSON files to surface security
misconfigurations, calculate a security score, and generate downloadable PDF reports.

## Setup

```bash
cd cloudshield
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**.

The SQLite database (`database.db`) and `reports/` folder are created automatically on first run.

## Using it

1. Register an account, then log in.
2. Go to **Analyze**, upload an IAM policy JSON and/or a cloud config JSON (see `sample_data/` for examples).
3. Click **Analyze Security** to run the scan and view your score, risk level, and findings.
4. Download the PDF report or revisit it anytime from **Reports**.

## Notes

- Risk bands: 90–100 LOW · 70–89 MEDIUM · 40–69 HIGH · 0–39 CRITICAL.
- `SECRET_KEY` defaults to a dev value — set the `CLOUDSHIELD_SECRET_KEY` environment
  variable before deploying anywhere real.
- This is a demo-grade analyzer (pattern-based checks), not a substitute for a full
  cloud security posture management (CSPM) tool.
