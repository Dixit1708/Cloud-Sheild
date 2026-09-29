
import os
import json
import uuid
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, send_from_directory, abort
)
from flask_login import (
    LoginManager, login_required, current_user
)

from models import db, User, Report
from auth import auth_bp
from analyzer import analyze_iam_policy
from misconfiguration_checker import analyze_cloud_config
from report_generator import generate_pdf_report

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CLOUDSHIELD_SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DURATION"] = 60 * 60 * 24 * 14  # 14 days

db.init_app(app)
app.register_blueprint(auth_bp)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access CloudShield."
login_manager.login_message_category = "error"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {"Critical": 20, "High": 10, "Medium": 5, "Low": 1}


def compute_score_and_risk(findings):
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - penalty)

    if score >= 90:
        risk = "LOW"
    elif score >= 70:
        risk = "MEDIUM"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    counts = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in counts:
            counts[key] += 1

    return score, risk, counts


# ---------------------------------------------------------------------------
# Core pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("auth.login"))


@app.route("/dashboard")
@login_required
def dashboard():
    reports = Report.query.filter_by(user_id=current_user.id) \
        .order_by(Report.created_at.desc()).all()

    latest = reports[0] if reports else None
    total_findings = sum(r.total_findings for r in reports)
    critical_total = sum(r.critical for r in reports)

    trend = [
        {"date": r.created_at.strftime("%b %d"), "score": r.security_score}
        for r in reversed(reports[:10])
    ]

    return render_template(
        "dashboard.html",
        latest=latest,
        reports_count=len(reports),
        total_findings=total_findings,
        critical_total=critical_total,
        trend=trend,
    )


@app.route("/analyze", methods=["GET"])
@login_required
def analyze_page():
    return render_template("analyze.html")


@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    """Accepts up to two JSON files: iam_file, cloud_file"""
    iam_file = request.files.get("iam_file")
    cloud_file = request.files.get("cloud_file")

    if not iam_file and not cloud_file:
        return jsonify({"error": "Please upload at least one JSON file."}), 400

    findings = []
    filenames = []

    if iam_file and iam_file.filename:
        try:
            iam_data = json.load(iam_file.stream)
        except Exception:
            return jsonify({"error": f"'{iam_file.filename}' is not valid JSON."}), 400
        findings.extend(analyze_iam_policy(iam_data))
        filenames.append(iam_file.filename)

    if cloud_file and cloud_file.filename:
        try:
            cloud_data = json.load(cloud_file.stream)
        except Exception:
            return jsonify({"error": f"'{cloud_file.filename}' is not valid JSON."}), 400
        findings.extend(analyze_cloud_config(cloud_data))
        filenames.append(cloud_file.filename)

    score, risk, counts = compute_score_and_risk(findings)
    combined_name = " + ".join(filenames)

    # Generate PDF
    pdf_filename = f"cloudshield_report_{uuid.uuid4().hex[:10]}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
    generate_pdf_report(
        pdf_path, current_user, combined_name, score, risk, counts, findings
    )

    report = Report(
        user_id=current_user.id,
        filename=combined_name,
        security_score=score,
        risk_level=risk,
        total_findings=counts["total"],
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        findings_json=json.dumps(findings),
        pdf_path=pdf_filename,
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({
        "report_id": report.id,
        "security_score": score,
        "risk_level": risk,
        "counts": counts,
        "findings": findings,
    })


@app.route("/reports")
@login_required
def reports_page():
    reports = Report.query.filter_by(user_id=current_user.id) \
        .order_by(Report.created_at.desc()).all()
    return render_template("reports.html", reports=reports)


@app.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    report = db.session.get(Report, report_id)
    if not report or report.user_id != current_user.id:
        abort(404)
    findings = json.loads(report.findings_json)
    return render_template("report_detail.html", report=report, findings=findings)


@app.route("/reports/<int:report_id>/download")
@login_required
def download_report(report_id):
    report = db.session.get(Report, report_id)
    if not report or report.user_id != current_user.id:
        abort(404)
    return send_from_directory(REPORTS_DIR, report.pdf_path, as_attachment=True,
                                download_name=f"CloudShield_Report_{report.id}.pdf")


@app.route("/security-guide")
@login_required
def security_guide():
    return render_template("security_guide.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        current_user.full_name = request.form.get("full_name", current_user.full_name)
        db.session.commit()
        flash("Settings updated successfully.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html")


@app.route("/profile")
@login_required
def profile():
    reports_count = Report.query.filter_by(user_id=current_user.id).count()
    return render_template("profile.html", reports_count=reports_count)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
