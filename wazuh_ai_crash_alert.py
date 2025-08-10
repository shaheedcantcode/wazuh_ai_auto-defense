#!/usr/bin/env python3
import smtplib, os, subprocess, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

logging.basicConfig(
    filename="/home/sbd/wazuh_ai_crash.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

load_dotenv("/home/sbd/.env")
EMAIL_SENDER = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = "sbdfyp@gmail.com"
SMTP_SERVER, SMTP_PORT = "smtp.gmail.com", 587

def get_severity_color(severity: str) -> str:
    return {
        "CRITICAL": "red; font-weight:bold;",
        "HIGH": "darkorange; font-weight:bold;",
        "MEDIUM": "blue;",
        "LOW": "gray;"
    }.get(severity, "black;")

try:
    logs_raw = subprocess.check_output(
        ["journalctl", "-u", "wazuh_ai.service", "-n", "20", "--no-pager"], text=True
    )
except subprocess.CalledProcessError as e:
    logs_raw = f"[ERROR] Unable to retrieve logs: {e}"

logs_html = ""
for line in logs_raw.splitlines():
    upper = line.upper()
    if "CRITICAL" in upper:
        logs_html += f"<p style='color:red; font-weight:bold;'>{line}</p>"
    elif "HIGH" in upper:
        logs_html += f"<p style='color:darkorange; font-weight:bold;'>{line}</p>"
    elif "MEDIUM" in upper:
        logs_html += f"<p style='color:blue;'>{line}</p>"
    elif "LOW" in upper:
        logs_html += f"<p style='color:gray;'>{line}</p>"
    else:
        logs_html += f"<p>{line}</p>"

subject = "[ALERT] Wazuh AI Service Crash Detected"
body_html = f"""
<html><body>
<h2 style='color:red;'>ERROR: Wazuh AI Service Crash Detected</h2>
<p>Crash time: <b>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</b></p>
<div style="background-color:#f4f4f4; padding:10px; border-radius:5px; font-family:monospace;">
{logs_html}
</div>
</body></html>
"""

msg = MIMEMultipart("alternative")
msg["From"], msg["To"], msg["Subject"] = EMAIL_SENDER, EMAIL_RECEIVER, subject
msg.attach(MIMEText(body_html, "html"))

try:
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
    logging.info(f"Crash alert email sent to {EMAIL_RECEIVER}")
except Exception as e:
    logging.error(f"Failed to send crash alert email: {e}")
