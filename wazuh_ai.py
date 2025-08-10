#!/usr/bin/env python3
import os, json, pandas as pd, time, subprocess, shutil, gzip, logging, ipaddress, threading, signal
from collections import defaultdict
from datetime import datetime, timedelta
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from typing import Dict, Any, List

# -----------------------
# LOGGING SETUP
# -----------------------
logging.basicConfig(
    filename="/home/sbd/wazuh_ai_system.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# -----------------------
# LOAD CONFIG & ENV
# -----------------------
CONFIG_FILE = "/home/sbd/wazuh_ai_config.json"
default_config = {
    "ALERTS_FILE": "/var/ossec/logs/alerts/alerts.json",
    "DATASET_FILE": "/home/sbd/wazuh_ai_training_data.csv",
    "INITIAL_DATASET_FILE": "/home/sbd/mitre_dataset.csv",
    "FAILED_SSH_THRESHOLD": 5,
    "CONFIDENCE_THRESHOLD": 80,
    "BLOCK_DURATION_HOURS": 24,
    "BLOCKED_IPS_FILE": "/home/sbd/blocked_ips.json",
    "FAILED_SSH_FILE": "/home/sbd/failed_ssh.json",
    "HUMAN_REVIEW_FILE": "/home/sbd/human_review.csv",
    "INCIDENT_LOG_DIR": "/home/sbd/wazuh_ai_logs/",
    "LOG_RETENTION_DAYS": 30,
    "EMAIL_COOLDOWN": 300,
    "MODEL_FILE": "/home/sbd/wazuh_ai_model.pkl",
    "VECTORIZER_FILE": "/home/sbd/wazuh_ai_vectorizer.pkl"
}
config = json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else default_config

load_dotenv("/home/sbd/.env")
EMAIL_SENDER = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = "sbdfyp@gmail.com"
SMTP_SERVER, SMTP_PORT = "smtp.gmail.com", 587

# -----------------------
# GLOBALS & LOCK
# -----------------------
last_email_time = 0
last_summary_email = datetime.now()
failed_ssh_counter = defaultdict(int)
blocked_ips_timestamps: Dict[str, datetime] = {}
file_offset = 0
alerts_inode = None
model_mtime = None
data_lock = threading.Lock()

os.makedirs(config["INCIDENT_LOG_DIR"], exist_ok=True)

# -----------------------
# CONFIG VALIDATION
# -----------------------
def validate_config(cfg: Dict[str, Any]) -> None:
    numeric_fields = ["FAILED_SSH_THRESHOLD", "CONFIDENCE_THRESHOLD", "BLOCK_DURATION_HOURS", "EMAIL_COOLDOWN"]
    for field in numeric_fields:
        if not isinstance(cfg[field], int):
            raise ValueError(f"Config error: {field} must be an integer")
    # Create parent directories for all file-based config entries
    for key, value in cfg.items():
        if isinstance(value, str) and ("/" in value or value.endswith(".csv") or value.endswith(".json") or value.endswith(".pkl")):
            dir_path = os.path.dirname(value)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
validate_config(config)

# -----------------------
# PERSISTENCE FUNCTIONS
# -----------------------
def save_state() -> None:
    with data_lock:
        with open(config["BLOCKED_IPS_FILE"], 'w') as f:
            json.dump({ip: t.isoformat() for ip, t in blocked_ips_timestamps.items()}, f)
        with open(config["FAILED_SSH_FILE"], 'w') as f:
            json.dump(failed_ssh_counter, f)

def load_state() -> None:
    global blocked_ips_timestamps, failed_ssh_counter
    if os.path.exists(config["BLOCKED_IPS_FILE"]):
        with open(config["BLOCKED_IPS_FILE"], 'r') as f:
            data = json.load(f)
            blocked_ips_timestamps = {ip: datetime.fromisoformat(t) for ip, t in data.items()}
    if os.path.exists(config["FAILED_SSH_FILE"]):
        with open(config["FAILED_SSH_FILE"], 'r') as f:
            failed_ssh_counter.update(json.load(f))
load_state()

# -----------------------
# EMAIL
# -----------------------
def get_severity_color(severity: str) -> str:
    return {
        "CRITICAL": "red; font-weight:bold;",
        "HIGH": "darkorange; font-weight:bold;",
        "MEDIUM": "blue;",
        "LOW": "gray;"
    }.get(severity, "black;")

def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def send_email(subject: str, html_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["From"], msg["To"], msg["Subject"] = EMAIL_SENDER, EMAIL_RECEIVER, subject
    msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        logging.info(f"Email sent: {subject}")
    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP authentication failed — check credentials")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error: {e}")

# -----------------------
# ML MODEL LOAD/TRAIN
# -----------------------
def load_or_train_model():
    global model_mtime
    if os.path.exists(config["MODEL_FILE"]) and os.path.exists(config["VECTORIZER_FILE"]):
        model_mtime = os.path.getmtime(config["MODEL_FILE"])
        logging.info("Loading model from disk...")
        model = joblib.load(config["MODEL_FILE"])
        vectorizer = joblib.load(config["VECTORIZER_FILE"])
    else:
        logging.info("Training model at startup...")
        df = pd.read_csv(config["DATASET_FILE"]) if os.path.exists(config["DATASET_FILE"]) else pd.read_csv(config["INITIAL_DATASET_FILE"])
        vectorizer = TfidfVectorizer()
        X_train = vectorizer.fit_transform(df["description"])
        y_train = df["severity"]
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        joblib.dump(model, config["MODEL_FILE"])
        joblib.dump(vectorizer, config["VECTORIZER_FILE"])
        model_mtime = os.path.getmtime(config["MODEL_FILE"])
    return model, vectorizer

model, vectorizer = load_or_train_model()

def check_model_reload():
    global model, vectorizer, model_mtime
    try:
        new_mtime = os.path.getmtime(config["MODEL_FILE"])
        if new_mtime != model_mtime:
            logging.info("Detected updated model — reloading...")
            model, vectorizer = load_or_train_model()
    except FileNotFoundError:
        pass
    threading.Timer(300, check_model_reload).start()

check_model_reload()

# -----------------------
# ALERT PROCESSING WITH LOG ROTATION HANDLING
# -----------------------
def read_new_alerts() -> List[dict]:
    global file_offset, alerts_inode
    alerts = []
    try:
        st = os.stat(config["ALERTS_FILE"])
        if alerts_inode is None:
            alerts_inode = st.st_ino
        elif st.st_ino != alerts_inode:
            logging.warning("Log rotation detected — resetting file offset")
            alerts_inode = st.st_ino
            file_offset = 0
        with open(config["ALERTS_FILE"], "r") as f:
            f.seek(file_offset)
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.warning("JSON decode error in alerts.json")
                    continue
            file_offset = f.tell()
    except FileNotFoundError:
        logging.error("Alerts file not found.")
    return alerts

# -----------------------
# BLOCKING & UNBLOCKING
# -----------------------
def block_ip(ip: str, port: int = None) -> None:
    if not valid_ip(ip):
        logging.warning(f"Invalid IP skipped: {ip}")
        return
    with data_lock:
        unblock_time = datetime.now() + timedelta(hours=config["BLOCK_DURATION_HOURS"])
        if ip in blocked_ips_timestamps and blocked_ips_timestamps[ip] > datetime.now():
            return
        try:
            cmd = ["sudo", "ufw", "deny", "from", ip] if not port else ["sudo", "ufw", "deny", "from", ip, "to", "any", "port", str(port)]
            subprocess.run(cmd, check=True)
            blocked_ips_timestamps[ip] = unblock_time
            save_state()
            logging.info(f"Blocked IP: {ip} until {unblock_time}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block IP {ip}: {e}")

def unblock_expired_ips() -> None:
    now = datetime.now()
    with data_lock:
        for ip, unblock_time in list(blocked_ips_timestamps.items()):
            if now >= unblock_time:
                subprocess.run(["sudo", "ufw", "delete", "deny", "from", ip], check=False)
                del blocked_ips_timestamps[ip]
                logging.info(f"Unblocked IP: {ip}")
        save_state()

# -----------------------
# HUMAN REVIEW LOGGING
# -----------------------
def log_human_review(srcip: str, description: str, severity: str, confidence: float) -> None:
    review_df = pd.DataFrame([[datetime.now(), srcip, description, severity, confidence]],
                             columns=["timestamp", "srcip", "description", "predicted_severity", "confidence"])
    review_df.to_csv(config["HUMAN_REVIEW_FILE"], mode='a', header=not os.path.exists(config["HUMAN_REVIEW_FILE"]), index=False)

# -----------------------
# PREDICTION
# -----------------------
def predict_severities(alerts: List[dict]) -> pd.DataFrame:
    descriptions, src_ips = [], []
    with data_lock:
        for alert in alerts:
            if "rule" in alert and "description" in alert["rule"]:
                desc, src = alert["rule"]["description"], alert.get("srcip", "Unknown")
                descriptions.append(desc)
                src_ips.append(src)
                if "ssh" in desc.lower() and "failed" in desc.lower():
                    failed_ssh_counter[src] += 1
    if not descriptions:
        return pd.DataFrame(columns=["srcip", "rule_description", "predicted_severity", "confidence"])
    X_new = vectorizer.transform(descriptions)
    probs = model.predict_proba(X_new)
    preds = model.predict(X_new)
    return pd.DataFrame({"srcip": src_ips, "rule_description": descriptions, "predicted_severity": preds, "confidence": probs.max(axis=1)*100})

# -----------------------
# ALERT EMAILS
# -----------------------
def send_instant_alerts(alerts_df: pd.DataFrame) -> None:
    global last_email_time
    now = time.time()
    if now - last_email_time < config["EMAIL_COOLDOWN"]:
        return
    high_or_critical = alerts_df[
        (alerts_df["predicted_severity"].isin(["High", "Critical"])) &
        (alerts_df["confidence"] >= config["CONFIDENCE_THRESHOLD"])
    ]
    if high_or_critical.empty:
        for _, row in alerts_df.iterrows():
            # Only log if below confidence threshold
            if row["confidence"] < config["CONFIDENCE_THRESHOLD"]:
                log_human_review(row["srcip"], row["rule_description"], row["predicted_severity"], row["confidence"])
        return
    html_body = """
    <html><body>
    <h2>High/Critical Security Alerts</h2>
    <table border="1" cellspacing="0" cellpadding="5">
    <tr><th>Source IP</th><th>Description</th><th>Severity</th><th>Confidence</th></tr>
    """
    for _, row in high_or_critical.iterrows():
        color = get_severity_color(row["predicted_severity"].upper())
        html_body += f"""
        <tr>
            <td>{row['srcip']}</td>
            <td>{row['rule_description']}</td>
            <td style="color:{color}">{row['predicted_severity']}</td>
            <td>{row['confidence']:.2f}%</td>
        </tr>
        """
    html_body += "</table></body></html>"
    send_email("[Wazuh AI] High/Critical Alerts", html_body)
    last_email_time = now

# -----------------------
# DAILY SUMMARY
# -----------------------
def send_daily_summary() -> None:
    global last_summary_email
    now = datetime.now()
    if now.date() != last_summary_email.date():
        today = now.strftime("%Y-%m-%d")
        daily_log_file = os.path.join(config["INCIDENT_LOG_DIR"], f"wazuh_ai_incidents_{today}.log")
        if os.path.exists(daily_log_file):
            rows = []
            with open(daily_log_file, "r") as f:
                for line in f:
                    try:
                        ts, ip, desc, sev, conf = line.strip().split(" | ")
                        rows.append((ts, ip, desc, sev, conf))
                    except ValueError:
                        logging.warning(f"Malformed log line skipped in summary: {line.strip()}")
                        continue
            html = "<html><body><h2>Daily Security Summary</h2><table border=1><tr><th>Timestamp</th><th>IP</th><th>Description</th><th>Severity</th><th>Confidence</th></tr>"
            for ts, ip, desc, sev, conf in rows:
                html += f"<tr><td>{ts}</td><td>{ip}</td><td>{desc}</td><td style='color:{get_severity_color(sev.upper())}'>{sev}</td><td>{conf}</td></tr>"
            html += "</table></body></html>"
            send_email(f"[Wazuh AI] Daily Summary - {today}", html)
        last_summary_email = now
    threading.Timer(60, send_daily_summary).start()

# -----------------------
# WATCHDOG HANDLER
# -----------------------
class AlertHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == config["ALERTS_FILE"]:
            unblock_expired_ips()
            alerts = read_new_alerts()
            alerts_df = predict_severities(alerts)
            for _, row in alerts_df.iterrows():
                if row["confidence"] < config["CONFIDENCE_THRESHOLD"]:
                    log_human_review(row["srcip"], row["rule_description"], row["predicted_severity"], row["confidence"])
                if failed_ssh_counter[row["srcip"]] >= config["FAILED_SSH_THRESHOLD"]:
                    block_ip(row["srcip"], port=22)
                elif row["predicted_severity"] in ["High", "Critical"] and row["confidence"] >= config["CONFIDENCE_THRESHOLD"]:
                    block_ip(row["srcip"])
            send_instant_alerts(alerts_df)
            save_state()

# -----------------------
# SIGNAL HANDLING
# -----------------------
def shutdown_handler(signum, frame):
    logging.info("Shutting down gracefully...")
    save_state()
    observer.stop()

signal.signal(signal.SIGTERM, shutdown_handler)

# -----------------------
# MAIN
# -----------------------
if __name__ == "__main__":
    logging.info("Starting Wazuh AI...")
    send_daily_summary()
    event_handler = AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(config["ALERTS_FILE"]) or ".", recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown_handler(None, None)
    observer.join()