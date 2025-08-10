#!/usr/bin/env bash
#
# install_wazuh_ai.sh – turn a fresh Ubuntu 22.04 VM into
# a fully-functional Wazuh-AI node in one go.
#
# Run with:   sudo ./install_wazuh_ai.sh
# ──────────────────────────────────────────────────────────
set -euo pipefail

# ---------- 0. pre-flight ----------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "[!] Please run as root: sudo ./install_wazuh_ai.sh"; exit 1;
fi

echo "[*] Updating APT & installing system packages …"
apt-get update -y
apt-get install -y python3 python3-pip python3-venv ufw curl jq

# ---------- 1. create service user ------------------------------------------
if ! id sbd &>/dev/null; then
  useradd -m -s /bin/bash sbd
  echo "[*] Created user 'sbd'"
fi

PROJECT_HOME="/home/sbd"
SRC_DIR="$(pwd)"

# ---------- 2. copy project files -------------------------------------------
echo "[*] Copying project files into $PROJECT_HOME …"
install -o sbd -g sbd -m 0644 "$SRC_DIR"/wazuh_ai.py                "$PROJECT_HOME"/
install -o sbd -g sbd -m 0644 "$SRC_DIR"/wazuh_ai_crash_alert.py    "$PROJECT_HOME"/
install -o sbd -g sbd -m 0644 "$SRC_DIR"/retrain_model.py           "$PROJECT_HOME"/
install -o sbd -g sbd -m 0644 "$SRC_DIR"/mitre_dataset.csv          "$PROJECT_HOME"/
install -o sbd -g sbd -m 0644 "$SRC_DIR"/wazuh_ai_config.json       "$PROJECT_HOME"/
install -o sbd -g sbd -m 0600 "$SRC_DIR"/.env                       "$PROJECT_HOME"/

chown sbd:sbd "$PROJECT_HOME"/*.py "$PROJECT_HOME"/*.csv "$PROJECT_HOME"/*.json "$PROJECT_HOME"/.env

# ---------- 3. Python deps ---------------------------------------------------
echo "[*] Creating virtualenv & installing Python libraries …"
sudo -u sbd python3 -m venv "$PROJECT_HOME/venv"
sudo -u sbd "$PROJECT_HOME/venv/bin/pip" install --upgrade pip
sudo -u sbd "$PROJECT_HOME/venv/bin/pip" install pandas scikit-learn watchdog python-dotenv joblib

# ---------- 4. systemd services ---------------------------------------------
echo "[*] Installing systemd service files …"
cat >/etc/systemd/system/wazuh_ai.service <<'EOF'
[Unit]
Description=Wazuh-AI ML companion
After=network.target wazuh-manager.service
OnFailure=wazuh_ai_failure_alert.service

[Service]
User=sbd
Group=sbd
WorkingDirectory=/home/sbd
Environment="PATH=/home/sbd/venv/bin"
ExecStart=/home/sbd/venv/bin/python /home/sbd/wazuh_ai.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/wazuh_ai_failure_alert.service <<'EOF'
[Unit]
Description=Email crash details when Wazuh-AI fails

[Service]
Type=oneshot
User=sbd
Environment="PATH=/home/sbd/venv/bin"
ExecStart=/home/sbd/venv/bin/python /home/sbd/wazuh_ai_crash_alert.py
EOF

systemctl daemon-reload
systemctl enable --now wazuh_ai.service

# ---------- 5. cron job for retraining --------------------------------------
echo "[*] Creating daily cron job (03:00) for model retrain …"
cat >/etc/cron.d/wazuh_ai_retrain <<'EOF'
0 3 * * * sbd /home/sbd/venv/bin/python /home/sbd/retrain_model.py >> /home/sbd/retrain.log 2>&1
EOF
chmod 644 /etc/cron.d/wazuh_ai_retrain

# ---------- 6. basic UFW -----------------------------------------------------
echo "[*] Enabling UFW (SSH allowed) …"
ufw allow 22/tcp
ufw --force enable

# ---------- 7. install Wazuh (official script) ------------------------------
if ! command -v wazuh-modulesd &>/dev/null; then
  echo "[*] Installing Wazuh 4.12 (all-in-one) – this takes a while …"
  sudo -u sbd bash -c 'curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a'
fi

echo "[^o^] All done!  → Verify with:  systemctl status wazuh_ai.service"
