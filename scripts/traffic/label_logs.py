import os
import re

BASE_DIR = "data/raw"

ATTACK_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",         # SQLi
    r"(\<script\>)",                          # XSS
    r"(\bOR\b.*=)",                           # SQL logic
    r"(\bUNION\b)",                           # SQL union
    r"(\.\./\.\./)",                          # Path traversal
]

def is_malicious(line):
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def process_app(app_name):
    app_path = os.path.join(BASE_DIR, app_name)
    access_file = os.path.join(app_path, "access.log")
    benign_file = os.path.join(app_path, "benign.log")
    malicious_file = os.path.join(app_path, "malicious.log")

    if not os.path.exists(access_file):
        return

    with open(access_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    benign_lines = []
    malicious_lines = []

    for line in lines:
        if is_malicious(line):
            malicious_lines.append(line)
        else:
            benign_lines.append(line)

    with open(benign_file, "w", encoding="utf-8") as f:
        f.writelines(benign_lines)

    with open(malicious_file, "w", encoding="utf-8") as f:
        f.writelines(malicious_lines)

    print(f"{app_name}: {len(benign_lines)} benign, {len(malicious_lines)} malicious")

if __name__ == "__main__":
    for app in ["dvwa", "juice_shop", "webgoat"]:
        process_app(app)
