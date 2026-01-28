import requests
import time
import random

BASE_URLS = [
    "http://localhost/dvwa/",
    "http://localhost/juice/",
    "http://localhost/webgoat/"
]

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/537.36"
]

def visit(url):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        requests.get(url, headers=headers, timeout=5)
    except:
        pass

while True:
    url = random.choice(BASE_URLS)
    visit(url)
    time.sleep(random.uniform(1, 3))
