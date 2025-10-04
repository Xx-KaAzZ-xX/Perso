#!/usr/bin/python3
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time
import tempfile
import re
import requests
import os

# --- CONFIG ---
LINKEDIN_EMAIL = ""
LINKEDIN_PASS = ""
PROFILE_URL = "https://www.linkedin.com/in/username/"  # <-- remplace par ton URL complète
PROXY = "socks5h://127.0.0.1:9050"
#PROXY = None  # ex: "http://user:pass@proxy-host:3128" ou None
HEADLESS = True

def safe_filename(name, ext="jpeg", max_len=120):
    s = re.sub(r'[^A-Za-z0-9._-]', '_', name).strip('_')
    if len(s) > max_len:
        s = s[:max_len]
    return f"{s}.{ext}"

def selenium_cookies_to_requests(session, selenium_driver):
    for c in selenium_driver.get_cookies():
        # requests wants cookie name:value in session.cookies
        session.cookies.set(c['name'], c.get('value', ''), domain=c.get('domain', None))

def start_browser(proxy=PROXY, headless=HEADLESS):
    options = Options()
    # headless
    if headless:
        # modern headless flag
        options.add_argument("--headless=new")
    # common flags for CI/servers
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-notifications")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    # give a fresh profile in /tmp to avoid "user data dir" conflicts
    tmpdir = tempfile.mkdtemp(prefix="selenium-profile-")
    options.add_argument(f"--user-data-dir={tmpdir}")

    if PROXY:
        print(f"Trying with proxy : {PROXY}")
        options.add_argument(f"--proxy-server={PROXY}")
        # simple proxy config for Chrome

    # start driver (assumes chromedriver is in PATH)
    driver = webdriver.Chrome(options=options)
    return driver

def login_linkedin(driver, email, password):
    driver.get("https://api.ipify.org?format=json")
    ip_text = driver.find_element(By.TAG_NAME, "body").text
    print(f"Chrome proxy : ", ip_text)
    driver.get("https://www.linkedin.com/login")
    time.sleep(3)
    # Fill form
    driver.find_element(By.ID, "username").send_keys(email)
    driver.find_element(By.ID, "password").send_keys(password)
    driver.find_element(By.ID, "password").submit()
    # wait a bit for login redirect
    time.sleep(3)
    # quick check that we are logged in: presence of profile/avatar or home title
    # This is a simple heuristic — adapt if needed
    if "feed" not in driver.current_url and "checkpoint" not in driver.current_url:
        # still could be logged in even if URL not containing 'feed'
        pass
    return driver

def extract_name_and_image_url(driver, profile_url):
    driver.get(profile_url)
    time.sleep(3)  # let JS load

    soup = BeautifulSoup(driver.page_source, "html.parser")

    # 1) try to extract name (usually in h1)
    name = None
    h1 = soup.find("h1")
    if h1:
        name = h1.get_text(strip=True)

    # 2) try to find image URL with JSON keys (rootUrl + fileIdentifyingUrlPathSegment)
    script_text = " ".join([s.string for s in soup.find_all("script") if s.string])
    root_match = re.search(r'"rootUrl"\s*:\s*"([^"]+)"', script_text)
    file_match = re.search(r'"fileIdentifyingUrlPathSegment"\s*:\s*"([^"]+)"', script_text)
    if root_match and file_match:
        root_url = unescape(root_match.group(1))
        file_segment = unescape(file_match.group(1))
        image_url = f"{root_url}{file_segment}"
        return name or "", image_url

    # 3) fallback: try to find an <img> likely to be the profile picture
    # look for img tags whose src contains media.licdn.com (LinkedIn media)
    img = None
    for candidate in soup.find_all("img"):
        src = candidate.get("src") or ""
        alt = candidate.get("alt") or ""
        # heuristic: LinkedIn media domain + alt containing the name or presence of 'profile' keywords
        if "media.licdn.com" in src:
            img = candidate
            break
        # sometimes data-delayed-url or data-src
        data_src = candidate.get("data-delayed-url") or candidate.get("data-src") or ""
        if "media.licdn.com" in data_src:
            img = candidate
            break

    if img:
        src = img.get("src") or img.get("data-delayed-url") or img.get("data-src") or ""
        if src:
            return name or "", src

    # 4) last resort: try regex on page for any media.licdn.com URL
    regex_media = re.search(r'(https?://media\.licdn\.com[^\s"\\\']+)', driver.page_source)
    if regex_media:
        return name or "", regex_media.group(1)

    return name or "", None

def download_image_with_selenium_cookies(driver, image_url, out_path, proxy=PROXY):
    sess = requests.Session()

    # Si proxy est en socks5, requests doit utiliser socks proxy (nécessite pysocks)
    if PROXY:
        # Exemples de mapping :
        # socks5  -> use socks5h to force remote DNS resolution if needed
        if PROXY.startswith("socks5://") or PROXY.startswith("socks5h://"):
            # prefer socks5h to resolve DNS through PROXY
            p = PROXY.replace("socks5://", "socks5h://")
            sess.proxies.update({"http": p, "https": p})
            r = sess.get("https://api.ipify.org?format=json")
            #print(f"requests sees:", r.text)
        else:
            # http PROXY
            sess.proxies.update({"http": PROXY, "https": PROXY})

    # import cookies from selenium to requests
    selenium_cookies_to_requests(sess, driver)

    r = sess.get(image_url, timeout=15, stream=True)
    r.raise_for_status()
    with open(out_path, "wb") as fh:
        for chunk in r.iter_content(1024):
            if chunk:
                fh.write(chunk)
    return out_path



def main():
    driver = start_browser(proxy=PROXY, headless=HEADLESS)
    try:
        login_linkedin(driver, LINKEDIN_EMAIL, LINKEDIN_PASS)
        name, image_url = extract_name_and_image_url(driver, PROFILE_URL)
        print(f"[+] Profile name: {name}")
        print(f"[+] Image URL: {image_url}")

        if image_url:
            filename = safe_filename(name or "profile", ext="jpeg")
            out_path = os.path.join(os.getcwd(), filename)
            try:
                download_image_with_selenium_cookies(driver, image_url, out_path, proxy=PROXY)
                print(f"[+] Image saved to: {out_path}")
            except Exception as e:
                print(f"[!] Failed to download image: {e}")
        else:
            print("[!] No image URL found on the page.")
    finally:
        try:
            driver.quit()
        except Exception:
            pass

if __name__ == "__main__":
    main()
