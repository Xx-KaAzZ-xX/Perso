#!/usr/bin/python3
import os
import random
import tempfile
import time
import os
import json
from selenium import webdriver
from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image
import pytesseract
from bs4 import BeautifulSoup
import re
import requests
from dotenv import load_dotenv


CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
OUTPUT_DIR = "profile_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def start_selenium(proxy=None, headless=True):
    """Démarre un navigateur Chrome avec ou sans proxy SOCKS5."""
    options = Options()
    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--ignore-certificate-errors")

    tmpdir = tempfile.mkdtemp(prefix="selenium-profile-")
    options.add_argument(f"--user-data-dir={tmpdir}")

    if proxy:
        # le proxy est directement de type socks5://IP:PORT
        #options.add_argument(f"--proxy-server={proxy.strip()}")
        options.add_argument(f"--proxy-server={proxy}")

    service = Service(CHROMEDRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=options)
    return driver

def retrieve_url(url, proxy=None, headless=True, timeout=15):
    """Charge l’URL via Chrome + proxy et prend un screenshot.
    Retourne True si succès, False si échec (ex: timeout proxy)."""
    name = url.rstrip("/").split("/in/")[-1]
    out_path = os.path.join(OUTPUT_DIR, f"{name}.png")
    driver = start_selenium(proxy=proxy, headless=headless)
    try:
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(2)
        driver.save_screenshot(out_path)
        print(f"[+] Screenshot enregistré : {out_path} via {proxy}")
        return True
    except Exception as e:
        print(f"[-] Erreur sur {url} via {proxy} : {e}")
        return False
    finally:
        driver.quit()
### functions for  private profiles retrieval ###########################

def safe_filename(name, ext="jpeg", max_len=120):
    s = re.sub(r'[^A-Za-z0-9._-]', '_', name).strip('_')
    if len(s) > max_len:
        s = s[:max_len]
    return f"{s}.{ext}"

def selenium_cookies_to_requests(session, selenium_driver):
    for c in selenium_driver.get_cookies():
        # requests wants cookie name:value in session.cookies
        session.cookies.set(c['name'], c.get('value', ''), domain=c.get('domain', None))

def start_browser():
    options = Options()
    options.add_argument("--headless=new")
    # common flags for CI/servers
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-notifications")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    # give a fresh profile in /tmp to avoid "user data dir" conflicts
    tmpdir = tempfile.mkdtemp(prefix="selenium-profile-auth-")
    options.add_argument(f"--user-data-dir={tmpdir}")

    # start driver (assumes chromedriver is in PATH)
    driver_auth = webdriver.Chrome(options=options)
    return driver_auth

def login_linkedin(driver_auth_auth, email, password):
    driver_auth.get("https://api.ipify.org?format=json")
    ip_text = driver_auth.find_element(By.TAG_NAME, "body").text
    print(f"IP Public : ", ip_text)
    driver_auth.get("https://www.linkedin.com/login")
    time.sleep(3)
    # Fill form
    driver_auth.find_element(By.ID, "username").send_keys(email)
    driver_auth.find_element(By.ID, "password").send_keys(password)
    driver_auth.find_element(By.ID, "password").submit()
    # wait a bit for login redirect
    time.sleep(3)
    # quick check that we are logged in: presence of profile/avatar or home title
    # This is a simple heuristic — adapt if needed
    if "feed" not in driver_auth.current_url and "checkpoint" not in driver_auth.current_url:
        # still could be logged in even if URL not containing 'feed'
        pass
    return driver_auth


def extract_name_and_image_url(driver_auth, profile_url, timeout=10):
    """
    Récupère le nom et l'image du profil LinkedIn en s'assurant que
    la page est complètement chargée via WebDriverWait.
    """
    driver_auth.get(profile_url)

    try:
        # Attendre que le <h1> contenant le nom soit présent
        h1_element = WebDriverWait(driver_auth, timeout).until(
            EC.presence_of_element_located((By.TAG_NAME, "h1"))
        )
    except Exception:
        print("[!] Timeout ou profil inaccessible")
        return None, None

    soup = BeautifulSoup(driver_auth.page_source, "html.parser")

    # 1) Nom
    name = None
    h1 = soup.find("h1")
    if h1:
        name = h1.get_text(strip=True)

    # 2) Image via JSON script
    script_text = " ".join([s.string for s in soup.find_all("script") if s.string])
    root_match = re.search(r'"rootUrl"\s*:\s*"([^"]+)"', script_text)
    file_match = re.search(r'"fileIdentifyingUrlPathSegment"\s*:\s*"([^"]+)"', script_text)
    if root_match and file_match:
        root_url = root_match.group(1)
        file_segment = file_match.group(1)
        image_url = f"{root_url}{file_segment}"
        return name or "", image_url

    # 3) Fallback : <img> avec media.licdn.com
    img = None
    for candidate in soup.find_all("img"):
        src = candidate.get("src") or ""
        if "media.licdn.com" in src:
            img = candidate
            break
        data_src = candidate.get("data-delayed-url") or candidate.get("data-src") or ""
        if "media.licdn.com" in data_src:
            img = candidate
            break

    if img:
        src = img.get("src") or img.get("data-delayed-url") or img.get("data-src") or ""
        if src:
            return name or "", src

    # 4) Last resort : regex dans le HTML
    regex_media = re.search(r'(https?://media\.licdn\.com[^\s"\\\']+)', driver_auth.page_source)
    if regex_media:
        return name or "", regex_media.group(1)

    return name or "", None

def download_image_with_selenium_cookies(driver_auth, image_url, out_path, proxy=None):
    sess = requests.Session()

    # import cookies from selenium to requests
    selenium_cookies_to_requests(sess, driver_auth)

    r = sess.get(image_url, timeout=15, stream=True)
    r.raise_for_status()
    with open(out_path, "wb") as fh:
        for chunk in r.iter_content(1024):
            if chunk:
                fh.write(chunk)
    return out_path




###########################

# --- boucle principale ---
with open("working_proxies.txt") as f:
    proxies = [p.strip() for p in f if p.strip()]

with open("profiles.txt") as f:
    profiles = [p.strip() for p in f if p.strip()]

sampled = random.sample(proxies, min(3, len(proxies)))

for profile_url in profiles:
    print(f"[+] Traitement du profil : {profile_url}")
    success = False
    for proxy in sampled:
        try:
            proxy_full = f"socks5://{proxy}"
            print(f"trying to get {profile_url} with {proxy_full}")
            success = retrieve_url(profile_url, proxy=proxy_full)
            name = profile_url.rstrip("/").split("/in/")[-1]
            screenshot_path = os.path.join(OUTPUT_DIR, f"{name}.png")
            if success:
                ##on check si le profil est public, on a pas la phrase "view full profile"
                img = Image.open(screenshot_path)
                text = pytesseract.image_to_string(img)
                if "profile" in text.lower():
                    print(f"[+] Profil public détecté : {profile_url}")
                    break
                else:
                    print(f"[-] Private profile : {profile_url}")
                    load_dotenv()
                    LINKEDIN_EMAIL = os.getenv("LINKEDIN_EMAIL")
                    LINKEDIN_PASS = os.getenv("LINKEDIN_PASS")
                    driver_auth = start_browser()
                    login_linkedin(driver_auth, LINKEDIN_EMAIL, LINKEDIN_PASS)
                    name, image_url = extract_name_and_image_url(driver_auth, profile_url)
                    print(f"[+] Profile name: {name}")
                    print(f"[+] Image URL: {image_url}")
                    if image_url:
                        filename = safe_filename(name or "profile", ext="jpeg")
                        out_path = os.path.join(OUTPUT_DIR, filename)
                        try:
                            download_image_with_selenium_cookies(driver_auth, image_url, out_path, proxy=None)
                            print(f"[+] Image saved to: {out_path}")
                        except Exception as e:
                            print(f"[!] Failed to download image: {e}")
                    else:
                        print("[!] No image URL found on the page.")


                    ## launch retrieval with connection to the account
                break
            else:
                print(f"[!] Proxy {proxy_full} échoué pour {profile_url}, essai du prochain proxy.")
        except Exception as e:
            print(f"Error : {e}")
    if not success:
        print(f"[-] Aucun proxy n’a fonctionné pour {profile_url}")
