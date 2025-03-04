import json
import time
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager

def setup_driver():
    options = webdriver.ChromeOptions()
    options.binary_location = "/usr/bin/google-chrome"
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    service = Service("/usr/local/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)
    print("✅ ChromeDriver Session Started:", driver.session_id)
    return driver

def close_driver(driver):
    if driver:
        driver.quit()
        print("✅ ChromeDriver Session Closed.")

def load_urls(filename):
    with open(filename, "r") as file:
        return [line.strip() for line in file if line.strip()]

def check_csp(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"ℹ️ {url} - Status Code: {response.status_code}")
        print(f"ℹ️ CSP Header: {response.headers.get('Content-Security-Policy')}")
        csp_header = response.headers.get("Content-Security-Policy", "None")
        if csp_header == "None":
            return ("No CSP Found", 2)
        elif "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
            return ("Weak CSP", 1)
        else:
            return ("Strict CSP", -1)
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed for {url}: {e}")
        return ("Request Failed", 0)


def inject_xss_payload(url, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if not query_params:
        return None
    for param in query_params.keys():
        query_params[param] = payload
        break
    modified_query = urlencode(query_params, doseq=True)
    return urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, modified_query, parsed_url.fragment))

def test_xss_execution(driver, url):
    xss_payloads = ["<script>alert('XSS');</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    for payload in xss_payloads:
        attack_url = inject_xss_payload(url, payload)
        if not attack_url:
            return ("No injectable parameters found.", 0)
        try:
            driver.get(attack_url)
            time.sleep(2)
            try:
                alert = driver.switch_to.alert
                alert.dismiss()
                return ("XSS Executed!", 3)
            except NoAlertPresentException:
                pass
        except UnexpectedAlertPresentException as e:
            return ("XSS Executed!", 3)
    return ("XSS did not execute.", 0)

def test_cookie_security(driver, url):
    driver.get(url)
    try:
        alert = driver.switch_to.alert
        alert.dismiss()
    except NoAlertPresentException:
        pass
    cookies = driver.execute_script("return document.cookie;")
    secure_flags = driver.execute_script(
        "return document.cookie.split('; ').map(c => c.includes('Secure') && c.includes('HttpOnly') && c.includes('SameSite')).length > 0;"
    )
    if not cookies:
        return ("No Cookies Accessible", 4)
    return ("Cookies Accessible & Secure Flags Present", 3) if secure_flags else ("Cookies Accessible, Missing Security Flags", 2)

def is_public_url(url):
    domain = urlparse(url).netloc
    return ("Public Asset", 2) if "internal" not in domain and "localhost" not in domain else ("Internal Asset", 0)

def calculate_severity(driver, url):
    score = 0
    csp_status, csp_points = check_csp(url)
    score += csp_points
    asset_status, asset_points = is_public_url(url)
    score += asset_points
    xss_status, xss_points = test_xss_execution(driver, url)
    score += xss_points
    cookie_status, cookie_points = test_cookie_security(driver, url)
    score += cookie_points
    severity = "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 10 else "Critical"
    return {"URL": url, "Asset Exposure": asset_status, "CSP Status": csp_status, "XSS Execution": xss_status, "Cookie Access": cookie_status, "Final Score": score, "Severity": severity}

def scan_urls(file_name):
    driver = setup_driver()
    urls = load_urls(file_name)
    results = []

    if not urls:
        print("❌ No URLs loaded. Check urls.txt")
        return

    for url in urls:
        print(f"🕵️‍♂️ Testing: {url}")
        result = calculate_severity(driver, url)
        results.append(result)
        print(result)

    close_driver(driver)

    with open("xss_scan_results.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
    print("✅ Scan complete. Results saved to xss_scan_results.json.")

if __name__ == "__main__":
    scan_urls("urls.txt")
