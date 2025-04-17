# scanner.py (v3)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import argparse
import sys
import time
from collections import deque
import concurrent.futures # For concurrency

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
# Added a DOM-based payload
DOM_PAYLOAD_ATTRIBUTE = 'data-xss-success'
DOM_PAYLOAD_VALUE = 'true'
PAYLOADS = [
    "<script>alert('XSS_Alert1')</script>",
    "'><script>alert('XSS_Alert2')</script>",
    f"<img src=x onerror=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}', '{DOM_PAYLOAD_VALUE}')\">", # DOM change payload
    "<img src=x onerror=alert('XSS_Alert4')>",
    "javascript:alert('XSS_Alert5')",
]
# Timeout for waiting for alert/DOM change in seconds
CONFIRMATION_WAIT_TIMEOUT = 3
# Max workers for ThreadPoolExecutor
MAX_WORKERS = 10

# --- Helper Functions ---

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
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(15) # Slightly increased page load timeout
        return driver
    except ValueError as ve:
         print(f"[!] WebDriver Manager Error: {ve}. Check network connection or cache.", file=sys.stderr)
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
        return None # Headless confirmation disabled or failed setup

    print(f"  [*] Attempting headless confirmation for: {url[:100]}...")
    confirmation_type = None
    confirmation_detail = ""

    try:
        driver.get(url)

        # 1. Check for Alert first
        try:
            WebDriverWait(driver, CONFIRMATION_WAIT_TIMEOUT).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            confirmation_detail = f"Alert('{alert_text}')"
            print(f"  [+] CONFIRMED via Alert: {confirmation_detail}")
            alert.accept()
            confirmation_type = "Alert"
            return confirmation_type, confirmation_detail # Confirmed via Alert
        except TimeoutException:
            # No alert found, proceed to check DOM change
            pass
        except UnexpectedAlertPresentException:
             # Alert appeared unexpectedly - still counts!
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                confirmation_detail = f"Unexpected Alert('{alert_text}')"
                print(f"  [+] CONFIRMED via Unexpected Alert: {confirmation_detail}")
                alert.accept()
                confirmation_type = "Alert (Unexpected)"
                return confirmation_type, confirmation_detail
            except NoAlertPresentException:
                 print("  [!] Alert was present but disappeared before handling.", file=sys.stderr)
                 # Continue to DOM check just in case

        # 2. If no alert confirmed, check for specific DOM attribute change
        if not confirmation_type:
            try:
                # Wait briefly for potential DOM change to occur after page load/scripts run
                time.sleep(0.5)
                body_element = driver.find_element(By.TAG_NAME, 'body')
                attribute_value = body_element.get_attribute(DOM_PAYLOAD_ATTRIBUTE)
                if attribute_value == DOM_PAYLOAD_VALUE:
                    confirmation_detail = f"DOM attribute '{DOM_PAYLOAD_ATTRIBUTE}' set to '{DOM_PAYLOAD_VALUE}'"
                    print(f"  [+] CONFIRMED via DOM Change: {confirmation_detail}")
                    confirmation_type = "DOM Change"
                    return confirmation_type, confirmation_detail # Confirmed via DOM
            except NoSuchElementException:
                # Body element not found? Highly unlikely but handle it.
                print("  [!] Body element not found during DOM check.", file=sys.stderr)
            except TimeoutException:
                 # If we added an explicit wait for the attribute, handle timeout
                 print("  [-] DOM attribute change not detected within timeout.")
            except Exception as e_dom:
                 print(f"  [!] Error during DOM check: {e_dom}", file=sys.stderr)

        # If neither confirmation method worked
        print("  [-] No Alert or specific DOM change detected within timeout.")
        return None, None # Not confirmed

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
        # Added timeout to requests call
        response = session.get(url, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        # Check content type - only parse HTML
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type:
            print(f"  [*] Skipping link extraction for non-HTML content: {url} ({content_type})")
            return set()

        soup = BeautifulSoup(response.content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            try:
                full_url = urljoin(url, href)
                parsed_link = urlparse(full_url)
                # Basic cleanup and scope check
                if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == base_domain:
                    clean_url = parsed_link._replace(fragment='', query='').geturl() # Also remove query params for visited check? Maybe too aggressive. Keep query for now.
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
        # Catch potential BeautifulSoup errors too
        print(f"[!] Error parsing links from {url}: {e}", file=sys.stderr)
        return set()

def get_forms(url, session):
    """Fetches and parses HTML to find all forms."""
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type:
             print(f"  [*] Skipping form extraction for non-HTML content: {url} ({content_type})")
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
    # Provide default empty string if attributes are missing
    action = form.attrs.get('action', '')
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    try:
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.attrs.get('name')
            if input_name is None: # Skip inputs without names
                continue
            input_type = input_tag.attrs.get('type', 'text').lower()
            input_value = input_tag.attrs.get('value', '')
            # Handle select options - maybe take the first option value?
            if input_tag.name == 'select' and not input_value:
                 option = input_tag.find('option')
                 if option:
                     input_value = option.attrs.get('value', '')

            inputs.append({'type': input_type, 'name': input_name, 'value': input_value})
    except Exception as e:
         print(f"[!] Error parsing inputs for a form: {e}", file=sys.stderr)
         # Continue with potentially incomplete inputs

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
        if param_name not in query_params:
            return None # Param might have disappeared (shouldn't happen with current logic)

        modified_params = query_params.copy()
        modified_params[param_name] = [payload]
        modified_query = urlencode(modified_params, doseq=True)
        test_url = parsed_url._replace(query=modified_query).geturl()

        response = session.get(test_url, timeout=10, allow_redirects=True)
        response_body = response.content.decode(errors='ignore')
        final_url = response.url

        if payload in response_body:
            # Return potential hit details for later confirmation
            return {'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'payload': payload, 'final_url': final_url}
        return None # No reflection

    except requests.exceptions.Timeout:
        print(f"  [!] Timeout testing param '{param_name}'", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [!] Error testing param '{param_name}': {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] Unexpected error testing param '{param_name}': {e}", file=sys.stderr)
        return None

def task_test_form(form_details, url, payload, session):
    """Task for ThreadPoolExecutor: Tests a single form submission."""
    target_url = urljoin(url, form_details['action'])
    inputs = form_details['inputs']
    data = {}
    tested_fields = []

    for input_item in inputs:
        if not input_item.get('name'): continue
        if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea']:
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
             # Return potential hit details for later confirmation
            return {'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'payload': payload, 'final_url': final_url}
        return None # No reflection

    except requests.exceptions.Timeout:
         print(f"  [!] Timeout submitting form (Action: {form_details['action']})", file=sys.stderr)
         return None
    except requests.exceptions.RequestException as e:
        print(f"  [!] Error submitting form (Action: {form_details['action']}): {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] Unexpected error submitting form (Action: {form_details['action']}): {e}", file=sys.stderr)
        return None

# --- Main Scanner Logic ---

def scan_page(url, session, driver, executor):
    """Scans a single page using ThreadPoolExecutor for initial checks."""
    print(f"\n[*] Scanning {url}...")
    potential_vulnerabilities = []
    futures = []

    # 1. Submit tasks for URL Parameters
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    print(f"[*] Testing {len(query_params)} URL parameters concurrently...")
    for param_name in query_params.keys():
        if not query_params[param_name]: continue
        for payload in PAYLOADS:
            futures.append(executor.submit(task_test_url_param, url, param_name, payload, session))

    # 2. Submit tasks for Forms
    forms = get_forms(url, session)
    print(f"[*] Testing {len(forms)} forms concurrently...")
    for form in forms:
        form_details = get_form_details(form)
        if not form_details['inputs']: continue
        for payload in PAYLOADS:
             futures.append(executor.submit(task_test_form, form_details, url, payload, session))

    # 3. Collect results from completed tasks (potential reflections)
    print(f"[*] Waiting for {len(futures)} reflection checks to complete...")
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            potential_vulnerabilities.append(result)
            print(f"  [+] Potential Reflection found ({result['type']}) - Queued for confirmation.")

    # 4. Perform Headless Confirmation (Sequentially for now)
    confirmed_vulnerabilities = []
    if driver and potential_vulnerabilities:
        print(f"[*] Performing headless confirmation for {len(potential_vulnerabilities)} potential findings...")
        for potential_vuln in potential_vulnerabilities:
            confirmation_type, confirmation_detail = confirm_xss_with_headless(potential_vuln['final_url'], driver)
            if confirmation_type:
                potential_vuln['confirmed'] = True
                potential_vuln['confirmation_type'] = confirmation_type
                potential_vuln['confirmation_detail'] = confirmation_detail
                confirmed_vulnerabilities.append(potential_vuln)
            else:
                 # Mark as unconfirmed explicitly if needed, or just don't add to confirmed list
                 potential_vuln['confirmed'] = False
                 # Keep potential_vuln in a separate list if you want to report unconfirmed reflections

    # Return only confirmed vulnerabilities from this page scan
    # Modify this if you want to return potential ones too
    return [v for v in potential_vulnerabilities if v.get('confirmed')]


# --- Crawler ---
def crawl(start_url, max_depth, session, driver, executor):
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
            print(f"[*] Max depth ({max_depth}) reached for branch starting at {current_url}. Stopping crawl here.")
            continue # Stop crawling deeper on this branch

        # Scan the current page
        # Pass the executor to scan_page
        confirmed_on_page = scan_page(current_url, session, driver, executor)
        all_confirmed_vulnerabilities.extend(confirmed_on_page)

        # Find new links only if we haven't reached the max depth for the *next* level
        if current_depth < max_depth -1:
            print(f"[*] Discovering links on {current_url} (Depth {current_depth})...")
            new_links = get_links(current_url, session, base_domain)
            added_count = 0
            for link in new_links:
                if link not in visited:
                    visited.add(link)
                    queue.append((link, current_depth + 1))
                    added_count += 1
            if added_count > 0:
                 print(f"  - Added {added_count} new links to queue (Depth {current_depth + 1})")
        else:
             print(f"[*] Not discovering links on {current_url} as next depth ({current_depth+1}) would exceed max depth ({max_depth})")


    print(f"\n[*] Crawler finished. Visited {len(visited)} unique URLs.")
    return all_confirmed_vulnerabilities


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner v3 (DOM Confirm, Concurrency, Error Handling) - Use Responsibly!")
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation (much faster, reports reflections only)")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers for reflection checks (default: {MAX_WORKERS})")

    args = parser.parse_args()
    target_url = args.url
    max_depth = args.depth
    use_headless = not args.no_headless
    num_workers = args.workers

    # Setup Selenium Driver
    driver = None
    if use_headless:
        print("[*] Setting up headless browser (Selenium)...")
        driver = setup_driver()
        if not driver:
            print("[!] Proceeding without headless confirmation.")
            use_headless = False
    else:
         print("[*] Headless confirmation disabled via command line.")

    # Use a session object
    session = requests.Session()
    # More descriptive User-Agent
    session.headers.update({'User-Agent': 'XSSScanner/0.3 (+https://github.com/your-repo)'})

    start_time = time.time()

    # Create ThreadPoolExecutor
    # Pass the executor to the crawl function
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        all_confirmed = crawl(target_url, max_depth, session, driver, executor)

    end_time = time.time()

    # --- Reporting ---
    print("\n--- Scan Summary ---")

    if all_confirmed:
        print(f"\n[***] Found {len(all_confirmed)} CONFIRMED XSS vulnerabilities:")
        for vuln in all_confirmed:
            details = f"Type: {vuln['type']}, Confirmation: {vuln.get('confirmation_type', 'N/A')} ({vuln.get('confirmation_detail', 'N/A')}), Payload: {vuln['payload']}, Final URL: {vuln['final_url']}"
            if vuln['type'] == 'URL Parameter':
                print(f"  - Param: {vuln['parameter']}, {details}")
            elif vuln['type'] == 'Form Input':
                 print(f"  - Form Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, {details}")
    else:
        print("\n[*] No vulnerabilities confirmed via headless browser (Alert or DOM change).")
        if not use_headless:
             print("    (Headless confirmation was disabled. Run without --no-headless for confirmation checks.)")


    print(f"\n--- Scan Finished in {end_time - start_time:.2f} seconds ---")

    # Cleanup Selenium Driver
    if driver:
        print("[*] Closing headless browser...")
        driver.quit()

