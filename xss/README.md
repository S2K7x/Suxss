# XSSpy Scanner v1.0

**A Context-Aware XSS Scanner with DOM and Stored XSS Detection Capabilities**

## ⚠️ Disclaimer ⚠️

**This tool is intended for educational purposes and authorized security testing ONLY.** Running this scanner against websites without explicit, written permission from the owner is **illegal and unethical**. The developers assume no liability and are not responsible for any misuse or damage caused by this tool. **Use responsibly.**

## Description

XSSpy is a Python-based Cross-Site Scripting (XSS) vulnerability scanner designed to automate the detection of various XSS types. It crawls web applications, injects payloads, analyzes responses, and uses a headless browser (Selenium) to confirm potential vulnerabilities, reducing false positives. It features context-aware scanning for reflected XSS, basic DOM XSS checks (hash and query parameter sources), and a basic mechanism for detecting potential stored XSS with correlation attempts.

## Features

* **Crawling:** Basic breadth-first crawling based on specified depth within the same domain.
* **Reflected XSS Scanning:**
    * Context-Aware Analysis: Attempts to identify the reflection context (HTML, attribute, script) and uses tailored payloads.
    * Uses internal payload lists and supports external files.
* **DOM-based XSS Scanning:**
    * Checks URL fragment (`#`) as a source using executable payloads.
    * Checks URL query parameters (`?param=...`) as a source by injecting markers and checking common sinks (`innerHTML`, event handlers). Attempts execution confirmation if a sink is hit.
* **Stored XSS Scanning (Basic):**
    * Logs payloads submitted during the scan.
    * Performs a second crawl phase, re-visiting discovered pages.
    * Attempts to correlate execution detected during the second phase (via `alert()` markers) back to the original submission point.
* **Headless Confirmation:** Uses Selenium and a headless Chrome browser to confirm execution via `alert()` dialogs or specific DOM attribute changes, significantly reducing false positives.
* **Payload Flexibility:** Supports loading custom payload lists (templates or static) via the `-pL` argument. Includes built-in payloads with basic evasion techniques.
* **Rate Limiting:** Optional delay (`--delay`) between page scans to avoid overwhelming the target server.
* **Logging:** Uses Python's `logging` module for detailed output control (verbose, quiet, log to file).

## Requirements

* Python 3.7+
* Google Chrome browser installed (for headless confirmation)
* Python libraries listed in `requirements.txt`:
    * `requests`
    * `beautifulsoup4`
    * `selenium`
    * `webdriver-manager` (automatically handles ChromeDriver)

## Installation

1.  **Clone the repository (or download the script):**
    ```bash
    git clone <your-repo-url>
    cd xsspy-scanner
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: `webdriver-manager` will automatically download the correct ChromeDriver the first time the scanner runs with headless mode enabled.*

## Usage

```bash
python xsspy_scanner.py <target_url> [options]
```

**Required Argument:**

* `url`: The starting URL for the scan (e.g., `https://example.com`).

**Common Options:**

* `-d DEPTH`, `--depth DEPTH`: Maximum crawl depth (Default: 2).
* `-pL PAYLOAD_LIST`, `--payload-list PAYLOAD_LIST`: Path to a custom payload file.
* `--delay DELAY`: Delay in seconds between page scans (Default: 0).
* `--no-headless`: Disable headless browser confirmation (faster, less accurate, disables DOM/Stored checks).
* `-w WORKERS`, `--workers WORKERS`: Number of concurrent workers for checks (Default: 10).
* `-o OUTPUT_LOG`, `--output-log OUTPUT_LOG`: File to write detailed scan logs to.
* `-v`, `--verbose`: Enable verbose (debug) logging to console and file.
* `-q`, `--quiet`: Suppress informational messages (show warnings/errors only) on console.
* `--skip-stored-check`: Skip the Phase 2 re-crawl for stored XSS verification.
* `--user-agent USER_AGENT`: Specify a custom User-Agent string.

**Examples:**

1.  **Basic Scan (Depth 1, Headless Enabled):**
    ```bash
    python xsspy_scanner.py [https://test.vulnweb.com](https://test.vulnweb.com) --depth 1
    ```

2.  **Deeper Scan with Custom Payloads and Delay:**
    ```bash
    python xsspy_scanner.py [https://example.com/app](https://example.com/app) -d 3 -pL custom_payloads.txt --delay 0.5
    ```

3.  **Verbose Scan, Logging to File, No Headless:**
    ```bash
    python xsspy_scanner.py [https://anothersite.com](https://anothersite.com) -v -o scan.log --no-headless
    ```

4.  **Scan Skipping Stored Check:**
    ```bash
    python xsspy_scanner.py [https://complexapp.com](https://complexapp.com) --skip-stored-check
    ```

## Payload File Format

* The file provided via `-pL` should be a plain text file.
* Each line represents one payload template or static payload.
* Lines starting with `#` are ignored as comments.
* Empty lines are ignored.
* To enable **stored XSS correlation**, include the placeholder `{marker}` within the `alert()` function of your payload templates (e.g., `<img src=x onerror=alert('MYPAYLOAD_{marker}')>`). The scanner will replace `{marker}` with a unique ID during submission.

## Output Interpretation

The scanner logs progress based on the verbosity level (`-v`, `-q`). The final summary includes:

* **Reflected XSS:** `URL Parameter` or `Form Input` type. Confirmed via headless checks.
* **DOM-based XSS (Confirmed - Hash):** Found via executable payload in URL fragment (`#`). Confirmed via headless checks.
* **DOM-based XSS (Confirmed - Query Param):** Found by injecting an executable payload into a query parameter after a marker indicated a potential sink. Confirmed via headless checks. Includes `Sink Hint`.
* **DOM-based XSS (Potential):** Found when a marker injected into a query parameter reached a potential sink, but subsequent execution confirmation failed or wasn't attempted. Requires manual verification.
* **Stored XSS (Correlated):** Execution confirmed during Phase 2 re-crawl, and the marker extracted from the confirmation (`alert` text) matched a logged submission. Includes details of the likely original submission.
* **Stored XSS (Potential - ...):** Execution confirmed during Phase 2, but correlation failed (no marker, unknown marker, or DOM change confirmation). Requires manual investigation to find the source.

## Limitations

* **Context Analysis:** Heuristic-based, may not always be accurate.
* **DOM Analysis:** Limited sources (hash, query) and basic sink checking. No full JavaScript parsing or taint analysis.
* **Stored XSS:** Correlation relies on markers in `alert()` and may miss vulnerabilities or fail correlation. Doesn't handle complex application state.
* **Evasion:** Payloads include basic evasion but may not bypass advanced filters or WAFs.
* **Crawler:** Basic, doesn't handle JavaScript-rendered links well.
* **Authentication:** No built-in support for complex login flows.
* **Performance:** Headless browser checks are inherently slow.

## License

(Specify your chosen license here, e.g., MIT License)

```
[Link to LICENSE file or full license text]
```

## Contributing

(Optional: Add guidelines if you want others to contribute)

```
Contributions are welcome! Please read CONTRIBUTING.md for details.
