### README for `suxss` Tool

---

# suxss: Advanced XSS Testing Tool

**suxss** is a customizable, user-friendly tool for detecting and analyzing Cross-Site Scripting (XSS) vulnerabilities, particularly useful for bug bounty hunters and security researchers. Equipped with features such as customizable wordlists, encoding options, custom headers, and verbose mode, this tool enhances your penetration testing workflow and makes bypassing firewalls and WAFs easier.

---

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Features](#features)
4. [Examples](#examples)
5. [Payload Customization](#payload-customization)
6. [Encoding Options](#encoding-options)
7. [Error Handling](#error-handling)
8. [Verbose Mode and Color Coding](#verbose-mode-and-color-coding)

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/suxss.git
   cd suxss
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

```bash
python3 suxss.py <url> <payload_file> -p <parameter_name> [OPTIONS]
```

- **`<url>`**: Target URL.
- **`<payload_file>`**: Path to a file containing payloads for XSS testing.
- **`-p <parameter_name>`**: Specifies the parameter in the URL or POST data to inject payloads into.

### Required Arguments

- `url`: The target URL for XSS testing.
- `payload_file`: Path to a file containing payloads for injection.
- `-p, --parameter`: Parameter name to test for XSS.

---

## Features

- **Custom Payloads**: Load payloads from an external file.
- **Encoding Options**: Supports `none`, `url`, `html`, and `base64` encoding.
- **Request Method**: Supports both `GET` and `POST` methods.
- **Verbose Mode**: Display detailed output of requests and results.
- **Custom User-Agent**: Specify a custom User-Agent header to evade certain security controls.
- **Additional Headers**: Add custom headers in `key:value` format to bypass WAFs.

---

## Examples

1. **Basic GET Request** with verbose mode enabled:

   ```bash
   python3 suxss.py "http://example.com" payloads.txt -p query -r GET -v
   ```

2. **POST Request with URL Encoding**:

   ```bash
   python3 suxss.py "http://example.com/api" payloads.txt -p search -r POST -e url
   ```

3. **Custom Headers and Timeout**:

   ```bash
   python3 suxss.py "http://example.com" payloads.txt -p q -t 10 -c "X-Forwarded-For: 127.0.0.1, Referer: https://example.com"
   ```

---

## Payload Customization

The `payloads.txt` file provided with the tool includes various encoded and obfuscated payloads to bypass WAFs. You can create and use a custom payload file by modifying `payloads.txt` or specifying another file with custom payloads.

---

## Encoding Options

The tool supports several encoding methods:

- **none**: No encoding applied.
- **url**: Encodes special characters using URL encoding (`%3Cscript%3E`).
- **html**: Encodes special characters in HTML format (`&lt;script&gt;`).
- **base64**: Encodes payloads in Base64, a method sometimes effective in bypassing certain filters.

To use encoding, simply specify it with the `-e` or `--encoding` option.

```bash
python3 suxss.py "http://example.com" payloads.txt -p query -e url
```

---

## Error Handling

The tool includes error handling for:

- Missing or invalid payload files
- Invalid header formatting
- HTTP request timeouts
- Interruptions (like `Ctrl+C`)

Each error outputs a user-friendly message and exits cleanly.

---

## Verbose Mode and Color Coding

When **verbose mode** is enabled with `-v`, the tool displays additional details:

- **Request URL** and payload details
- **Result color coding**:
  - **Green**: XSS reflected in the response.
  - **Yellow**: Testing each payload.
  - **Red**: Payload not reflected or other failures.

Verbose mode helps debug payload behavior and response reflection status.
