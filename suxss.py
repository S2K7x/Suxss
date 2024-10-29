import requests
import urllib.parse
import html
import base64
import argparse
from termcolor import colored
import sys

class XSSTool:
    def __init__(self, args):
        self.target_url = args.url
        self.payload_file = args.payload_file
        self.parameter = args.parameter
        self.request_type = args.request_type.upper()
        self.verbose = args.verbose
        self.encoding = args.encoding
        self.timeout = args.timeout
        self.headers = {"User-Agent": args.user_agent}
        if args.custom_headers:
            self.headers.update(self.parse_custom_headers(args.custom_headers))
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Load custom payloads from a file."""
        try:
            with open(self.payload_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(colored(f"[+] Loaded {len(payloads)} payloads from {self.payload_file}", "green"))
            return payloads
        except FileNotFoundError:
            print(colored("[-] Payload file not found. Please check the file path.", "red"))
            sys.exit(1)
        except Exception as e:
            print(colored(f"[-] Error loading wordlist: {e}", "red"))
            sys.exit(1)

    def parse_custom_headers(self, headers_str):
        """Parse custom headers in 'key:value,key:value' format."""
        headers = {}
        try:
            for header in headers_str.split(','):
                key, value = header.split(':')
                headers[key.strip()] = value.strip()
            return headers
        except ValueError:
            print(colored("[-] Invalid format for custom headers. Use 'key:value,key:value' format.", "red"))
            sys.exit(1)

    def encode_payload(self, payload):
        """Apply specified encoding to the payload."""
        if self.encoding == 'url':
            return urllib.parse.quote(payload)
        elif self.encoding == 'html':
            return html.escape(payload)
        elif self.encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        return payload

    def send_payload(self, payload):
        """Send a request with the payload based on the selected method."""
        encoded_payload = self.encode_payload(payload)
        data = {self.parameter: encoded_payload}
        
        try:
            if self.request_type == "GET":
                response = requests.get(self.target_url, params=data, headers=self.headers, timeout=self.timeout)
            else:  # POST request
                response = requests.post(self.target_url, data=data, headers=self.headers, timeout=self.timeout)

            if self.verbose:
                print(colored(f"[VERBOSE] Testing payload: {payload}", "yellow"))
                print(colored(f"[VERBOSE] Request URL: {response.url}", "blue"))

            if encoded_payload in response.text:
                print(colored(f"[+] XSS found with payload: {payload}", "green"))
                return True
            else:
                if self.verbose:
                    print(colored("[-] Payload not reflected", "red"))
                return False
        except requests.RequestException as e:
            print(colored(f"[-] Request error: {e}", "red"))
            return False
        except KeyboardInterrupt:
            print(colored("\n[!] Process interrupted by user. Exiting...", "red"))
            sys.exit(0)

    def run(self):
        """Run the XSS testing tool across all payloads."""
        print(colored(f"[+] Starting XSS scan on {self.target_url}", "cyan"))
        try:
            for payload in self.payloads:
                self.send_payload(payload)
        except KeyboardInterrupt:
            print(colored("\n[!] Process interrupted by user. Exiting...", "red"))
            sys.exit(0)
        print(colored("[*] Scan completed.", "cyan"))


def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Testing Tool for Bug Bounty Researchers")
    parser.add_argument("url", help="Target URL for XSS testing")
    parser.add_argument("payload_file", help="File containing XSS payloads")
    parser.add_argument("-p", "--parameter", required=True, help="Parameter to test for XSS (e.g., 'q')")
    parser.add_argument("-r", "--request-type", choices=["GET", "POST"], default="GET", help="HTTP request method")
    parser.add_argument("-e", "--encoding", choices=["none", "url", "html", "base64"], default="none", help="Encoding type for payloads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("-u", "--user-agent", default="Mozilla/5.0", help="Custom User-Agent string")
    parser.add_argument("-c", "--custom-headers", help="Additional headers in 'key:value,key:value' format")

    args = parser.parse_args()
    xss_tool = XSSTool(args)
    xss_tool.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Process interrupted by user. Exiting...", "red"))
        sys.exit(0)
