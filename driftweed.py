import os
from io import BytesIO
import socket
from aslookup import get_as_data
import requests
import builtwith
import nmap
import whois
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
import dns.resolver
from dns.resolver import Resolver
from urllib.parse import urlparse, urlunparse
from datetime import datetime


# Function to normalize URLs (ensure consistent formatting)
def normalize_url(url):
    # If the URL does not include '://', add 'http://' by default
    parsed = urlparse(url if '://' in url else 'http://' + url)
    netloc = parsed.netloc.lower()  # Normalize the domain part to lowercase
    path = parsed.path.rstrip('/')  # Remove trailing slash if present
    # Return the normalized URL
    normalized = urlunparse((parsed.scheme, netloc, path, '', '', ''))
    return normalized


class Driftweed:
    """
    Driftweed class performs various network and website-related tasks such as:
    - HTTP status checking
    - Technology detection
    - Port scanning
    - Whois info retrieval
    - IP lookup
    - ASN lookup
    - Screenshot capture
    - DNS record checking
    """

    def __init__(
            self, url: str,
            get_http_status=False,
            get_tech_detect=False,
            get_port_scan=False,
            get_whois_info=False,
            get_ip_lookup=False,
            get_asn_lookup=False,
            get_screenshot=False,
            get_dns_check=False
    ):
        """
        Initialize the Driftweed object with various options for website information retrieval.
        """
        # Normalize the URL and extract the hostname
        self.url = normalize_url(url)
        self.hostname = urlparse(self.url).hostname

        # Set flags to control which features to retrieve
        self.get_http_status = get_http_status
        self.get_tech_detect = get_tech_detect
        self.get_port_scan = get_port_scan
        self.get_whois_info = get_whois_info
        self.get_ip_lookup = get_ip_lookup
        self.get_asn_lookup = get_asn_lookup
        self.get_screenshot = get_screenshot
        self.get_dns_check = get_dns_check

        # Attempt to resolve the IP address of the hostname
        try:
            self.ip = str(socket.gethostbyname(self.hostname))
        except:
            self.ip = ''

        # Custom headers for HTTP requests to simulate a browser
        self.requests_headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        }

        # Setup custom DNS resolver (Google DNS and Cloudflare DNS)
        self.custom_resolver = Resolver()
        self.custom_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def http_status(self) -> dict:
        """
        Get the HTTP status code, response time, and security headers from the URL.
        """
        try:
            response = requests.get(self.url, headers=self.requests_headers, timeout=10)
            # Extract relevant security headers from the response
            headers_result = {
                h: response.headers.get(h, "Not Set")
                for h in [
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                    "Permissions-Policy"
                ]
            }
            return {
                'status': 'Completed',
                'result': {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'N/A'),
                    'content_len': len(response.text),
                    'redirect': normalize_url(response.url) != self.url,
                    'response_time': response.elapsed.total_seconds(),
                    'ssl': self.url.lower().startswith('https') or response.url.lower().startswith('https'),
                    'final_url': response.url,
                    'server': response.headers.get('Server', 'N/A'),
                    'security_headers': headers_result
                }
            }
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def tech_detect(self) -> dict:
        """
        Detect the technologies used on the website using the builtwith library.
        """
        try:
            technology_list = builtwith.parse(self.url)
            # Flatten the list of technologies and remove duplicates
            value_list = [v for values in technology_list.values() for v in values]
            return {'status': 'Completed', 'result': {'technologies': list(set(value_list))}}
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def port_scan(self, start_port: int = 1, end_port: int = 999) -> dict:
        """
        Perform a port scan on the host within the specified port range.
        """
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.hostname, arguments=f'-p {start_port}-{end_port} --host-timeout 30s')
            ports = {}
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        ports[str(port)] = nm[host][proto][port]['state']
            return {'status': 'Completed', 'result': ports}
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def whois_info(self) -> dict:
        """
        Retrieve WHOIS information about the website domain.
        """
        try:
            response = whois.whois(self.url)
            return {'status': 'Completed', 'result': {k: v for k, v in response.items() if v}}
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def ip_lookup(self) -> dict:
        """
        Get location and organization information for the resolved IP address.
        """
        try:
            response = requests.get(f"https://ipinfo.io/{self.ip}/json").json()
            return {
                'status': 'Completed',
                'result': {
                    'city': response.get('city'),
                    'region': response.get('region'),
                    'country': response.get('country'),
                    'location': response.get('loc'),
                    'organization': response.get('org'),
                }
            }
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def asn_lookup(self) -> dict:
        """
        Perform ASN (Autonomous System Number) lookup using the IP address.
        """
        try:
            if not self.ip:
                raise Exception("No IP resolved for hostname.")
            asn_result = get_as_data(self.ip, service="shadowserver")
            return {
                'status': 'Completed',
                'result': {
                    'ASN Number': asn_result.asn,
                    'ASN Handle': asn_result.handle,
                    'ASN Name': asn_result.as_name,
                    'ISP': asn_result.isp,
                    'Prefix': asn_result.prefix,
                    'Country Code': asn_result.cc,
                }
            }
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def screenshot(self, path: str = None) -> dict:
        """
        Take a screenshot of the website using Selenium and save it to the specified path.
        """
        try:
            options = Options()
            options.add_argument("--headless")  # Run in headless mode (no GUI)
            service = Service("/usr/local/bin/geckodriver")  # Path to GeckoDriver
            driver = webdriver.Firefox(service=service, options=options)
            driver.set_window_size(1920, 1080)  # Set browser window size
            driver.get(self.url)
            screenshot = driver.get_screenshot_as_png()
            driver.quit()

            # If no path is specified, generate a default path based on the hostname and current time
            if not path:
                path = os.path.join(os.getcwd(), f"{self.hostname}_{datetime.now().strftime('%m-%d_%H-%M')}.png")

            with open(path, 'wb') as f:
                f.write(BytesIO(screenshot).getbuffer())

            return {'status': 'Completed', 'result': {'path': path}}
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def dns_check(self) -> dict:
        """
        Perform DNS record checks for various record types (A, MX, TXT, CNAME, NS).
        """
        try:
            result = {}
            # Check for each DNS record type
            for record_type in ['A', 'MX', 'TXT', 'CNAME', 'NS']:
                try:
                    answers = self.custom_resolver.resolve(self.hostname, record_type)
                    result[record_type] = [str(r) for r in answers]
                except dns.resolver.NoAnswer:
                    result[record_type] = 'No Answer'
                except dns.resolver.NXDOMAIN:
                    result[record_type] = 'Domain Not Found'
                except dns.resolver.Timeout:
                    result[record_type] = 'DNS Timeout'
                except Exception as e:
                    result[record_type] = str(e)
            return {'status': 'Completed', 'result': result}
        except Exception as error:
            return {'status': 'Error', 'result': str(error)}

    def run(self) -> dict:
        """
        Run all selected tasks and return the results.
        """
        return {
            'http_status': self.http_status() if self.get_http_status else None,
            'tech_detect': self.tech_detect() if self.get_tech_detect else None,
            'port_scan': self.port_scan() if self.get_port_scan else None,
            'whois_info': self.whois_info() if self.get_whois_info else None,
            'ip_lookup': self.ip_lookup() if self.get_ip_lookup else None,
            'asn_lookup': self.asn_lookup() if self.get_asn_lookup else None,
            'screenshot': self.screenshot() if self.get_screenshot else None,
            'check_dns': self.dns_check() if self.get_dns_check else None
        }
