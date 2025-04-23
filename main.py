from io import BytesIO
from urllib.parse import urlparse
import socket
from aslookup import get_as_data
import requests
import builtwith
import nmap
import whois
import logging
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
import dns.resolver


class Driftweed:
    def __init__(
            self, url: str,
            http_status=False,
            tech_detect=False,
            port_scan=False,
            ip_lookup=False,
            asn_lookup=False,
            check_dns=False
    ):
        super().__init__()
        self.url = url
        self.hostname = urlparse(self.url).hostname

        self.http_status = http_status
        self.tech_detect = tech_detect
        self.port_scan = port_scan
        self.ip_lookup = ip_lookup
        self.asn_lookup = asn_lookup
        self.check_dns = check_dns

        try:
            self.ip = str(socket.gethostbyname(self.hostname))
        except:
            self.ip = ''

        self.requests_headers = {
            'Content-Length': '',
            'Content-Type': 'text/plain',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Dnt': '1',
            "Connection": "keep-alive",
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US,en;q=0.9,fa;q=0.8',
            'Referer': 'https://www.google.com/search?q=random+site+in+google&sca_esv=3a8e7eb7e7e5ec6f&rlz=1C1ASUM_enIR1116IR1116&sxsrf=ADLYWIJ5xEMh4rNxchHdlWKxC7JbNh_tAg%3A1735073982976&ei=viBrZ4WmO8XX1sQPrJXjmAE&ved=0ahUKEwiF_aejpsGKAxXFq5UCHazKGBMQ4dUDCBA&uact=5&oq=random+site+in+google&gs_lp=Egxnd3Mtd2l6LXNlcnAiFXJhbmRvbSBzaXRlIGluIGdvb2dsZTIGEAAYFhgeMgYQABgWGB4yBhAAGBYYHjIGEAAYFhgeMgsQABiABBiGAxiKBTILEAAYgAQYhgMYigUyCxAAGIAEGIYDGIoFMgsQABiABBiGAxiKBTIIEAAYgAQYogQyCBAAGIAEGKIESOBjUO4DWIJgcAN4AZABAJgB8wOgAedNqgEENC0yMrgBA8gBAPgBAZgCGaAC-k6oAhHCAgoQABiwAxjWBBhHwgINEAAYgAQYsAMYQxiKBcICDhAAGLADGOQCGNYE2AEBwgIZEC4YgAQYsAMY0QMYQxjHARjIAxiKBdgBAcICExAuGIAEGLADGEMYyAMYigXYAQHCAgoQIxiABBgnGIoFwgIEECMYJ8ICCxAAGIAEGLEDGIMBwgIHECMYJxjqAsICExAAGIAEGEMYtAIYigUY6gLYAQHCAhwQLhiABBjRAxhDGLQCGMcBGMgDGIoFGOoC2AEBwgILEAAYgAQYkQIYigXCAg4QLhiABBixAxjRAxjHAcICCxAuGIAEGLEDGIMBwgIIEAAYgAQYsQPCAgoQABiABBhDGIoFwgIQEAAYgAQYsQMYQxiDARiKBcICChAuGIAEGEMYigXCAhAQLhiABBjRAxhDGMcBGIoFwgIIEC4YgAQYsQPCAgUQABiABMICDRAAGIAEGLEDGEMYigXCAhMQLhiABBixAxjRAxhDGMcBGIoFwgIOEAAYgAQYkQIYsQMYigXCAgUQABjvBZgDB_EFMjPftRblseyIBgGQBhG6BgYIARABGAmSBwYzLjQtMjKgB9KtAQ&sclient=gws-wiz-serp',
        }

    def http_status(self) -> dict:
        try:
            response = requests.get(self.url, headers=self.requests_headers, timeout=10)
            security_headers = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy"
            ]
            headers_result = {h: response.headers.get(h, "Not Set") for h in security_headers}

            return {
                'status': 'Completed',
                'result': {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'N/A'),
                    'content_len': len(response.text),
                    'redirect': response.url != self.url,
                    'response_time': response.elapsed.total_seconds(),
                    'ssl': self.url.lower().startswith('https'),
                    'final_url': response.url,
                    'server': response.headers.get('Server', 'N/A'),
                    'security_headers': headers_result
                }
            }
        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def tech_detect(self) -> dict:
        try:
            technology_list = builtwith.parse(self.url)
            value_list = []

            for key, value in technology_list.items():
                value_list.extend(value)
            return {
                'status': 'Completed',
                'result': list(set(value_list))
            }

        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def port_scan(self, start_port: int = 1, end_port: int = 999) -> dict:
        try:
            nm = nmap.PortScanner()

            nm.scan(
                hosts=self.hostname,
                arguments=f'-p {start_port}-{end_port}',
                timeout=30
            )

            port_list = []
            for host in nm.all_hosts():
                for row in nm[host].all_protocols():
                    data = nm[host][row].keys()
                    for port in data:
                        state = nm[host][row][port]['state']
                        port_data = {
                            port: state,
                        }
                        port_list.append(port_data)
            return {
                'status': 'Completed',
                'result': port_list,
            }

        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def whois_info(self) -> dict:
        try:
            response = whois.whois(self.url)
            return {
                'status': 'Completed',
                'result': [
                    {'tag': key, 'value': value, 'category': 'Data'}
                    for key, value in response.items()
                    if value
                ],
            }

        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def ip_lookup(self) -> dict:
        try:
            response = requests.get(f"https://ipinfo.io/{self.ip}/json").json()
            return {
                'status': 'Completed',
                'result': [
                    {'tag': 'city', 'value': response['city'], 'category': 'Data'},
                    {'tag': 'region', 'value': response['region'], 'category': 'Data'},
                    {'tag': 'country', 'value': response['country'], 'category': 'Data'},
                    {'tag': 'location', 'value': response['loc'], 'category': 'Data'},
                    {'tag': 'organization', 'value': response['org'], 'category': 'Data'},
                ],
            }
        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def asn_lookup(self) -> dict:
        try:
            asn_result = get_as_data(self.hostname, service="shadowserver")
            return {
                'status': 'Completed',
                'result': [
                    {'tag': 'ASN Number', 'value': asn_result.asn},
                    {'tag': 'ASN Handle', 'value': asn_result.handle},
                    {'tag': 'ASN Name', 'value': asn_result.as_name},
                    {'tag': 'ISP', 'value': asn_result.isp},
                    {'tag': 'Prefix', 'value': asn_result.prefix},
                    {'tag': 'Country Code', 'value': asn_result.cc},
                ],
            }

        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def screenshot(self, path: str = None) -> dict:
        try:
            logging.getLogger('WDM').setLevel(logging.ERROR)
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            gecko_driver_path = "/usr/local/bin/geckodriver"  # You might want to make this dynamic
            service = Service(gecko_driver_path)

            # Create the webdriver instance
            driver = webdriver.Firefox(service=service, options=options)
            driver.set_window_size(1920, 1080)
            driver.get(self.url)
            # Capture screenshot as PNG
            screenshot_png = driver.get_screenshot_as_png()
            screenshot = BytesIO(screenshot_png)

            # Optionally save the screenshot to the specified path
            if path:
                with open(path, 'wb') as f:
                    f.write(screenshot.getbuffer())
                    logging.info(f'Screenshot saved to {path}')

            driver.quit()
            return {
                'status': 'COMPLETED',
                'result': [
                    {'tag': 'screenshot', 'value': path, 'category': 'Document'},
                ]
            }

        except Exception as error:
            return {
                'status': 'Error',
                'result': str(error),
            }

    def check_dns(self) -> dict:
        dns_records = {"A": [], "MX": [], "TXT": [], "CNAME": [], "NS": []}

        for rtype in dns_records:
            try:
                answers = dns.resolver.resolve(self.hostname, rtype)
                dns_records[rtype] = [str(r.to_text()) for r in answers]
            except dns.resolver.NoAnswer:
                dns_records[rtype] = ["No Answer"]
            except dns.resolver.NXDOMAIN:
                dns_records[rtype] = ["Domain Not Found"]
            except Exception as e:
                dns_records[rtype] = [f"Error: {e}"]

        return dns_records

    def run(self) -> dict:
        if self.http_status:
            result['http_status'] = self.http_status()
        if self.tech_detect:
            result['tech_detect'] = self.tech_detect()
        if self.port_scan:
            result['port_scan'] = self.port_scan()
        if self.ip_lookup:
            result['ip_lookup'] = self.ip_lookup()
        if self.asn_lookup:
            result['asn_lookup'] = self.asn_lookup()

        if self.check_dns:
            result['check_dns'] = self.check_dns()
        return result


obj = Driftweed('https://www.google.com')
result = obj.ip_lookup()
print(result)
