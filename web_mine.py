import http
import urllib.request
from urllib import parse, robotparser, request

import ipinfo
from dotenv import load_dotenv
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import socket
import os
import concurrent.futures

GLOBAL_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
FAVICON_BASE_URL = "https://icon.horse/icon/"
WHOIS_API= f"https://webwhois.verisign.com/webwhois-ui/rest/whois?q="



def check_url_validity(target_url):
    try:
        parsed_result = urlparse(target_url)
        return all([parsed_result.scheme, parsed_result.netloc])
    except ValueError:  # More specific exception handling
        return False


def extract_page_title(url):
    try:
        cookies = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
        urllib.request.install_opener(opener)

        headers = {'User-Agent': USER_AGENT}
        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, timeout=GLOBAL_TIMEOUT) as response:
            html_content = response.read().decode('utf-8')
            title_start = html_content.find('<title>')
            title_end = html_content.find('</title>', title_start)
            if title_start != -1 and title_end != -1:
                return html_content[title_start + 7:title_end]
            else:
                return "No title found"
    except urllib.error.HTTPError as e:
        return f"HTTP Error: {e.code}"
    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            return "Error: Request timed out"
        else:
            return f"URL Error: {e.reason}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def fetch_favicon_url(website_domain):
    return FAVICON_BASE_URL + website_domain


def website_information(target_website_url):
    extracted_page_title = extract_page_title(target_website_url)
    parsed_url = urlparse(target_website_url)
    parsed_domain = parsed_url.netloc
    if parsed_domain.startswith("www."):
        parsed_domain = parsed_domain[4:]
    try:
        ip_addresses = [res[4][0] for res in socket.getaddrinfo(parsed_domain, 80)]
        resolved_ip_address = ip_addresses[0]
    except Exception as e:
        resolved_ip_address = f"Error retrieving IP: {str(e)}"
    generated_favicon_url = fetch_favicon_url(parsed_domain)
    return parsed_domain, resolved_ip_address, extracted_page_title, generated_favicon_url


def gather_redirect_routes(initial_url, redirect_limit=10):
    redirect_routes = []
    for _ in range(redirect_limit):
        try:
            request_headers = {'User-Agent': USER_AGENT}
            response = requests.get(initial_url, allow_redirects=False, timeout=GLOBAL_TIMEOUT, headers=request_headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as error_http:
            return {f'HTTP Error: {error_http}'}
        except requests.exceptions.ConnectionError as error_connection:
            return {f'Connection Error: {error_connection}'}
        except requests.exceptions.Timeout as error_timeout:
            return {f'Timout Error: {error_timeout}'}
        except requests.exceptions.RequestException as error_request:
            return { f'Request Error: {error_request}'}

        if 300 <= response.status_code < 400:
            redirect_routes.append(initial_url)
            initial_url = response.headers['Location']
        else:
            break

    return {'Redirected': redirect_routes, 'Final domain': initial_url}


def fetch_website_cookies(website_url):
    try:
        response = requests.get(website_url, timeout=GLOBAL_TIMEOUT)
        cookies_dict = {cookie.name: cookie.value for cookie in response.cookies}
        return {'Cookies': cookies_dict}
    except requests.exceptions.Timeout:
        return {'Error': 'Request timed out.'}
    except requests.exceptions.ConnectionError:
        return {'Error': 'Connection Error.'}
    except requests.exceptions.HTTPError as e:
        return {'Error': f'HTTP Error occurred: {e.response.status_code}'}
    except requests.exceptions.RequestException:
        return {'Error': 'Request Error.'}


def fetch_response_headers(website_url, timeout=5):
    try:
        res = requests.get(website_url, timeout=timeout)
        response_headers = res.headers
        headers_map = {header: value for header, value in response_headers.items()}
        return headers_map
    except requests.exceptions.Timeout as e:
        return {'Error': f'Timeout error: {e}'}
    except requests.exceptions.RequestException as e:
        return {'Error': f'Failed to fetch URL: {e}'}



load_dotenv()
ipinfo_api_key = os.getenv('IPINFO_API_KEY')


def retrieve_ip_info(ip_str):
    try:
        handler = ipinfo.getHandler(ipinfo_api_key)
        details = handler.getDetails(ip_str)
        return details.all
    except ValueError as e:
        return {'Error': f'{e}'}


def fetch_dns_records(domain):
    record_types = ['A', 'NS', 'CNAME', 'MX', 'TXT', 'AAAA', 'SRV', 'SOA']
    records = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            records[record_type] = ['No record found']
        except dns.resolver.NXDOMAIN:
            return {'Error': f'Domain {domain} does not exist'}
        except dns.resolver.Timeout:
            return {'Error': 'Request timed out'}
        except Exception as e:
            records[record_type] = [f'Error retrieving {record_type} records: {str(e)}']

    return records


import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def fetch_ssl_certificate_info(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = x509.load_der_x509_certificate(ssock.getpeercert(True), default_backend())
                subject = certificate.subject.rfc4514_string()
                issuer = certificate.issuer.rfc4514_string()
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": certificate.serial_number,
                    "not_valid_before": certificate.not_valid_before.isoformat(),
                    "not_valid_after": certificate.not_valid_after.isoformat()
                }
    except ssl.SSLError as e:
        return {'Error': f'SSL error: {str(e)}'}
    except socket.gaierror:
        return {'Error': 'DNS lookup failed'}
    except Exception as e:
        return {'Error': f'Unhandeled error: {str(e)}'}


def get_sitemaps(website, timeout=5):
    robotstxturl = parse.urljoin(website, "robots.txt")
    sitemaps = []
    try:
        socket.setdefaulttimeout(timeout)
        rp = robotparser.RobotFileParser()
        rp.set_url(robotstxturl)
        rp.read()
        sitemaps = rp.site_maps()
    except os.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            print(f"Timeout Error: {e}")
        else:
            print(f"URLError: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        socket.setdefaulttimeout(None)

    return sitemaps



from urllib.robotparser import RobotFileParser
def fetch_sitemaps(website_url):
    robotstxt_url = urljoin(website_url, "robots.txt")

    try:
        response = requests.get(robotstxt_url, timeout=GLOBAL_TIMEOUT)

        rp = RobotFileParser()
        rp.parse(response.text.splitlines())
        sitemaps = rp.site_maps()

        if not sitemaps:  # If no sitemaps are found
            return {'Error': 'No sitemaps found'}

        return {'Sitemaps': sitemaps}

    except requests.exceptions.HTTPError:
        return {'Error': 'HTTP Error occurred'}
    except requests.exceptions.Timeout:
        return {'Error': 'Request timed out'}
    except requests.exceptions.RequestException:
        return {'Error': 'Request Error'}


import requests
from urllib.parse import urljoin
from xml.etree import ElementTree

def fetch_all_sitemaps(website_url, timeout=5):
    robotstxt_url = urljoin(website_url, "robots.txt")
    try:
        response = requests.get(robotstxt_url, timeout=timeout)
        response.raise_for_status()

        sitemaps = [line.split(": ")[1] for line in response.text.splitlines() if line.startswith("Sitemap:")]
        all_urls = []

        for sitemap_url in sitemaps:
            sitemap_response = requests.get(sitemap_url, timeout=timeout)
            sitemap_response.raise_for_status()
            root = ElementTree.fromstring(sitemap_response.content)
            namespace = {'sitemap': root.tag.split('}')[0].strip('{')}
            urls = root.findall('sitemap:url/sitemap:loc', namespace)
            all_urls.extend([url.text for url in urls])

        if not all_urls:
            return {'Error': 'No URLs found in sitemaps'}

        return {'URLs': all_urls}

    except requests.exceptions.HTTPError:
        return {'Error': 'HTTP Error for sitemaps'}
    except requests.exceptions.Timeout:
        return {'Error': 'Request timed out'}
    except requests.exceptions.RequestException:
        return {'Error': 'Request Error'}


import socket

def is_port_open(hostname, port):
    result = {"status": "closed", "error": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            connection_result = sock.connect_ex((hostname, port))
            if connection_result == 0:
                result["status"] = "open"
            else:
                result["status"] = "closed"
    except socket.error as e:
        result["error"] = str(e)
    return result


import socket
from concurrent.futures import ThreadPoolExecutor

def scan_open_ports(hostname, ports):
    def check_port(port):
        result = {"port": port, "status": "closed", "error": None}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                connection_result = sock.connect_ex((hostname, port))
                if connection_result == 0:
                    result["status"] = "open"
                else:
                    result["status"] = "closed"
        except socket.error as e:
            result["error"] = str(e)
        return result

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {executor.submit(check_port, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            results.append(future.result())
    return results


import requests
import re

def fetch_whois_info(domain):
    if not re.match(r'^[a-zA-Z0-9-]{1,63}(\.[a-zA-Z]{2,})+$', domain):
        return {'error': 'Invalid domain format'}

    url = WHOIS_API + f'{domain}&type=domain'
    try:
        response = requests.get(url)
        response.raise_for_status()

        data = response.json()
        if 'message' in data:
            whois_data = parse_whois_message(data['message'])
            return whois_data
        else:
            return {'error': 'not found'}

    except requests.exceptions.HTTPError as e:
        return {'error': f'HTTP Error: {e.response.status_code}'}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request Error: {str(e)}'}

def parse_whois_message(message):
    lines = message.split('\n')
    whois_data = {}
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            whois_data[key.strip()] = value.strip()
    return whois_data


from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException

def get_screenshot(url, options=None):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    if options:
        for option in options:
            chrome_options.add_argument(option)

    result = {"screenshot": None, "error": None}
    try:
        with webdriver.Chrome(options=chrome_options) as driver:
            driver.get(url)
            driver.implicitly_wait(10)
            screenshot_base64 = driver.get_screenshot_as_base64()
            result["screenshot"] = screenshot_base64
    except WebDriverException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
    finally:
        return result


from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup


def get_internal_external_links(url, timeout=GLOBAL_TIMEOUT, user_agent="Mozilla/5.0"):

    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        base_url = urlparse(url).scheme + '://' + urlparse(url).netloc
        links = set(a['href'] for a in soup.find_all('a', href=True))

        internal_links = set()
        external_links = set()

        for link in links:
            absolute_link = urljoin(base_url, link)
            if urlparse(absolute_link).netloc == urlparse(url).netloc:
                internal_links.add(absolute_link)
            else:
                external_links.add(absolute_link)

        return {'Internal Links': list(internal_links), 'External Links': list(external_links)}

    except requests.exceptions.RequestException as e:
        return {'error': f'Request error: {e}',
                'message': 'Failed parse of webpage.'}


import requests
import re

def get_emails_from_content(url, timeout=GLOBAL_TIMEOUT, user_agent="Mozilla/5.0"):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        if 'text/html' in response.headers['Content-Type']:
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
            return {'Emails': list(set(emails))}
        else:
            return {'error': 'The content type of the response is not text/html', 'Emails': []}

    except requests.exceptions.HTTPError as e:
        return {'error': f'HTTP Error: {e.response.status_code}', 'Emails': []}
    except requests.exceptions.Timeout as e:
        return {'error': 'Request timed out', 'Emails': []}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request Error: {str(e)}', 'Emails': []}


import requests
import re

def get_phone_numbers(url, timeout=GLOBAL_TIMEOUT, user_agent="Mozilla/5.0"):
    headers = {'User-Agent': user_agent}
    phone_pattern = r'\b(?:\+?\d{1,3})?\s*(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b'
    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        if 'text/html' in response.headers['Content-Type']:
            phone_numbers = re.findall(phone_pattern, response.text)
            return {'Phone Numbers': list(set(phone_numbers))}
        else:
            return {'error': 'NotFound', 'Phone Numbers': []}

    except requests.exceptions.HTTPError as e:
        return {'error': f'HTTP Error: {e.response.status_code}', 'Phone Numbers': []}
    except requests.exceptions.Timeout as e:
        return {'error': 'Request timed out', 'Phone Numbers': []}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request Error: {str(e)}', 'Phone Numbers': []}
