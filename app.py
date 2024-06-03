from flask import Flask, render_template, request as flask_request, jsonify
import os
import re
import json
from web_mine import website_information, get_screenshot, get_internal_external_links, \
    get_emails_from_content as get_emails, get_phone_numbers, gather_redirect_routes, fetch_website_cookies, \
    fetch_response_headers, retrieve_ip_info, fetch_dns_records, fetch_ssl_certificate_info, fetch_sitemaps, \
    scan_open_ports, fetch_whois_info
from dotenv import load_dotenv
import concurrent.futures

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

load_dotenv()
secret_key = os.getenv('SECRET_KEY')
app.secret_key = secret_key

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/web_mine', methods=["POST"])
def web_tool():
    user_url = flask_request.form.get('web_input')
    if not user_url:
        return jsonify({"error": "Please provide a valid URL"}), 400

    url_pattern = re.compile(r'^http(s)://(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+(?:/[^/\s]*)?$')
    if not url_pattern.match(user_url):
        return jsonify({"error": "Please provide a valid HTTPS URL"}), 400

    domain, ip_str, title, favicon = website_information(user_url)
    large_json = {
        "ip_info": {},
        "cookies": {},
        "headers": {},
        "dns_records": {},
        "ssl_info": {},
        'redirects': {},
        'sitemap': {},
        'port_info': {},
        'whois_info': {},
        'screenshot': {},
        'link_info': {},
        'email_info': {},
        'phone_info': {}
    }

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_mapping = {
            executor.submit(gather_redirect_routes, user_url): "redirects",
            executor.submit(fetch_website_cookies, user_url): "cookies",
            executor.submit(fetch_response_headers, user_url): "headers",
            executor.submit(retrieve_ip_info, ip_str): "ip_info",
            executor.submit(fetch_dns_records, domain): "dns_records",
            executor.submit(fetch_ssl_certificate_info, domain): "ssl_info",
            executor.submit(fetch_sitemaps, user_url): "sitemap",  # Choose the appropriate sitemap function
            executor.submit(scan_open_ports, domain): "port_info",
            executor.submit(fetch_whois_info, domain): "whois_info",
            executor.submit(get_screenshot, user_url): "screenshot",
            executor.submit(get_internal_external_links, user_url): "link_info",
            executor.submit(get_emails, user_url): "email_info",
            executor.submit(get_phone_numbers, user_url): "phone_info"
        }

        for future in concurrent.futures.as_completed(future_mapping):
            key = future_mapping[future]
            try:
                large_json[key] = future.result()
            except Exception as e:
                print(f"Error processing {key}: {e}")

    return render_template('web_mine.html', user_url=domain, ip_info=ip_str, title=title, favicon=favicon, web_info=json.dumps(large_json))

if __name__ == '__main__':
    app.run(debug=True, port=5000)