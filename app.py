import concurrent.futures
from flask import Flask, render_template, request as flask_request, jsonify
from web_tools import *
from file_tools import *
from dotenv import load_dotenv


app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

load_dotenv()
secret_key = os.getenv('SECRET_KEY')
app.secret_key = secret_key


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/web_tool', methods=["POST"])
def web_tool():
    user_url = flask_request.form.get('web_input')
    if not user_url:
        return jsonify({"error": "Please provide a valid URL"}), 400

    url_pattern = re.compile(
        r'^http(s)://(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+(?:/[^/\s]*)?$')
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
        # Submit tasks for all functions with the same input
        redirect_future = executor.submit(get_redirects, user_url)
        cookies_future = executor.submit(get_cookies, user_url)
        headers_future = executor.submit(get_headers, user_url)
        ip_info_future = executor.submit(get_ip_info, ip_str)
        dns_rec_future = executor.submit(get_records, domain)
        ssl_cer_future = executor.submit(get_ssl, domain)
        sitemap_future = executor.submit(site_maps, user_url)
        port_info_future = executor.submit(check_ports, domain)
        whois_info_future = executor.submit(whois_info, domain)
        screenshot_future = executor.submit(get_screenshot, user_url)
        link_info_future = executor.submit(
            get_internal_external_links, user_url)
        email_info_future = executor.submit(get_emails, user_url)
        phone_info_future = executor.submit(get_phone_numbers, user_url)

    # Map the futures to the corresponding keys in the dictionary
        future_mapping = {
            redirect_future: "redirects",
            cookies_future: "cookies",
            headers_future: "headers",
            ip_info_future: "ip_info",
            dns_rec_future: "dns_records",
            ssl_cer_future: "ssl_info",
            sitemap_future: "sitemap",
            port_info_future: "port_info",
            whois_info_future: "whois_info",
            screenshot_future: "screenshot",
            link_info_future: "link_info",
            email_info_future: "email_info",
            phone_info_future: "phone_info"
        }

        # Wait for all tasks to complete using as_completed
        futures = [redirect_future, cookies_future, headers_future,
                   ip_info_future, dns_rec_future, ssl_cer_future, sitemap_future,
                   port_info_future, whois_info_future, screenshot_future, link_info_future, email_info_future, phone_info_future]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                key = future_mapping[future]
                large_json[key] = result

            except Exception as e:
                # Handle exceptions raised during execution
                print(f"Error: {e}")
    return render_template('web_tools.html', user_url=domain, ip_info=ip_str, title=title, favicon=favicon, web_info=json.dumps(large_json))



if __name__ == '__main__':
    app.run(debug=True, port=5001)
