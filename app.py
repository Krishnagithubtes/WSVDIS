from flask import Flask, render_template, request, redirect, url_for, session, make_response
import requests
from bs4 import BeautifulSoup
import pdfkit  # pip install pdfkit and wkhtmltopdf
import PyPDF2
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == '123':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/scan', methods=['POST'])
def scan():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    url = request.form['url']
    result = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        result['status'] = f"Status Code: {response.status_code}"

        # XSS detection
        xss_indicators = ['<script>', 'onerror=', 'onload=', 'alert(', 'document.cookie', 'javascript:', 'vbscript:', 'onmouseover=', 'onfocus=']
        xss_found = any(indicator in response.text.lower() for indicator in xss_indicators)
        xss_payload = '<script>alert(1)</script>'
        try:
            test_response = requests.get(f"{url}?test={xss_payload}", headers=headers, timeout=5, verify=False)
            if xss_payload in test_response.text:
                xss_found = True
        except:
            pass
        result['xss'] = "XSS vulnerability detected" if xss_found else "No XSS vulnerability found"
        result['xss_flag'] = xss_found

        # Clickjacking
        frame_option = response.headers.get('X-Frame-Options')
        csp = response.headers.get('Content-Security-Policy', '')
        click_vuln = not (('frame-ancestors' in csp) or frame_option)
        result['clickjacking'] = "Vulnerable to clickjacking" if click_vuln else "Protected from clickjacking"
        result['clickjacking_flag'] = click_vuln

        # SQL Injection
        sqli_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT NULL--"]
        sqli_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db', 'odbc', 'sqlite_exception']
        sqli_found = False
        for payload in sqli_payloads:
            try:
                test_resp = requests.get(f"{url}?id={payload}", headers=headers, timeout=5, verify=False)
                if any(error in test_resp.text.lower() for error in sqli_errors):
                    sqli_found = True
                    break
            except:
                continue
        result['sqli'] = "SQL Injection vulnerability detected" if sqli_found else "No SQL Injection vulnerability found"
        result['sqli_flag'] = sqli_found

        # Authentication/session
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        auth_issues = []
        login_forms = [f for f in forms if any(field in str(f).lower() for field in ['password', 'login', 'signin'])]
        if login_forms:
            auth_issues.append("Login form found - verify secure authentication")
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.secure:
                auth_issues.append(f"Insecure cookie: {cookie.name}")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                auth_issues.append(f"Cookie missing HttpOnly: {cookie.name}")
        result['auth'] = auth_issues if auth_issues else ["No authentication issues detected"]
        result['auth_flag'] = bool(auth_issues)

        # Misconfigurations
        misconfig_flags = []
        if response.headers.get('Server'):
            misconfig_flags.append(f"Server header exposed: {response.headers['Server']}")
        if response.headers.get('X-Powered-By'):
            misconfig_flags.append(f"Technology disclosure: {response.headers['X-Powered-By']}")
        if "index of /" in response.text.lower():
            misconfig_flags.append("Directory listing enabled")
        error_indicators = ['exception', 'stack trace', 'error occurred', 'warning:', 'fatal error']
        if any(error in response.text.lower() for error in error_indicators):
            misconfig_flags.append("Verbose error messages detected")
        default_indicators = ['welcome to', 'default page', 'it works', 'apache2 ubuntu']
        if any(default in response.text.lower() for default in default_indicators):
            misconfig_flags.append("Default web server page detected")
        result['misconfig'] = misconfig_flags if misconfig_flags else ["No security misconfigurations found"]
        result['misconfig_flag'] = bool(misconfig_flags)

        # Security headers
        result['headers'] = {
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Missing'),
            'Content-Security-Policy': csp if csp else 'Missing',
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Missing'),
            'Referrer-Policy': response.headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': response.headers.get('Permissions-Policy', 'Missing'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Missing')
        }

    except requests.exceptions.RequestException as req_error:
        result['error'] = f"Request error: {str(req_error)}"

    # Save for download
    session['last_result'] = result
    session['last_url'] = url

    return render_template('result.html', result=result, url=url)

@app.route('/download/<fmt>')
def download(fmt):
    if 'last_result' not in session:
        return redirect(url_for('index'))

    result = session['last_result']
    url = session['last_url']
    rendered = render_template('result.html', result=result, url=url)

    if fmt == 'html':
        response = make_response(rendered)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = 'attachment; filename=scan_result.html'
        return response

    elif fmt == 'pdf':
        pdf = pdfkit.from_string(rendered, False)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=scan_result.pdf'
        return response

    return "Invalid format", 400

@app.route('/extract', methods=['GET', 'POST'])
def extract():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('extract.html', error='No file part')
        file = request.files['file']
        if file.filename == '':
            return render_template('extract.html', error='No selected file')
        if file and file.filename.endswith('.pdf'):
            try:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ''
                for page in pdf_reader.pages:
                    text += page.extract_text()
                return render_template('extract.html', text=text)
            except Exception as e:
                return render_template('extract.html', error=f"Error extracting PDF: {e}")
        else:
            return render_template('extract.html', error='Invalid file type. Please upload a PDF.')

    return render_template('extract.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', debug=False)