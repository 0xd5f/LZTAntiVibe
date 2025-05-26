import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class WebSecurityScanner:
    def __init__(self, user_agent=None, timeout=10):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.timeout = timeout

    def check_sql_injection(self, url):
        payloads = ["' OR 1=1--", "\" OR \"\"=\""]
        for payload in payloads:
            params = {'id': payload}
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
                if any(error in resp.text.lower() for error in ["mysql", "syntax", "odbc", "mysqli", "psql", "error"]):
                    return True
            except:
                continue
        return False

    def check_xss(self, url):
        payload = "<script>alert(1)</script>"
        params = {'q': payload}
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if payload in resp.text:
                return True
        except:
            pass
        return False

    def check_file_inclusion(self, url):
        payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
        for payload in payloads:
            params = {'file': payload}
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
                if "root:x:" in resp.text or "[fonts]" in resp.text:
                    return True
            except:
                continue
        return False

    def check_ssti(self, url):
        payload = "{{7*7}}"
        params = {'name': payload}
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if "49" in resp.text:
                return True
        except:
            pass
        return False

    def check_directory_traversal(self, url):
        payload = "../../../../etc/passwd"
        params = {'path': payload}
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if "root:x:" in resp.text:
                return True
        except:
            pass
        return False

    def check_middleware_header(self, url):
        custom_header = "middleware:middleware:middleware:middleware:middleware"
        try:
            resp = self.session.get(url, headers={"X-Middleware-Subrequest": custom_header}, timeout=self.timeout)
            if "middleware" in resp.text.lower() or resp.headers.get("X-Middleware-Subrequest"):
                return True
        except:
            pass
        return False

    def check_captcha(self, url):
        try:
            resp = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")
            if soup.find("iframe", {"src": lambda x: x and "recaptcha" in x}):
                return "reCAPTCHA"
            elif "hcaptcha.com" in resp.text:
                return "hCaptcha"
            elif soup.find_all(lambda tag: tag.name == "input" and "captcha" in (tag.get('id', '') + tag.get('name', ''))):
                return "Custom captcha"
            else:
                return None
        except:
            return None

    def check_ssrf(self, url):
        ssrf_urls = [
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://localhost"
        ]
        for u in ssrf_urls:
            params = {'url': u}
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
                if "localhost" in resp.text.lower() or "root:x:" in resp.text.lower() or "EC2" in resp.text:
                    return True
            except:
                continue
        return False

    def check_open_redirect(self, url):
        payloads = ["http://evil.com", "//evil.com"]
        for payload in payloads:
            params = {'next': payload, 'url': payload, 'redirect': payload}
            try:
                resp = self.session.get(url, params=params, allow_redirects=False, timeout=self.timeout)
                location = resp.headers.get('Location', '')
                if 'evil.com' in location:
                    return True
            except:
                continue
        return False

    def check_host_header_injection(self, url):
        try:
            resp = self.session.get(url, headers={"Host": "evil.com"}, timeout=self.timeout)
            if "evil.com" in resp.text.lower() or "evil.com" in resp.headers.get('Location', ''):
                return True
        except:
            pass
        return False

    def check_http_method_fuzz(self, url):
        for method in ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']:
            try:
                resp = self.session.request(method, url, timeout=self.timeout)
                if resp.status_code < 400 and resp.status_code != 405:
                    return method
            except:
                continue
        return None

    def check_security_headers(self, url):
        try:
            resp = self.session.get(url, timeout=self.timeout)
            missing = []
            needed = [
                "X-Frame-Options", "X-Content-Type-Options",
                "Content-Security-Policy", "Strict-Transport-Security",
                "Referrer-Policy", "Permissions-Policy"
            ]
            for h in needed:
                if h not in resp.headers:
                    missing.append(h)
            return missing
        except:
            return []

    def check_info_leak(self, url):
        try:
            resp = self.session.get(url, timeout=self.timeout)
            leaks = []
            keywords = ["debug", "traceback", "exception", "dump", "password", "secret", "api_key", "AWS_ACCESS_KEY"]
            for kw in keywords:
                if kw in resp.text.lower():
                    leaks.append(kw)
            return leaks
        except:
            return []
