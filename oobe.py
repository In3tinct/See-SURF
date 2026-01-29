import time
import requests
import json
import base64
import hashlib
from threading import Thread
import urllib

class OOBEHandler:
    def __init__(self, vulnerable_list, print_lock, custom_domain=None):
        self.vulnerable_list = vulnerable_list
        self.print_lock = print_lock
        self.custom_domain = custom_domain
        self.enabled = False
        self.running = False
        self.tracker = {}
        self.token = ""
        self.webhook_url = ""
        self.api_url = ""

    def setup(self):
        try:
            # IF CUSTOM DOMAIN IS PROVIDED, SKIP WEBHOOK.SITE
            if self.custom_domain:
                self.webhook_url = f"http://{self.custom_domain.strip('/')}"
                self.enabled = True
                print(f"\033[94m[+] For Custom domain, Manual monitoring of logs {self.custom_domain} required for Blind SSRF.")
                return True

            # Create the private session
            r = requests.post("https://webhook.site/token", timeout=10)
            if r.status_code == 201:
                self.token = r.json()['uuid']
                self.webhook_url = f"https://webhook.site/{self.token}"
                self.api_url = f"https://webhook.site/token/{self.token}/requests"
                self.enabled = True
                with self.print_lock:
                    print(f"\033[94m[+] OOBE Module Active (Private Session: {self.token})\033[0m")
                self._start_polling()
                return True
        except Exception as e:
            print(f"\033[91m[!] Webhook.site Setup Error: {e}\033[0m")
        return False

    def get_payload(self, original_url, param_name):
        # If custom domain was provided
        if self.custom_domain:
            params = {
            "original_url": original_url,
            "vuln_param": param_name
            }

            # Convert params dict to JSON and base64-encode it (URL-safe)
            b64_encoded_params = base64.urlsafe_b64encode(json.dumps(params).encode()).decode()
            complete_url = f"{self.custom_domain}/blind_ssrf?b64_params={b64_encoded_params}"
            return complete_url

        # We use a hash to identify which specific URL/Param triggered the hit
        url_hash = hashlib.md5(f"{original_url}{param_name}".encode()).hexdigest()[:8]
        self.tracker[url_hash] = {"url": original_url, "param": param_name}
        return f"{self.webhook_url}?id={url_hash}"

    def _start_polling(self):
        self.running = True
        t = Thread(target=self._poll_loop, daemon=True)
        t.start()

    def _poll_loop(self):
        processed_request_ids = set()
        while self.running:
            try:
                r = requests.get(self.api_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for req in data.get('data', []):
                        req_uuid = req.get('uuid')
                        if req_uuid not in processed_request_ids:
                            self._match_hash(req)
                            processed_request_ids.add(req_uuid)
            except: pass
            time.sleep(5)

    def _match_hash(self, request_data):
        query = str(request_data.get('query'))
        for url_hash, info in self.tracker.items():
            if url_hash in query:
                self._alert(info, request_data.get('ip'))

    def _alert(self, info, ip):
        if any(v['original_url'] == info['url'] and v['vulnerable_param'] == info['param'] for v in self.vulnerable_list):
            return

        with self.print_lock:
            print(f"\n\033[91m[!!!] BLIND SSRF CONFIRMED (Webhook) [!!!]")
            print(f"Target: {info['url']}\nParam:  {info['param']}\nSource: {ip}\033[0m\n")
        
        self.vulnerable_list.append({
            "type": "Blind SSRF",
            "original_url": info['url'],
            "vulnerable_param": info['param'],
            "payload": "Webhook Callback Received",
            "reason": f"HTTP Interaction from {ip}"
        })

    def cleanup(self):
        """Deletes the token and all associated data from Webhook.site."""
        if not self.token:
            return
        
        self.running = False
        try:
            # Send DELETE request to the token endpoint
            # This wipes the dashboard and the UUID entirely
            r = requests.delete(f"https://webhook.site/token/{self.token}", timeout=10)
            if r.status_code == 200:
                with self.print_lock:
                    print(f"\033[94m[*] OOBE Session {self.token} successfully deleted from Webhook.site.\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Cleanup Failed: {e}\033[0m")

    def stop(self):
        self.running = False