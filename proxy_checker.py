import sqlite3
from datetime import datetime, timedelta
import requests
import logging

class ProxyCache:
    def __init__(self, db_path='proxy_cache.db', expiry_days=1):
        self.db_path = db_path
        self.expiry_days = expiry_days
        self.conn = sqlite3.connect(self.db_path)
        self.create_tables()

    def create_tables(self):
        """Create the required tables in the database if they don't exist"""
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    ip TEXT PRIMARY KEY,
                    is_proxy BOOLEAN,
                    exemption BOOLEAN DEFAULT 0,
                    timestamp DATETIME
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS exemptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT, -- 'ip' or 'dns'
                    value TEXT -- The actual IP or DNS exemption
                )
            ''')

    def get_cached_result(self, ip_address):
        with self.conn:
            cursor = self.conn.execute('SELECT is_proxy, exemption, timestamp FROM cache WHERE ip = ?', (ip_address,))
            row = cursor.fetchone()
            if row:
                is_proxy, exemption, timestamp = row
                if exemption:
                    return False  # Treat exempted IPs as non-proxies
                if datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S') > datetime.now() - timedelta(days=self.expiry_days):
                    return is_proxy
                else:
                    self.delete_entry(ip_address)
        return None

    def set_cached_result(self, ip_address, is_proxy):
        with self.conn:
            self.conn.execute('''
                INSERT OR REPLACE INTO cache (ip, is_proxy, timestamp)
                VALUES (?, ?, ?)
            ''', (ip_address, is_proxy, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    def is_exempt(self, ip_address):
        with self.conn:
            cursor = self.conn.execute('SELECT exemption FROM cache WHERE ip = ?', (ip_address,))
            row = cursor.fetchone()
            return row is not None and row[0] == 1

    def set_exemption(self, ip_address, exempt):
        with self.conn:
            self.conn.execute('''
                INSERT OR REPLACE INTO cache (ip, exemption, timestamp)
                VALUES (?, ?, ?)
            ''', (ip_address, exempt, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    def delete_entry(self, ip_address):
        with self.conn:
            self.conn.execute('DELETE FROM cache WHERE ip = ?', (ip_address,))

    def get_exempt_list(self):
        with self.conn:
            cursor = self.conn.execute('SELECT ip FROM cache WHERE exemption = 1')
            return [row[0] for row in cursor.fetchall()]

    def list_dns_exemptions(self):
        with self.conn:
            cursor = self.conn.execute("SELECT value FROM exemptions WHERE type='dns'")
            return [row[0] for row in cursor.fetchall()]

    def __del__(self):
        self.conn.close()

class ProxyChecker:
    def __init__(self, api_key, api_url, cache, proxycheck_api_key, proxycheck_api_url):
        self.api_key = api_key
        self.api_url = api_url
        self.cache = cache
        self.proxycheck_api_key = proxycheck_api_key
        self.proxycheck_api_url = proxycheck_api_url

    def is_proxy(self, ip_address):
        cached_result = self.cache.get_cached_result(ip_address)
        if cached_result is not None:
            logging.debug(f"Cache hit for {ip_address}: {cached_result}")
            return cached_result

        if self.check_proxy_api(ip_address) or self.check_proxycheck_io(ip_address):
            self.cache.set_cached_result(ip_address, True)
            return True

        self.cache.set_cached_result(ip_address, False)
        return False

    def check_proxy_api(self, ip_address):
        params = {
            'key': self.api_key,
            'ip': ip_address,
            'format': 'json'
        }
        try:
            response = requests.get(self.api_url, params=params)
            response.raise_for_status()
            data = response.json()
            logging.debug(f"API response data for {ip_address}: {data}")
            return bool(data.get('proxy'))
        except requests.RequestException as e:
            logging.error(f"API request failed for {ip_address}: {e}")
            return False

    def check_proxycheck_io(self, ip_address):
        params = {
            'key': self.proxycheck_api_key,
            'vpn': 1,
            'asn': 1,
            'node': 1,
            'inf': 1
        }
        url = f"{self.proxycheck_api_url}/{ip_address}"
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            logging.debug(f"Proxycheck.io response data for {ip_address}: {data}")
            result = data.get(ip_address, {})
            return result.get('proxy', 'no') == 'yes'
        except requests.RequestException as e:
            logging.error(f"Proxycheck.io request failed for {ip_address}: {e}")
            return False

    def get_ip_info(self, ip_address):
        """Get full IP info from proxycheck.io"""
        params = {
            'key': self.proxycheck_api_key,
            'vpn': 1,
            'asn': 1,
            'node': 1,
            'inf': 1
        }
        url = f"{self.proxycheck_api_url}/{ip_address}"
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            logging.debug(f"IP info from proxycheck.io for {ip_address}: {data}")
            return data.get(ip_address, {})
        except requests.RequestException as e:
            logging.error(f"Proxycheck.io request failed for {ip_address}: {e}")
            return None

    def exempt_ip(self, ip_address):
        if self.cache.is_exempt(ip_address):
            return False  # Already exempted
        self.cache.set_exemption(ip_address, True)
        return True  # Newly exempted

    def remove_exemption(self, ip_address):
        self.cache.set_exemption(ip_address, False)

    def list_exemptions(self):
        return self.cache.get_exempt_list()

    def add_dns_exemption(self, dns_pattern):
        with self.cache.conn:
            cursor = self.cache.conn.execute("SELECT 1 FROM exemptions WHERE type='dns' AND value=?", (dns_pattern,))
            if cursor.fetchone():
                return False  # DNS exemption already exists
            self.cache.conn.execute("INSERT INTO exemptions (type, value) VALUES ('dns', ?)", (dns_pattern,))
            return True  # Successfully added

    def remove_dns_exemption(self, dns_pattern):
        with self.cache.conn:
            cursor = self.cache.conn.execute("DELETE FROM exemptions WHERE type='dns' AND value=?", (dns_pattern,))
            return cursor.rowcount > 0  # Returns True if something was deleted

    def list_dns_exemptions(self):
        with self.cache.conn:
            cursor = self.cache.conn.execute("SELECT value FROM exemptions WHERE type='dns'")
            return [row[0] for row in cursor.fetchall()]
