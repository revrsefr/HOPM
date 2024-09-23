import irc.bot
import logging
import re
import socket
from ipaddress import ip_address, IPv4Address, IPv6Address
from fnmatch import fnmatch
from proxy_checker import ProxyChecker

class ProxyCheckBot(irc.bot.SingleServerIRCBot):
    def __init__(self, server, port, nickname, channel, oper_username, oper_password, proxy_checker, admin_list, dns_exemptions):
        super().__init__([(server, port)], nickname, nickname)
        self.channel = channel
        self.oper_username = oper_username
        self.oper_password = oper_password
        self.proxy_checker = proxy_checker
        self.admin_list = admin_list
        self.dns_exemptions = dns_exemptions

    def on_welcome(self, connection, event):
        connection.oper(self.oper_username, self.oper_password)
        connection.join(self.channel)

    def on_pubmsg(self, connection, event):
        message = safe_decode(event.arguments[0])
        user = event.source

        # Log the received message for debugging
        logging.debug(f"Received public message from {user}: {message}")

        # If the user is an admin, process the command
        if self.is_admin(user):
            parts = message.split()
            if message.startswith("!hopm exempt "):
                if len(parts) >= 3:
                    command = parts[2]
                    if command == 'add' and len(parts) == 4:
                        ip_str = parts[3]
                        if self.is_valid_ip(ip_str) and not self.is_private_ip(ip_str):
                            if self.proxy_checker.exempt_ip(ip_str):
                                connection.privmsg(self.channel, f"IP {ip_str} agregado a lista blanca.")
                            else:
                                connection.privmsg(self.channel, f"La IP {ip_str} ya se encuentra en la lista blanca.")
                    elif command == 'del' and len(parts) == 4:
                        ip_str = parts[3]
                        if self.is_valid_ip(ip_str):
                            self.proxy_checker.remove_exemption(ip_str)
                            connection.privmsg(self.channel, f"IP {ip_str} borrada de la lista blanca.")
                    elif command == 'dns' and len(parts) == 5 and parts[3] == 'add':
                        dns_pattern = parts[4]
                        if self.proxy_checker.add_dns_exemption(dns_pattern):
                            connection.privmsg(self.channel, f"DNS exemption added: {dns_pattern}")
                        else:
                            connection.privmsg(self.channel, f"{dns_pattern} is already exempt.")
                    elif command == 'dns' and len(parts) == 5 and parts[3] == 'del':
                        dns_pattern = parts[4]
                        if self.proxy_checker.remove_dns_exemption(dns_pattern):
                            connection.privmsg(self.channel, f"DNS exemption removed: {dns_pattern}")
                        else:
                            connection.privmsg(self.channel, f"{dns_pattern} is not in the exemptions list.")
                    elif command == 'dns' and parts[3] == 'list':
                        dns_exempt_list = self.proxy_checker.list_dns_exemptions()
                        if dns_exempt_list:
                            connection.privmsg(self.channel, f"DNS Lista blanca: {', '.join(dns_exempt_list)}")
                        else:
                            connection.privmsg(self.channel, "No DNS exemptions found.")
                    elif command == 'list':
                        exempt_list = self.proxy_checker.list_exemptions()
                        if exempt_list:
                            connection.privmsg(self.channel, f"Lista blanca de IP's: {', '.join(exempt_list)}")
                        else:
                            connection.privmsg(self.channel, "Lista blanca vacia.")
            elif message.startswith(">info"):
                if len(parts) == 2:
                    ip_str = parts[1]
                    if self.is_valid_ip(ip_str):
                        info = self.proxy_checker.get_ip_info(ip_str)
                        if info:
                            connection.privmsg(self.channel, f"IP {ip_str} - Country: {info.get('country')}, City: {info.get('city')}, Proxy: {info.get('proxy')}, ASN: {info.get('asn')}, Type: {info.get('type')}")
                        else:
                            connection.privmsg(self.channel, f"No information available for IP {ip_str}")
                    else:
                        connection.privmsg(self.channel, f"{ip_str} is not a valid IP.")
            else:
                logging.debug(f"Ignored message: {message}")

    def on_privnotice(self, connection, event):
        message = safe_decode(event.arguments[0])
        logging.debug(f"Received privnotice: {message}")

        if "Client connecting:" in message:
            ip_str, nick = self.extract_ip_and_nick_from_privnotice(message)

            if ip_str and nick:
                logging.debug(f"Extracted IP: {ip_str}, Nick: {nick}")
                if self.is_valid_ip(ip_str) and not self.is_private_ip(ip_str):
                    if self.is_dns_exempt(ip_str):
                        logging.info(f"{nick}@{ip_str} is exempted due to DNS match.")
                        return

                    if self.proxy_checker.is_proxy(ip_str):
                        self.zline_ip(connection, ip_str)
                        connection.privmsg(self.channel, f"Alerta: {nick}@{ip_str}. Usuario baneado del servidor motivo: Proxy/VPN")
                    else:
                        logging.info(f"{nick}@{ip_str} passed the proxy/VPN check.")
                else:
                    logging.debug(f"Invalid or private IP: {ip_str}")
            else:
                logging.debug(f"No valid IP or nickname found in privnotice.")

    def on_ctcp(self, connection, event):
        if event.arguments[0] == "VERSION":
            connection.ctcp_reply(event.source.nick, f"VERSION: killer by reverse v1.0")

    def is_admin(self, user):
        for admin in self.admin_list:
            if fnmatch(user, admin):
                return True
        return False

    def is_valid_ip(self, ip_str):
        try:
            ip = ip_address(ip_str)
            return isinstance(ip, (IPv4Address, IPv6Address))
        except ValueError:
            return False

    def is_private_ip(self, ip_str):
        try:
            ip = ip_address(ip_str)
            return ip.is_private or ip.is_link_local
        except ValueError:
            return False

    def extract_ip_and_nick_from_privnotice(self, message):
        match = re.search(r"Client connecting: (.*?) \((.*?)@.*?\) \[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+)\]", message)
        return (match.group(3), match.group(1)) if match else (None, None)

    def zline_ip(self, connection, ip_address):
        connection.send_raw(f"GZLINE *@{ip_address} 1d :Usuario baneado del servidor motivo: Proxy/VPN. Si crees que es un error manda un correo a info@matojeand.com")

    # Perform reverse DNS lookup and check against DNS exemptions
    def is_dns_exempt(self, ip_str):
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]  # Get the hostname from the IP
            logging.debug(f"Reverse DNS lookup for {ip_str}: {hostname}")

            # Check if the hostname matches any of the DNS exemptions (wildcard matching)
            for pattern in self.dns_exemptions:
                if fnmatch(hostname, pattern):
                    logging.info(f"IP {ip_str} is exempted due to matching hostname: {hostname}")
                    return True
        except (socket.herror, socket.gaierror):
            logging.debug(f"Failed reverse DNS lookup for {ip_str}.")
        return False

# Safe decoding to avoid UnicodeDecodeError
def safe_decode(message):
    try:
        return message.decode("utf-8", errors="replace")  # Try UTF-8 first
    except (UnicodeDecodeError, AttributeError):
        try:
            return message.decode("latin-1", errors="replace")  # Fallback to Latin-1
        except AttributeError:
            return message  # If it's already a string (Python 3 strings are unicode)
