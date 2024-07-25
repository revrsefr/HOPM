import irc.bot
import logging
import re
from ipaddress import ip_address, IPv4Address, IPv6Address

class ProxyCheckBot(irc.bot.SingleServerIRCBot):
    def __init__(self, server, port, nickname, channel, oper_username, oper_password, proxy_checker, admin_list):
        super().__init__([(server, port)], nickname, nickname)
        self.channel = channel
        self.oper_username = oper_username
        self.oper_password = oper_password
        self.proxy_checker = proxy_checker
        self.admin_list = admin_list

    def on_welcome(self, connection, event):
        connection.oper(self.oper_username, self.oper_password)
        connection.join(self.channel)

    def on_pubmsg(self, connection, event):
        channel = event.target
        user = event.source
        message = event.arguments[0]

        if channel == self.channel and self.is_admin(user):
            logging.debug(f"Admin command received: {message}")
            if message.startswith("!hopm exempt "):
                parts = message.split()
                if len(parts) == 4:
                    command = parts[2]
                    ip_str = parts[3]
                    if self.is_valid_ip(ip_str) and not self.is_private_ip(ip_str):
                        if command == 'add':
                            if self.proxy_checker.exempt_ip(ip_str):
                                connection.privmsg(self.channel, f"IP {ip_str} has been exempted from proxy checks.")
                            else:
                                connection.privmsg(self.channel, f"IP {ip_str} is already exempted.")
                        elif command == 'del':
                            self.proxy_checker.remove_exemption(ip_str)
                            connection.privmsg(self.channel, f"IP {ip_str} exemption has been removed.")
                    elif command == 'list':
                        exempt_list = self.proxy_checker.list_exemptions()
                        connection.privmsg(self.channel, f"Exempted IPs: {', '.join(exempt_list)}")

    def on_privnotice(self, connection, event):
        message = event.arguments[0]

        if "REMOTECONNECT" in message:
            return

        ip_str, nick = self.extract_ip_and_nick_from_privnotice(message)

        if ip_str and nick:
            if self.is_valid_ip(ip_str) and not self.is_private_ip(ip_str):
                if self.proxy_checker.is_proxy(ip_str):
                    uid = self.generate_uid()
                    self.zline_ip(connection, ip_str, uid)
                    connection.privmsg(self.channel, f"Scanned {nick}@{ip_str}. Response positive: User has been banned from the server: Proxy. ID: {uid}")
                else:
                    connection.privmsg(self.channel, f"Scanned {nick}@{ip_str}. Response None: User passed control of HOPM.")

    def on_ctcp(self, connection, event):
        if event.arguments[0] == "VERSION":
            connection.ctcp_reply(event.source.nick, f"VERSION ProxyCheckBot v1.0")

    def is_admin(self, user):
        return user in self.admin_list

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
        match = re.search(r"CONNECT: Client connecting on port \d+ \(class .+\): (.*?)!.*?@.*?\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+)\)", message)
        return (match.group(2), match.group(1)) if match else (None, None)

    def zline_ip(self, connection, ip_address, uid):
        connection.send_raw(f"ZLINE *@{ip_address} 1d :Proxy detected, Z-lined by HOPM.")

    def generate_uid(self):
        return str(uuid.uuid4()).split('-')[0].upper()
