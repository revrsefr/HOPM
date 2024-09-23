import logging
import configparser
from logging.handlers import RotatingFileHandler
from bot import ProxyCheckBot
from proxy_checker import ProxyChecker, ProxyCache

# Configure rotating logging
log_handler = RotatingFileHandler('proxy_check_bot.log', maxBytes=5*1024*1024, backupCount=5)
log_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[log_handler])

def load_config(file_path):
    """Load the configuration from the given INI file"""
    config = configparser.ConfigParser()
    config.read(file_path)
    return config

if __name__ == "__main__":
    try:
        config = load_config('config.ini')

        server = config.get('irc', 'server')
        port = config.getint('irc', 'port')
        channel = config.get('irc', 'channel')
        nickname = config.get('irc', 'nickname')
        oper_username = config.get('irc', 'oper_username')
        oper_password = config.get('irc', 'oper_password')

        api_key = config.get('proxy', 'api_key')
        api_url = config.get('proxy', 'api_url')
        proxycheck_api_key = config.get('proxycheck', 'api_key')
        proxycheck_api_url = config.get('proxycheck', 'api_url')

        admin_list = config.get('admin', 'admin_list').split(',')

        # Set up the cache and the proxy checker
        cache = ProxyCache(db_path='proxy_cache.db', expiry_days=1)
        proxy_checker = ProxyChecker(api_key, api_url, cache, proxycheck_api_key, proxycheck_api_url)

        # Initialize and start the bot
        dns_exemptions = ['*.irccloud.com', '*.kiwiirc.com']  # Add wildcard DNS exemptions here
        bot = ProxyCheckBot(server, port, nickname, channel, oper_username, oper_password, proxy_checker, admin_list, dns_exemptions)
        bot.start()

    except Exception as e:
        logging.exception("An error occurred while starting the bot")
