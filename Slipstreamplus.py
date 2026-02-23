import sys
import signal
import os
import subprocess
import threading
import time
import socket
import json
import atexit
import random
import ipaddress
import ssl
try:
    import ctypes
    import winreg
except ImportError:
    ctypes = None  # type: ignore
    winreg = None  # type: ignore

from urllib.parse import unquote, quote, urlparse, parse_qs
from queue import Queue, Empty
from typing import Optional, List, Dict, Tuple

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QListWidget,
    QListWidgetItem,
    QAbstractItemView,
    QPushButton,
    QLineEdit,
    QTextEdit,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QMessageBox,
    QMenu,
    QSystemTrayIcon,
    QFileDialog,
    QCheckBox,
    QTabWidget,
    QProgressBar,
    QGroupBox,
    QTableWidget,
    QTableWidgetItem,
    QInputDialog,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QComboBox,
    QHeaderView,
    QSplitter,
    QStyledItemDelegate,
    QStyle,
    QStyleOptionViewItem,
    QRadioButton,
)
from PySide6.QtCore import QObject, Signal, Qt, QEvent, QTimer, QSize, QRectF, QSharedMemory
from PySide6.QtGui import QColor, QBrush, QPalette, QIcon, QAction, QKeySequence, QPainter, QFont, QFontMetrics
from PySide6.QtSvg import QSvgRenderer

# Optional websocket-client for Clash API traffic endpoint
try:
    import websocket  # type: ignore
    HAS_WEBSOCKET = True
except Exception:
    websocket = None  # type: ignore
    HAS_WEBSOCKET = False


# ================= RESOURCE PATH FIX =================
def app_base_path() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(".")


def resource_path(relative_path: str) -> str:
    """Get absolute path to resource (dev and bundled)."""
    base_path = app_base_path()
    candidate = os.path.join(base_path, relative_path)
    if os.path.exists(candidate):
        return candidate
    try:
        meipass = sys._MEIPASS  # type: ignore[attr-defined]
        return os.path.join(meipass, relative_path)
    except Exception:
        return candidate


def bin_path(filename: str) -> str:
    path = resource_path(os.path.join("bin", filename))
    if os.name != "nt" and os.path.exists(path):
        import stat
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC)
    return path


def config_path(filename: str) -> str:
    base = app_base_path()
    dir_path = os.path.join(base, CONFIG_DIR_NAME)
    os.makedirs(dir_path, exist_ok=True)
    return os.path.join(dir_path, filename)


# ================= CONSTANTS & CONFIG =================
APP_ID = "Farhad.Slipstreamplus.v1"
APP_TITLE = "Slipstream Plus"
APP_VERSION = "v1.0"
DIALOG_TITLE = APP_TITLE
ICON_NAME = "icon.ico"

DNS_FILE_NAME = "dns.txt"
CONFIG_DIR_NAME = "config"
CONFIG_FILE_NAME = "settings.json"
RUNTIME_CONFIG_NAME = "config.json"

DEFAULT_DNS_LIST = """8.8.8.8
1.1.1.1
94.140.14.14
76.76.2.0
"""

DEFAULT_CONFIG: Dict[str, object] = {
    "domain": "",
    "mixed_port": 10808,
    "lan_mode": False,
    "auto_reconnect": True,
    "last_selected_dns": "",
    "saved_results": {},
    "proxy_rows": [],
    "last_selected_proxy": "",
    "proxy_mode": "Global",
    "proxy_system_set": False,

    # Scanner
    "fastscan_timeout_ms": 800,
    "fastscan_threads": 200,
    "cidr_random_sample": 0,   # 0 = off
    "cidr_expand_cap": 4096,   # max IPs to expand per CIDR when random_sample=0
    "real_ping_delay_ms": 2000,  # Slipstream ready timeout (ms)
    "scan_realtest": False,
}

SPEED_TEST_URL = "https://cachefly.cachefly.net/10mb.test"

if sys.platform == "win32":
    SLIPSTREAM_BIN = "slipstream-client-windows-amd64.exe"
    SINGBOX_BIN = "sing-box.exe"
else:
    SLIPSTREAM_BIN = "slipstream-client-linux-amd64"
    SINGBOX_BIN = "sing-box"


# ================= Utils =================
def get_free_port() -> int:
    try:
        s = socket.socket()
        s.bind(("", 0))
        port = int(s.getsockname()[1])
        s.close()
        return port
    except Exception:
        return random.randint(30000, 60000)


def _normalize_lines(lines: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in lines:
        x = x.strip()
        if not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def load_dns_from_file() -> List[str]:
    # dns.txt is disabled
    return []


def save_dns_to_file(dns_list: List[str]) -> None:
    # dns.txt is disabled
    return


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except Exception:
        return False

def _split_dns_csv(value: str) -> List[str]:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return _normalize_lines(parts)

def _normalize_dns_csv(value: str) -> Optional[str]:
    parts = _split_dns_csv(value)
    if not parts:
        return None
    for p in parts:
        if not is_valid_ip(p):
            return None
    return ",".join(parts)

def _primary_dns(value: str) -> str:
    parts = _split_dns_csv(value)
    return parts[0] if parts else value.strip()

def _resolver_args_from_dns(value: str) -> List[str]:
    parts = _split_dns_csv(value)
    args: List[str] = []
    for p in parts:
        args += ["--resolver", f"{p}:53"]
    return args

def _safe_qs_first(parsed, key: str) -> str:
    try:
        vals = parse_qs(parsed.query or "").get(key, [])
        if vals:
            return str(vals[0] or "").strip()
    except Exception:
        pass
    return ""

def _strip_port(ip: str) -> str:
    s = ip.strip()
    if ":" in s:
        s = s.split(":", 1)[0].strip()
    return s

def _parse_scan_token(token: str) -> Tuple[str, Optional[str]]:
    t = token.strip()
    if not t:
        return "", None
    if "/" in t:
        return "cidr", t
    ip = _strip_port(t)
    if is_valid_ip(ip):
        return "ip", ip
    return "", None

def is_success_result(result: str) -> bool:
    if not result:
        return False
    low = result.lower()
    return ("ok" in low) or ("alive" in low)


def _cidr_sample_ips(cidr: str, sample: int, cap: int) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []
    if net.version != 4:
        return []

    total_addrs = int(net.num_addresses)
    if total_addrs <= 0:
        return []

    # include full range (like original scanner)
    start = 0
    end = total_addrs

    count = max(end - start, 0)
    if count <= 0:
        return []

    if sample > 0:
        k = min(sample, count)
        if k <= 0:
            return []
        # random.sample(range) is efficient without building a list
        picks = random.sample(range(start, end), k)
        return [str(net.network_address + int(off)) for off in picks]

    # non-random: take first k without expanding all
    k = min(cap, count)
    if k <= 0:
        return []
    return [str(net.network_address + int(off)) for off in range(start, start + k)]


def load_config() -> Dict[str, object]:
    os.makedirs(CONFIG_DIR_NAME, exist_ok=True)
    cfg_path = os.path.join(CONFIG_DIR_NAME, CONFIG_FILE_NAME)
    if not os.path.exists(cfg_path):
        save_config(dict(DEFAULT_CONFIG))
        return dict(DEFAULT_CONFIG)

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                if k not in data:
                    data[k] = v
            return data
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(config_data: Dict[str, object]) -> None:
    try:
        os.makedirs(CONFIG_DIR_NAME, exist_ok=True)
        cfg_path = os.path.join(CONFIG_DIR_NAME, CONFIG_FILE_NAME)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4)
    except Exception:
        pass


def taskkill_names(names: List[str]) -> None:
    for n in names:
        try:
            if os.name == "nt":
                subprocess.run(
                    f"taskkill /F /IM {n}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.run(
                    ["killall", "-9", n],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception:
            pass


def interrupt_process(proc: Optional[subprocess.Popen]) -> bool:
    if not proc:
        return False
    try:
        if proc.poll() is not None:
            return True
        if os.name == "nt":
            try:
                proc.send_signal(subprocess.signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                return True
            except Exception:
                pass
        proc.terminate()
        return True
    except Exception:
        return False


# ================= System Proxy Utils =================
try:
    INTERNET_SETTINGS = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_ALL_ACCESS,
    )
except Exception:
    INTERNET_SETTINGS = None


def set_system_proxy(port: int) -> bool:
    if sys.platform != "win32" or not INTERNET_SETTINGS:
        return False
    try:
        winreg.SetValueEx(INTERNET_SETTINGS, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(INTERNET_SETTINGS, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        return True
    except Exception:
        return False


def clear_system_proxy() -> bool:
    if sys.platform != "win32" or not INTERNET_SETTINGS:
        return False
    try:
        winreg.SetValueEx(INTERNET_SETTINGS, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        return True
    except Exception:
        return False


# ================= Signals =================
class Emitter(QObject):
    log = Signal(str, str)  # level, message
    status = Signal(str)
    scan_finished = Signal()
    traffic_update = Signal(str, str, str, str)
    connection_drop = Signal(str)
    import_done = Signal(object)
    scan_stats_updated = Signal()
    scan_timer_start = Signal()
    scan_timer_stop = Signal()
    connect_request = Signal(str)
    disconnect_request = Signal()
    real_ping_progress = Signal(int)
    real_ping_test_row = Signal(int)


class ActiveBadgeDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option, index) -> None:
        text = str(index.data() or "")
        is_active = bool(index.data(Qt.UserRole + 2))
        before_text, after_text, svg_path = self._split_flag_text(text)

        opt = QStyleOptionViewItem(option)
        opt.font = QFont("Segoe UI Emoji")
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.CE_ItemViewItem, opt, painter, opt.widget)

        rect = opt.rect.adjusted(6, 0, -6, 0)
        fm = QFontMetrics(opt.font)
        badge_w = 0
        if is_active:
            badge_text = "Active"
            badge_w = fm.horizontalAdvance(badge_text) + 12 + 8
            rect.setRight(rect.right() - badge_w)

        pen_color = opt.palette.color(QPalette.HighlightedText) if opt.state & QStyle.State_Selected else opt.palette.color(QPalette.Text)
        painter.save()
        painter.setFont(opt.font)
        painter.setPen(pen_color)

        x = rect.left()
        y = rect.center().y() + (fm.ascent() - fm.descent()) // 2

        if before_text:
            painter.drawText(x, y, before_text)
            x += fm.horizontalAdvance(before_text)

        if svg_path:
            flag_h = min(rect.height(), fm.height())
            flag_w = int(flag_h * 4 / 3)
            flag_rect = QRectF(x + 4, rect.center().y() - flag_h / 2, flag_w, flag_h)
            try:
                renderer = QSvgRenderer(svg_path)
                renderer.render(painter, flag_rect)
                x = flag_rect.right() + 4
            except Exception:
                pass

        if after_text:
            painter.drawText(x, y, after_text)

        painter.restore()

        if not is_active:
            return

        painter.save()
        rect = opt.rect.adjusted(6, 0, -6, 0)

        fm = painter.fontMetrics()
        badge_text = "Active"
        badge_w = fm.horizontalAdvance(badge_text) + 12
        badge_h = max(16, fm.height() - 2)

        badge_rect = rect
        badge_rect.setLeft(rect.right() - badge_w)
        badge_rect.setTop(rect.center().y() - badge_h // 2)
        badge_rect.setBottom(badge_rect.top() + badge_h)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#e53935"))
        painter.drawRoundedRect(badge_rect, 6, 6)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(badge_rect, Qt.AlignCenter, badge_text)

        painter.restore()

    @staticmethod
    def _split_flag_text(text: str) -> Tuple[str, str, Optional[str]]:
        # Detect flag emoji (regional indicator pair) and map to asset\flag\<code>.svg
        def _is_regional(ch: str) -> bool:
            o = ord(ch)
            return 0x1F1E6 <= o <= 0x1F1FF

        def _remove_flags(s: str) -> str:
            out = []
            i = 0
            while i < len(s):
                if i + 1 < len(s) and _is_regional(s[i]) and _is_regional(s[i + 1]):
                    i += 2
                    continue
                out.append(s[i])
                i += 1
            return "".join(out)

        code = ""
        idx = -1
        for i in range(len(text) - 1):
            a = text[i]
            b = text[i + 1]
            if _is_regional(a) and _is_regional(b):
                code = chr(ord("a") + (ord(a) - 0x1F1E6)) + chr(ord("a") + (ord(b) - 0x1F1E6))
                idx = i
                break

        if not code:
            return text, "", None

        svg_path = resource_path(os.path.join("asset", "flag", f"{code}.svg"))
        if not os.path.exists(svg_path):
            return text, "", None

        before = _remove_flags(text[:idx])
        after = _remove_flags(text[idx + 2 :])
        return before, after, svg_path


# ================= Traffic Monitor Thread =================
class TrafficMonitor(threading.Thread):
    """
    Clash API traffic endpoint is typically a WebSocket (/traffic).
    If websocket-client isn't available, we disable traffic monitor to avoid spam.
    """
    def __init__(self, api_port: int, emitter: Emitter):
        super().__init__(daemon=True)
        self.api_port = api_port
        self.emitter = emitter
        self.running = True
        self.total_up = 0
        self.total_down = 0
        self._ws = None
        self._last_warn_ts = 0.0
        self._warn_cooldown = 10.0  # seconds

    def run(self) -> None:
        time.sleep(2)
        if not HAS_WEBSOCKET:
            return

        ws_url = f"ws://127.0.0.1:{self.api_port}/traffic"

        def on_message(ws, message):
            if not self.running:
                return
            try:
                data = json.loads(message)
                up_speed = int(data.get("up", 0))
                down_speed = int(data.get("down", 0))
                self.total_up += up_speed
                self.total_down += down_speed
                self.emitter.traffic_update.emit(
                    self.format_bytes(up_speed) + "/s",
                    self.format_bytes(down_speed) + "/s",
                    self.format_bytes(self.total_up),
                    self.format_bytes(self.total_down),
                )
            except Exception:
                pass

        def _warn(msg: str):
            return

        def on_error(ws, error):
            if self.running:
                _warn(f"Traffic API error. Retrying... ({error})")

        def on_close(ws, close_status_code, close_msg):
            if self.running:
                _warn("Traffic API disconnected. Retrying...")

        while self.running:
            try:
                self._ws = websocket.WebSocketApp(  # type: ignore[attr-defined]
                    ws_url,
                    on_message=on_message,
                    on_error=on_error,
                    on_close=on_close,
                )
                self._ws.run_forever(ping_interval=15, ping_timeout=5)
            except Exception as e:
                if self.running:
                    _warn(f"Traffic API disconnected. Retrying... ({e})")
            time.sleep(2)

    @staticmethod
    def format_bytes(size: float) -> str:
        power = 2**10
        n = 0
        labels = {0: "", 1: "K", 2: "M", 3: "G", 4: "T"}
        while size > power and n < 4:
            size /= power
            n += 1
        return f"{size:.2f} {labels[n]}B"

    def stop(self) -> None:
        self.running = False
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass


# ================= Fast DNS Tunnel Check =================
def _encode_dns_query(qname: str, qtype: int = 1) -> bytes:
    # Minimal DNS query encoder (A record by default)
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # recursion desired
    qdcount = 1
    header = tid.to_bytes(2, "big") + flags.to_bytes(2, "big") + qdcount.to_bytes(2, "big") + b"\x00\x00\x00\x00\x00\x00"
    parts = qname.strip(".").split(".")
    q = b""
    for p in parts:
        if not p:
            continue
        q += bytes([len(p)]) + p.encode("ascii", "ignore")
    q += b"\x00"
    q += qtype.to_bytes(2, "big") + b"\x00\x01"  # IN class
    return header + q


def _parse_dns_rcode(resp: bytes) -> Optional[int]:
    if len(resp) < 4:
        return None
    flags = int.from_bytes(resp[2:4], "big")
    return flags & 0x000F


def fast_dns_tunnel_check(dns_ip: str, domain: str, timeout_ms: int) -> Tuple[bool, str]:
    """
    Fast tunnel detection:
    Send random subdomain query to dns_ip:53, accept NOERROR(0) or NXDOMAIN(3) as alive.
    """
    domain = domain.strip().strip(".")
    if not domain:
        return False, "Domain empty"

    rand = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10))
    qname = f"{rand}.{domain}"
    payload = _encode_dns_query(qname, qtype=1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(max(timeout_ms, 50) / 1000.0)
    start = time.monotonic()
    try:
        s.sendto(payload, (dns_ip, 53))
        resp, _ = s.recvfrom(4096)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if elapsed_ms > timeout_ms:
            return False, "TIMEOUT"
        rcode = _parse_dns_rcode(resp)
        if rcode is None:
            return False, "BadResp"
        if rcode == 0:
            return True, f"OK (Resolved) [{elapsed_ms}ms]"
        if rcode == 3:
            return True, f"Tunnel Alive (NX) [{elapsed_ms}ms]"
        if rcode == 2:
            return False, f"ServFail (Blocked?) [{elapsed_ms}ms]"
        if rcode == 5:
            return False, f"Refused [{elapsed_ms}ms]"
        return False, f"RCODE {rcode} [{elapsed_ms}ms]"
    except socket.timeout:
        return False, "TIMEOUT"
    except Exception:
        return False, "Connect Err"
    finally:
        try:
            s.close()
        except Exception:
            pass


# ================= Main GUI =================
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.config = load_config()

        self.setWindowTitle(APP_TITLE)
        self.resize(1050, 720)
        self.setMinimumSize(900, 620)

        icon_path = resource_path(ICON_NAME)
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon.fromTheme("network-wireless"))

        # processes
        self.proc_tunnel: Optional[subprocess.Popen] = None
        self.proc_singbox: Optional[subprocess.Popen] = None
        self.traffic_thread: Optional[TrafficMonitor] = None

        self.running = False
        self.reconnecting = False
        self.graceful_stop = False
        self.current_dns_ip: Optional[str] = None
        self.current_domain: Optional[str] = None
        self.current_proxy_remark: str = ""
        self.current_proxy_username: str = ""
        self.current_proxy_password: str = ""
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.reconnect_timer: Optional[threading.Timer] = None

        # scanner
        self.scan_running = False
        self.scan_stop = threading.Event()
        self.scan_threads: List[threading.Thread] = []
        self.scan_pause_event = threading.Event()
        self.scan_queue: Queue[Tuple[str, str, int]] = Queue()
        self.scan_log_queue: Queue[str] = Queue()
        self.ping_queue: Queue[Tuple[int, str]] = Queue()
        self.scan_realtest_worker: Optional[threading.Thread] = None
        self.scan_realtest_lock = threading.Lock()
        self.scan_realtest_next_row = 0
        self.scan_lock = threading.Lock()
        self.scan_total = 0
        self.scan_checked = 0
        self.scan_success = 0
        self.scan_fail = 0
        self.scan_produced = 0
        self.closing = False
        self.real_ping_running = False
        self.real_ping_stop = threading.Event()
        self.conn_state_lock = threading.Lock()
        self.conn_connected_event = threading.Event()
        self.conn_state = "stopped"
        self.scan_ui_timer = QTimer()
        self.scan_ui_timer.setInterval(50)
        self.scan_ui_timer.timeout.connect(self._scan_ui_tick)
        self._scan_ui_tick_running = False
        self.scan_file_path = ""
        self.scan_processed = set()
        self.scan_logs_visible = True
        self.slipstream_ready_event = threading.Event()
        self.real_ping_total = 0
        self.real_ping_done = 0
        self._proxy_edit_guard = False
        self._imported_dns_list: List[str] = []
        self._loading_proxy_rows = False

        # signals
        self.emitter = Emitter()
        self.emitter.log.connect(self.logw)
        self.emitter.status.connect(self.set_status)
        self.emitter.scan_finished.connect(self.on_scan_finished)
        self.emitter.traffic_update.connect(self.update_traffic_labels)
        self.emitter.connection_drop.connect(self.handle_connection_drop)
        self.emitter.import_done.connect(self.on_import_done)
        self.emitter.scan_stats_updated.connect(self._scan_ui_tick)
        self.emitter.scan_timer_start.connect(self._start_scan_ui_timer)
        self.emitter.scan_timer_stop.connect(self._stop_scan_ui_timer)
        self.emitter.connect_request.connect(self._on_connect_request)
        self.emitter.disconnect_request.connect(self._on_disconnect_request)
        self.emitter.real_ping_progress.connect(self._set_real_ping_progress)
        self.emitter.real_ping_test_row.connect(self._set_real_ping_testing_row)

        # widgets shared
        self.dns_list_widget = QListWidget()
        self.dns_list_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.dns_list_widget.setStyleSheet("QListWidget::item { padding: 5px; }")
        self.dns_list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dns_list_widget.customContextMenuRequested.connect(self.show_dns_context_menu)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_box.customContextMenuRequested.connect(self.show_log_context_menu)
        self.log_box.setStyleSheet("background:#0f0f0f;color:#00ff00;font-family:Consolas;font-size:11px;")

        self.proxy_log_box = QTextEdit()
        self.proxy_log_box.setReadOnly(True)
        self.proxy_log_box.setStyleSheet("background:#0f0f0f;color:#d0d0d0;font-family:Consolas;font-size:11px;")

        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet("font-weight: bold; font-size: 14px;")

        # tray
        self.tray_icon = QSystemTrayIcon(self)
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            pixmap = QIcon.fromTheme("application-exit").pixmap(64, 64)
            self.tray_icon.setIcon(QIcon(pixmap))

        self.tray_menu = QMenu()
        self.act_set_proxy = QAction("Set System Proxy", self)
        self.act_set_proxy.triggered.connect(self.enable_system_proxy)
        self.act_clear_proxy = QAction("Clear System Proxy", self)
        self.act_clear_proxy.triggered.connect(self.disable_system_proxy)
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show_window)
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.close_app)
        self.tray_menu.addAction(self.act_set_proxy)
        self.tray_menu.addAction(self.act_clear_proxy)
        self.tray_menu.addSeparator()
        self.tray_menu.addAction(show_action)
        self.tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(self.tray_menu)
        self.tray_icon.activated.connect(self.on_tray_click)
        self.tray_icon.show()

        # build UI
        self.build_ui()
        self._sync_system_proxy_state()
        self._load_proxy_rows_from_config()
        self._update_proxy_connect_state()
        QTimer.singleShot(0, self._auto_connect_active_proxy)
        # Do not auto-load DNS list on startup
        atexit.register(self.force_stop)

    # ================= UI =================
    def build_ui(self) -> None:
        self.tabs = QTabWidget()

        # --- Proxy tab ---
        self.proxy_tab = QWidget()
        proxy_layout = QVBoxLayout(self.proxy_tab)

        proxy_controls = QHBoxLayout()
        self.btn_proxy_import = QPushButton("Import Links...")
        self.btn_proxy_import.clicked.connect(self.import_proxy_links)
        self.btn_proxy_add = QPushButton("Add Config")
        self.btn_proxy_add.clicked.connect(self.add_proxy_config_dialog)
        self.btn_proxy_copy = QPushButton("Copy Link")
        self.btn_proxy_copy.clicked.connect(self.copy_selected_proxy_link)
        self.btn_proxy_remove = QPushButton("Remove Selected")
        self.btn_proxy_remove.clicked.connect(self.remove_selected_proxy_rows)
        self.btn_proxy_settings = QPushButton("Settings")
        self.btn_proxy_settings.clicked.connect(self.open_proxy_settings_dialog)
        proxy_controls.addWidget(self.btn_proxy_import)
        proxy_controls.addWidget(self.btn_proxy_add)
        proxy_controls.addWidget(self.btn_proxy_copy)
        proxy_controls.addWidget(self.btn_proxy_remove)
        proxy_controls.addWidget(self.btn_proxy_settings)
        proxy_controls.addStretch()

        self.proxy_table = QTableWidget(0, 8)
        self.proxy_table.setHorizontalHeaderLabels(
            ["TYPE", "REMARKS", "ADDRESS", "PORT", "TRANSPORT", "DELAY (MS)", "SPEED (MB/S)", ""]
        )
        self.proxy_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.proxy_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.proxy_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.proxy_table.horizontalHeader().setStretchLastSection(True)
        self.proxy_table.setAlternatingRowColors(True)
        self.proxy_table.setShowGrid(False)
        self.proxy_table.verticalHeader().setDefaultSectionSize(28)
        self.proxy_table.setStyleSheet(
            "QTableWidget {"
            "  background-color: #1b1b1b;"
            "  alternate-background-color: #202020;"
            "  color: #e0e0e0;"
            "  border: 1px solid #2b2b2b;"
            "}"
            "QHeaderView::section {"
            "  background-color: #2a2a2a;"
            "  color: #f0f0f0;"
            "  padding: 6px;"
            "  border: 0px;"
            "  border-right: 1px solid #3a3a3a;"
            "  font-weight: bold;"
            "}"
            "QTableWidget::item {"
            "  padding: 4px 6px;"
            "}"
            "QTableWidget::item:selected {"
            "  background-color: #3a3f44;"
            "  color: #ffffff;"
            "}"
        )
        self.proxy_table.horizontalHeader().setSectionsClickable(True)
        self.proxy_table.setSortingEnabled(True)
        self.proxy_table.verticalHeader().setVisible(True)
        self.proxy_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.proxy_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.proxy_table.customContextMenuRequested.connect(self.show_proxy_context_menu)
        self.proxy_table.installEventFilter(self)
        self.proxy_table.cellChanged.connect(self.on_proxy_cell_changed)
        self.proxy_table.cellDoubleClicked.connect(self.edit_proxy_row_dialog)
        self.proxy_table.setItemDelegateForColumn(1, ActiveBadgeDelegate(self.proxy_table))
        self.proxy_table.setColumnWidth(1, 220)
        self.proxy_table.setColumnWidth(2, 200)
        self.proxy_table.setColumnWidth(7, 28)

        proxy_hint = QLabel("Paste links with Ctrl+V or use Import. Format: SLIPSTREAM://domain:53?dns=1.1.1.1,8.8.8.8#remarks")
        proxy_hint.setStyleSheet("color: #bdbdbd; font-size: 11px;")

        top_proxy = QWidget()
        top_proxy_layout = QVBoxLayout(top_proxy)
        top_proxy_layout.setContentsMargins(0, 0, 0, 0)
        top_proxy_layout.addLayout(proxy_controls)
        top_proxy_layout.addWidget(self.proxy_table)
        top_proxy_layout.addWidget(proxy_hint)

        self.proxy_log_box.setMinimumHeight(90)
        self.proxy_action_combo = QComboBox()
        self.proxy_action_combo.addItems(["Set System Proxy", "Clear System Proxy"])
        self.proxy_action_combo.setMaximumWidth(220)
        self.proxy_action_combo.currentIndexChanged.connect(self.on_proxy_action_selected)

        self.proxy_mode_combo = QComboBox()
        self.proxy_mode_combo.addItems(["Global", "IR-Direct"])
        mode = str(self.config.get("proxy_mode", "Global"))
        self.proxy_mode_combo.setCurrentText("IR-Direct" if mode == "IR-Direct" else "Global")
        self.proxy_mode_combo.currentIndexChanged.connect(self.on_proxy_mode_changed)

        self.lan_mode_chk_proxy = QCheckBox("LAN Mode (Hotspot)")
        self.lan_mode_chk_proxy.setChecked(bool(self.config.get("lan_mode", False)))
        self.lan_mode_chk_proxy.stateChanged.connect(self.on_lan_mode_changed)

        self.auto_reconnect_chk_proxy = QCheckBox("Auto Reconnect")
        self.auto_reconnect_chk_proxy.setChecked(bool(self.config.get("auto_reconnect", True)))
        self.auto_reconnect_chk_proxy.stateChanged.connect(self.on_auto_reconnect_changed)

        self.proxy_connect_btn = QPushButton("CONNECT")
        self.proxy_connect_btn.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 6px 12px;")
        self.proxy_connect_btn.clicked.connect(self.on_connect_clicked)
        self.proxy_connect_btn.setEnabled(False)

        self.proxy_clear_log_btn = QPushButton("Clear Log")
        self.proxy_clear_log_btn.clicked.connect(self.proxy_log_box.clear)

        proxy_action_row = QHBoxLayout()
        proxy_action_row.addWidget(self.proxy_action_combo)
        proxy_action_row.addSpacing(12)
        proxy_action_row.addWidget(self.proxy_mode_combo)
        proxy_action_row.addSpacing(12)
        proxy_action_row.addWidget(self.lan_mode_chk_proxy)
        proxy_action_row.addWidget(self.auto_reconnect_chk_proxy)
        proxy_action_row.addWidget(self.proxy_connect_btn)
        proxy_action_row.addWidget(self.proxy_clear_log_btn)
        proxy_action_row.addStretch()

        proxy_log_container = QWidget()
        proxy_log_layout = QVBoxLayout(proxy_log_container)
        proxy_log_layout.setContentsMargins(0, 0, 0, 0)
        proxy_log_layout.addWidget(self.proxy_log_box)
        proxy_log_layout.addLayout(proxy_action_row)

        proxy_splitter = QSplitter(Qt.Vertical)
        proxy_splitter.addWidget(top_proxy)
        proxy_splitter.addWidget(proxy_log_container)
        proxy_splitter.setSizes([520, 110])
        proxy_layout.addWidget(proxy_splitter)
        self.lbl_status_proxy = QLabel("Coder  : Farhad~UK")
        self.lbl_status_proxy.setEnabled(False)
        self.proxy_traffic_lbl = QLabel("↑ 0.00 B/s  ↓ 0.00 B/s   Total ↑ 0.00 B  ↓ 0.00 B")
        self.proxy_traffic_lbl.setStyleSheet("color: #bdbdbd; font-size: 11px;")
        proxy_footer = QHBoxLayout()
        proxy_footer.addWidget(self.lbl_status_proxy)
        proxy_footer.addSpacing(12)
        proxy_footer.addWidget(self.proxy_traffic_lbl)
        proxy_footer.addStretch()
        proxy_layout.addLayout(proxy_footer)

        self.tabs.addTab(self.proxy_tab, "Proxy")

        # --- Scanner tab ---
        scan_tab = QWidget()
        scan_layout = QHBoxLayout(scan_tab)

        left_col = QVBoxLayout()
        right_col = QVBoxLayout()

        settings_box = QGroupBox("Setting")
        settings_layout = QGridLayout(settings_box)

        settings_layout.addWidget(QLabel("CIDR/IPs:"), 0, 0)
        self.btn_browse = QPushButton("Browse And Select")
        self.btn_browse.clicked.connect(self.browse_scan_file)
        settings_layout.addWidget(self.btn_browse, 0, 1, 1, 3)

        settings_layout.addWidget(QLabel("Random Selection per CIDR (0 = all):"), 1, 0, 1, 2)
        self.num_random_count = QSpinBox()
        self.num_random_count.setRange(0, 100000)
        self.num_random_count.setValue(int(self.config.get("cidr_random_sample", 0)))
        settings_layout.addWidget(self.num_random_count, 1, 2, 1, 2)

        settings_layout.addWidget(QLabel("Domain To Check:"), 2, 0)
        self.domain_input = QLineEdit(str(self.config.get("domain", "")))
        self.domain_input.setPlaceholderText("s.yourdomain.com")
        settings_layout.addWidget(self.domain_input, 2, 1, 1, 3)

        settings_layout.addWidget(QLabel("Timeout (ms):"), 3, 0)
        self.num_timeout = QSpinBox()
        self.num_timeout.setRange(100, 10000)
        self.num_timeout.setValue(int(self.config.get("fastscan_timeout_ms", 1000)))
        settings_layout.addWidget(self.num_timeout, 3, 1)

        settings_layout.addWidget(QLabel("Max Parallelism:"), 3, 2)
        self.num_parallelism = QSpinBox()
        self.num_parallelism.setRange(1, 1000)
        self.num_parallelism.setValue(int(self.config.get("fastscan_threads", 120)))
        settings_layout.addWidget(self.num_parallelism, 3, 3)

        settings_layout.addWidget(QLabel("Slipstream Ready Timeout (ms):"), 4, 0)
        self.num_real_ping_delay = QSpinBox()
        self.num_real_ping_delay.setRange(0, 60000)
        self.num_real_ping_delay.setValue(int(self.config.get("real_ping_delay_ms", 2000)))
        settings_layout.addWidget(self.num_real_ping_delay, 4, 1)
        self.scan_realtest_chk = QCheckBox("Real Test During Scan")
        self.scan_realtest_chk.setChecked(bool(self.config.get("scan_realtest", False)))
        self.scan_realtest_chk.stateChanged.connect(self.on_scan_realtest_changed)
        settings_layout.addWidget(self.scan_realtest_chk, 4, 2, 1, 2)

        self.btn_scan = QPushButton("Start Scan")
        self.btn_scan.clicked.connect(self.start_fast_scan)
        settings_layout.addWidget(self.btn_scan, 5, 2, 1, 2)

        self.btn_pause_scan = QPushButton("Pause Scan")
        self.btn_pause_scan.setEnabled(False)
        self.btn_pause_scan.clicked.connect(self.toggle_pause_scan)
        settings_layout.addWidget(self.btn_pause_scan, 5, 0, 1, 2)

        left_col.addWidget(settings_box)

        list_box = QGroupBox("Dns List")
        list_layout = QVBoxLayout(list_box)

        self.scan_table = QTableWidget(0, 4)
        self.scan_table.setHorizontalHeaderLabels(["DNS IP", "Time (ms)", "Detail", "Real Ping"])
        self.scan_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.scan_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.scan_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.scan_table.horizontalHeader().setStretchLastSection(True)
        self.scan_table.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.scan_table.horizontalHeader().setStretchLastSection(True)
        self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_table.customContextMenuRequested.connect(self.show_scan_context_menu)
        list_layout.addWidget(self.scan_table)

        btn_row = QHBoxLayout()
        self.btn_save = QPushButton("Save IPs")
        self.btn_save.clicked.connect(self.show_save_ips_menu)
        self.btn_clear = QPushButton("Clear List")
        self.btn_clear.clicked.connect(self.clear_scan_results)
        self.btn_real_ping = QPushButton("Test Real Ping")
        self.btn_real_ping.clicked.connect(self.test_real_ping)
        btn_row.addWidget(self.btn_save)
        btn_row.addWidget(self.btn_clear)
        btn_row.addWidget(self.btn_real_ping)
        list_layout.addLayout(btn_row)

        left_col.addWidget(list_box)

        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 0)
        self.scan_progress.setTextVisible(True)
        self.scan_progress.setFormat("%p%")
        left_col.addWidget(self.scan_progress)

        self.lbl_status_scanner = QLabel("Coder  : Farhad~UK")
        self.lbl_status_scanner.setEnabled(False)
        left_col.addWidget(self.lbl_status_scanner)

        stats_row = QHBoxLayout()
        self.lbl_total = QLabel("Total: 0")
        self.lbl_checked = QLabel("Checked: 0")
        self.lbl_success = QLabel("Success: 0")
        self.lbl_fail = QLabel("Fail: 0")
        stats_row.addWidget(self.lbl_total)
        stats_row.addWidget(self.lbl_checked)
        stats_row.addWidget(self.lbl_fail)
        stats_row.addWidget(self.lbl_success)
        right_col.addLayout(stats_row)

        right_col.addWidget(self.log_box)

        # Save Remaining Project removed

        scan_layout.addLayout(left_col, 6)
        scan_layout.addLayout(right_col, 4)

        self.tabs.addTab(scan_tab, "Scanner")
        self.on_scan_realtest_changed()

        # --- About tab ---
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        about_layout.setContentsMargins(20, 20, 20, 20)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_path = resource_path(ICON_NAME)
        if os.path.exists(icon_path):
            icon_label.setPixmap(QIcon(icon_path).pixmap(96, 96))
        else:
            icon_label.setPixmap(QIcon.fromTheme("application-exit").pixmap(96, 96))

        title_label = QLabel(f"{APP_TITLE} {APP_VERSION}")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")

        rights_label = QLabel("All rights reserved.")
        rights_label.setAlignment(Qt.AlignCenter)
        rights_label.setStyleSheet("color: #bdbdbd; font-size: 12px;")

        coder_label = QLabel("Coder  : Farhad~UK")
        coder_label.setAlignment(Qt.AlignCenter)
        coder_label.setStyleSheet("color: #bdbdbd; font-size: 12px;")

        about_layout.addStretch()
        about_layout.addWidget(icon_label)
        about_layout.addSpacing(8)
        about_layout.addWidget(title_label)
        about_layout.addSpacing(6)
        about_layout.addWidget(rights_label)
        about_layout.addWidget(coder_label)
        about_layout.addStretch()

        self.tabs.addTab(about_tab, "About")

        # --- Connection tab (hidden, kept alive for logic) ---
        self.conn_tab = QWidget(self)
        conn_layout = QVBoxLayout(self.conn_tab)

        conn_grid = QGridLayout()
        self.connect_dns_input = QLineEdit()
        self.connect_dns_input.setPlaceholderText("DNS for connect (optional)")
        self.mixed_port_input = QSpinBox()
        self.mixed_port_input.setRange(1, 65535)
        self.mixed_port_input.setValue(int(self.config.get("mixed_port", 10808)))
        self.mixed_port_input.valueChanged.connect(self.update_lan_info)

        self.lan_mode_chk = QCheckBox("LAN Mode (Hotspot) (Allow phones on Wi‑Fi to use proxy)")
        self.lan_mode_chk.setChecked(bool(self.config.get("lan_mode", False)))
        self.lan_mode_chk.stateChanged.connect(self.on_lan_mode_changed)

        self.auto_reconnect_chk = QCheckBox("Auto Reconnect on Drop")
        self.auto_reconnect_chk.setChecked(bool(self.config.get("auto_reconnect", True)))
        self.auto_reconnect_chk.stateChanged.connect(self.on_auto_reconnect_changed)

        conn_grid.addWidget(QLabel("DNS:"), 0, 0)
        conn_grid.addWidget(self.connect_dns_input, 0, 1)
        conn_grid.addWidget(QLabel("Mixed Port:"), 1, 0)
        conn_grid.addWidget(self.mixed_port_input, 1, 1)

        conn_layout.addLayout(conn_grid)
        conn_layout.addWidget(self.lan_mode_chk)
        conn_layout.addWidget(self.auto_reconnect_chk)

        proxy_row = QHBoxLayout()
        self.set_sys_proxy_btn = QPushButton("Set System Proxy")
        self.set_sys_proxy_btn.clicked.connect(self.enable_system_proxy)
        self.clear_sys_proxy_btn = QPushButton("Clear System Proxy")
        self.clear_sys_proxy_btn.clicked.connect(self.disable_system_proxy)
        proxy_row.addWidget(self.set_sys_proxy_btn)
        proxy_row.addWidget(self.clear_sys_proxy_btn)
        conn_layout.addLayout(proxy_row)

        self.hotspot_btn = QPushButton("📶 Open Windows Mobile Hotspot")
        self.hotspot_btn.clicked.connect(self.open_hotspot_settings)
        conn_layout.addWidget(self.hotspot_btn)

        self.lan_info_lbl = QLabel("LAN IP: Not available")
        self.lan_info_lbl.setStyleSheet("color: #bdbdbd; font-size: 11px;")
        conn_layout.addWidget(self.lan_info_lbl)

        traffic_grid = QGridLayout()
        self.lbl_up_speed = QLabel("↑ Speed: 0.00 B/s")
        self.lbl_down_speed = QLabel("↓ Speed: 0.00 B/s")
        self.lbl_total_up = QLabel("Total Up: 0.00 B")
        self.lbl_total_down = QLabel("Total Down: 0.00 B")
        for l in [self.lbl_up_speed, self.lbl_total_up]:
            l.setStyleSheet("color: #4fc3f7; font-size: 11px;")
        for l in [self.lbl_down_speed, self.lbl_total_down]:
            l.setStyleSheet("color: #81c784; font-size: 11px;")
        traffic_grid.addWidget(self.lbl_up_speed, 0, 0)
        traffic_grid.addWidget(self.lbl_down_speed, 0, 1)
        traffic_grid.addWidget(self.lbl_total_up, 1, 0)
        traffic_grid.addWidget(self.lbl_total_down, 1, 1)
        conn_layout.addLayout(traffic_grid)

        self.connect_log_box = QTextEdit()
        self.connect_log_box.setReadOnly(True)
        self.connect_log_box.setStyleSheet("background:#101010;color:#e0e0e0;font-family:Consolas;font-size:11px;")
        conn_layout.addWidget(self.connect_log_box)

        self.connect_btn = QPushButton("🚀 CONNECT (Slipstream)")
        self.connect_btn.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 12px;")
        self.connect_btn.clicked.connect(self.on_connect_clicked)
        conn_layout.addWidget(self.connect_btn)

        conn_layout.addStretch()
        self.conn_tab.hide()
        # Tab removed from UI (controls remain for logic)

        # main layout
        main = QVBoxLayout(self)
        main.addWidget(self.tabs)
        main.addWidget(self.status_lbl)
        main.setContentsMargins(10, 10, 10, 10)

        self.update_lan_info()

    # ================= Proxy Tab =================
    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if obj is getattr(self, "proxy_table", None) and event.type() == QEvent.KeyPress:
            try:
                if event.matches(QKeySequence.Paste):
                    self.paste_proxy_links()
                    return True
                if event.matches(QKeySequence.Copy):
                    self.copy_selected_proxy_configs()
                    return True
                if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                    self.set_proxy_from_selected_row()
                    return True
                if event.key() == Qt.Key_Delete:
                    self.remove_selected_proxy_rows()
                    return True
                if event.modifiers() & Qt.ControlModifier:
                    if event.key() == Qt.Key_O:
                        self.test_tcping_selected_row()
                        return True
                    if event.key() == Qt.Key_R:
                        self.test_delay_selected_row()
                        return True
                    if event.key() == Qt.Key_T:
                        self.test_speed_selected_row()
                        return True
            except Exception:
                pass
        return super().eventFilter(obj, event)

    def paste_proxy_links(self) -> None:
        text = QApplication.clipboard().text()
        if not text:
            return
        self._load_proxy_links_from_text(text)

    def import_proxy_links(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, APP_TITLE, "", "Text Files (*.txt *.csv);;All Files (*.*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as e:
            QMessageBox.warning(self, DIALOG_TITLE, f"Failed to read file: {e}")
            return
        self._load_proxy_links_from_text(text)

    def _load_proxy_links_from_text(self, text: str) -> None:
        added = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = self._parse_proxy_link(line)
            if not parsed:
                continue
            self._add_proxy_row(parsed)
            added += 1
        if added == 0:
            self.emitter.log.emit("WARN", "Proxy: No valid slipstream links found.")
        else:
            self.emitter.log.emit("INFO", f"Proxy: Loaded {added} proxy link(s).")
            self._save_proxy_rows_to_config()

    def _parse_proxy_link(self, link: str) -> Optional[Dict[str, str]]:
        # Supported:
        # SLIPSTREAM://dns@domain:53#remarks
        # SLIPSTREAM://domain:53?dns=1.1.1.1,8.8.8.8#remarks
        # SLIPSTREAM://user:pass@domain:53?dns=1.1.1.1,8.8.8.8#remarks
        try:
            transport = "UDP"
            raw = link.strip()
            if raw.lower().startswith("slipstream:/") and not raw.lower().startswith("slipstream://"):
                transport = "UDP"
                link = raw.replace("slipstream:/", "slipstream://", 1)
            if "://" not in link:
                return None
            parsed = urlparse(link)
            if parsed.scheme.strip().lower() != "slipstream":
                return None
            remarks = unquote((parsed.fragment or "").strip())

            dns_qs = unquote(_safe_qs_first(parsed, "dns"))
            dns_norm = _normalize_dns_csv(dns_qs) if dns_qs else None

            domain = (parsed.hostname or "").strip()
            port = parsed.port or 0
            if port != 53 or not domain:
                return None
            if not self._is_valid_domain(domain):
                return None

            username = unquote(parsed.username or "").strip()
            password = unquote(parsed.password or "").strip()

            if dns_norm:
                cert_norm = dns_norm
            else:
                # legacy format: SLIPSTREAM://dns@domain:53#remarks
                legacy_dns = unquote(parsed.username or "").strip()
                cert_norm = _normalize_dns_csv(legacy_dns) if legacy_dns else None
                # if looks like user:pass but dns missing, reject
                if not cert_norm:
                    return None
                username = ""
                password = ""

            return {
                "type": "SLIPSTREAM",
                "remarks": remarks,
                "address": cert_norm,
                "domain": domain,
                "port": "53",
                "transport": transport,
                "cert": cert_norm,
                "username": username,
                "password": password,
            }
        except Exception:
            return None

    def _add_proxy_row(self, data: Dict[str, str]) -> None:
        was_sorting = self.proxy_table.isSortingEnabled()
        if was_sorting:
            self.proxy_table.setSortingEnabled(False)
        row = self.proxy_table.rowCount()
        self.proxy_table.insertRow(row)
        self._proxy_edit_guard = True
        try:
            self.proxy_table.setItem(row, 0, QTableWidgetItem("SLIPSTREAM"))
            base_remarks = data.get("remarks", "")
            remarks_item = QTableWidgetItem(base_remarks)
            remarks_item.setFont(QFont("Segoe UI Emoji"))
            remarks_item.setData(Qt.UserRole + 3, base_remarks)
            self.proxy_table.setItem(row, 1, remarks_item)
            addr_text = data.get("address", "")
            addr_item = QTableWidgetItem(addr_text)
            addr_item.setData(Qt.UserRole, data.get("cert", addr_text))
            addr_item.setData(Qt.UserRole + 1, data.get("domain", ""))
            addr_item.setData(Qt.UserRole + 2, str(data.get("username", "") or ""))
            addr_item.setData(Qt.UserRole + 3, str(data.get("password", "") or ""))
            self.proxy_table.setItem(row, 2, addr_item)
            port_item = QTableWidgetItem("53")
            port_item.setFlags(port_item.flags() & ~Qt.ItemIsEditable)
            self.proxy_table.setItem(row, 3, port_item)
            transport_item = QTableWidgetItem(str(data.get("transport", "UDP")))
            transport_item.setFlags(transport_item.flags() & ~Qt.ItemIsEditable)
            self.proxy_table.setItem(row, 4, transport_item)
            type_item = self.proxy_table.item(row, 0)
            if type_item:
                type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            delay_item = QTableWidgetItem("")
            delay_item.setFlags(delay_item.flags() & ~Qt.ItemIsEditable)
            self.proxy_table.setItem(row, 5, delay_item)
            speed_item = QTableWidgetItem("")
            speed_item.setFlags(speed_item.flags() & ~Qt.ItemIsEditable)
            self.proxy_table.setItem(row, 6, speed_item)
            extra_item = QTableWidgetItem("")
            extra_item.setFlags(extra_item.flags() & ~Qt.ItemIsEditable)
            self.proxy_table.setItem(row, 7, extra_item)
        finally:
            self._proxy_edit_guard = False
            if was_sorting:
                self.proxy_table.setSortingEnabled(True)
        if not self._loading_proxy_rows:
            QTimer.singleShot(0, self, self._save_proxy_rows_to_config)
            self._update_proxy_connect_state()

    def _refresh_proxy_row_numbers(self) -> None:
        return

    @staticmethod
    def _make_proxy_key(dns_ip: str, domain: str) -> str:
        return f"{dns_ip}|{domain}"

    def _save_proxy_rows_to_config(self) -> None:
        rows: List[Dict[str, str]] = []
        for r in range(self.proxy_table.rowCount()):
            type_item = self.proxy_table.item(r, 0)
            remarks_item = self.proxy_table.item(r, 1)
            addr_item = self.proxy_table.item(r, 2)
            port_item = self.proxy_table.item(r, 3)
            transport_item = self.proxy_table.item(r, 4)
            if not addr_item:
                continue
            base_remark = ""
            if remarks_item is not None:
                base_remark = str(remarks_item.data(Qt.UserRole + 3) or "").strip()
                if not base_remark:
                    base_remark = remarks_item.text().strip()
            rows.append(
                {
                    "type": type_item.text() if type_item else "slipstream",
                    "remarks": base_remark,
                    "address": addr_item.text(),
                    "domain": str(addr_item.data(Qt.UserRole + 1) or ""),
                    "port": "53",
                    "transport": transport_item.text() if transport_item else "TCP",
                    "username": str(addr_item.data(Qt.UserRole + 2) or ""),
                    "password": str(addr_item.data(Qt.UserRole + 3) or ""),
                }
            )
        self.config["proxy_rows"] = rows
        save_config(self.config)

    def _load_proxy_rows_from_config(self) -> None:
        rows = self.config.get("proxy_rows", [])
        if not isinstance(rows, list):
            return
        self._proxy_edit_guard = True
        self._loading_proxy_rows = True
        try:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                data = {
                    "type": str(row.get("type", "slipstream")),
                    "remarks": str(row.get("remarks", "")),
                    "address": str(row.get("address", "")),
                    "domain": str(row.get("domain", "")),
                    "port": str(row.get("port", "53")),
                    "transport": str(row.get("transport", "TCP")),
                    "cert": str(row.get("address", "")),
                    "username": str(row.get("username", "")),
                    "password": str(row.get("password", "")),
                }
                addr_norm = _normalize_dns_csv(data["address"])
                if not addr_norm:
                    continue
                data["address"] = addr_norm
                data["cert"] = addr_norm
                if not data["address"] or not data["domain"]:
                    continue
                self._add_proxy_row(data)
        finally:
            self._proxy_edit_guard = False
            self._loading_proxy_rows = False

        last_key = str(self.config.get("last_selected_proxy", "")).strip()
        if last_key:
            for r in range(self.proxy_table.rowCount()):
                data = self._get_proxy_row_data(r)
                if not data:
                    continue
                if self._make_proxy_key(*data) == last_key:
                    self.proxy_table.selectRow(r)
                    self._bold_proxy_row(r)
                    self._set_active_proxy_row(r)
                    break
        self._update_proxy_connect_state()

    def _auto_connect_active_proxy(self) -> None:
        last_key = str(self.config.get("last_selected_proxy", "")).strip()
        if not last_key:
            return
        for r in range(self.proxy_table.rowCount()):
            data = self._get_proxy_row_data(r)
            if not data:
                continue
            if self._make_proxy_key(*data) == last_key:
                dns_ip, domain = data
                self.connect_dns_input.setText(dns_ip)
                self._bold_proxy_row(r)
                self._set_active_proxy_row(r)
                self.current_proxy_remark = self._get_proxy_remark_for_dns_domain(dns_ip, domain)
                QTimer.singleShot(0, self, lambda: self.start_connection(ip_override=dns_ip, domain_override=domain))
                self.emitter.log.emit("INFO", f"Proxy: Auto-connected to {dns_ip} / {domain}")
                break

    def _bold_proxy_row(self, row: int) -> None:
        for r in range(self.proxy_table.rowCount()):
            bold = r == row
            for c in range(self.proxy_table.columnCount()):
                item = self.proxy_table.item(r, c)
                if item:
                    font = item.font()
                    font.setBold(bold)
                    item.setFont(font)

    def _set_active_proxy_row(self, row: int) -> None:
        for r in range(self.proxy_table.rowCount()):
            remarks_item = self.proxy_table.item(r, 1)
            if not remarks_item:
                continue
            if r == row:
                remarks_item.setData(Qt.UserRole + 2, True)
            else:
                remarks_item.setData(Qt.UserRole + 2, False)
            remarks_item.setText(remarks_item.text().strip())
        self._update_proxy_connect_state()

    def _has_active_proxy(self) -> bool:
        for r in range(self.proxy_table.rowCount()):
            remarks_item = self.proxy_table.item(r, 1)
            if remarks_item and bool(remarks_item.data(Qt.UserRole + 2)):
                return True
        return False

    def _update_proxy_connect_state(self) -> None:
        if not hasattr(self, "proxy_connect_btn"):
            return
        if self.running or self.reconnecting:
            self.proxy_connect_btn.setEnabled(True)
            return
        self.proxy_connect_btn.setEnabled(self._has_active_proxy())

    def on_proxy_cell_changed(self, row: int, col: int) -> None:
        if self._proxy_edit_guard:
            return
        # Enforce type and port
        self._proxy_edit_guard = True
        try:
            type_item = self.proxy_table.item(row, 0)
            if type_item is None:
                type_item = QTableWidgetItem("SLIPSTREAM")
                type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
                self.proxy_table.setItem(row, 0, type_item)
            if type_item.text().strip().upper() != "SLIPSTREAM":
                type_item.setText("SLIPSTREAM")

            port_item = self.proxy_table.item(row, 3)
            if port_item is None:
                port_item = QTableWidgetItem("53")
                port_item.setFlags(port_item.flags() & ~Qt.ItemIsEditable)
                self.proxy_table.setItem(row, 3, port_item)
            if port_item.text().strip() != "53":
                port_item.setText("53")
            transport_item = self.proxy_table.item(row, 4)
            if transport_item is None:
                transport_item = QTableWidgetItem("UDP")
                transport_item.setFlags(transport_item.flags() & ~Qt.ItemIsEditable)
                self.proxy_table.setItem(row, 4, transport_item)
            addr_item = self.proxy_table.item(row, 2)
            if addr_item is not None:
                cert_val = addr_item.data(Qt.UserRole) or addr_item.text().strip()
                if not cert_val:
                    cert_val = addr_item.text().strip()
                addr_item.setData(Qt.UserRole, cert_val)
        finally:
            self._proxy_edit_guard = False
        self._save_proxy_rows_to_config()

    def _update_proxy_remark_display(self, row: int) -> None:
        if row < 0 or row >= self.proxy_table.rowCount():
            return
        remarks_item = self.proxy_table.item(row, 1)
        if remarks_item is None:
            return
        base_remark = str(remarks_item.data(Qt.UserRole + 3) or "").strip()
        if not base_remark:
            base_remark = remarks_item.text().strip()
        remarks_item.setText(base_remark)
        remarks_item.setFont(QFont("Segoe UI Emoji"))

    def add_proxy_config_dialog(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Add Proxy")
        dlg.setWindowFlag(Qt.MSWindowsFixedSizeDialogHint, True)
        dlg.setSizeGripEnabled(False)
        form = QFormLayout(dlg)

        type_edit = QComboBox()
        type_edit.addItems(["SLIPSTREAM"])
        type_edit.setCurrentText("SLIPSTREAM")
        type_edit.setEnabled(False)
        remarks_edit = QLineEdit("")
        auth_enable_chk = QCheckBox("Enable username/password")
        auth_enable_chk.setChecked(False)
        username_edit = QLineEdit("")
        password_edit = QLineEdit("")
        password_edit.setEchoMode(QLineEdit.Password)
        username_edit.setEnabled(False)
        password_edit.setEnabled(False)
        auth_enable_chk.stateChanged.connect(
            lambda _:
            (username_edit.setEnabled(auth_enable_chk.isChecked()),
             password_edit.setEnabled(auth_enable_chk.isChecked()))
        )
        address_container = QWidget()
        address_layout = QVBoxLayout(address_container)
        address_layout.setContentsMargins(0, 0, 0, 0)
        address_layout.setSpacing(6)
        address_rows: List[Tuple[QWidget, QLineEdit]] = []

        def _add_address_row(value: str = "") -> None:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)
            edit = QLineEdit(value)
            btn_remove = QPushButton("-")
            btn_remove.setFixedWidth(28)

            def _remove_row() -> None:
                if len(address_rows) <= 1:
                    edit.clear()
                    return
                row_widget.setParent(None)
                for i, (w, _) in enumerate(address_rows):
                    if w is row_widget:
                        address_rows.pop(i)
                        break

            btn_remove.clicked.connect(_remove_row)
            row_layout.addWidget(edit)
            row_layout.addWidget(btn_remove)
            address_layout.addWidget(row_widget)
            address_rows.append((row_widget, edit))

        _add_address_row("")
        domain_edit = QLineEdit("")
        port_edit = QLineEdit("53")
        port_edit.setReadOnly(True)
        port_edit.setEnabled(False)
        transport_edit = QComboBox()
        transport_edit.addItems(["UDP", "TCP"])
        transport_edit.setCurrentText("UDP")
        transport_edit.setEnabled(False)
        form.addRow("type", type_edit)
        form.addRow("Remarks", remarks_edit)
        form.addRow("", auth_enable_chk)
        form.addRow("username", username_edit)
        form.addRow("password", password_edit)
        form.addRow("address", address_container)
        add_addr_btn = QPushButton("Add DNS")
        add_addr_btn.clicked.connect(lambda: _add_address_row(""))
        form.addRow("", add_addr_btn)
        form.addRow("domain", domain_edit)
        form.addRow("port", port_edit)
        form.addRow("Transport", transport_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if dlg.exec() != QDialog.Accepted:
            return

        addr_list = [e.text().strip() for _, e in address_rows]
        addr_list = [a for a in addr_list if a]
        if not addr_list:
            QMessageBox.warning(self, DIALOG_TITLE, "Address cannot be empty.")
            return
        for a in addr_list:
            if not is_valid_ip(a):
                QMessageBox.warning(self, DIALOG_TITLE, "Invalid IP(s) in address.")
                return
        new_addr = ",".join(addr_list)
        new_domain = domain_edit.text().strip()
        new_remarks = remarks_edit.text().strip()
        if not new_remarks:
            QMessageBox.warning(self, DIALOG_TITLE, "Remarks cannot be empty.")
            return
        new_username = username_edit.text().strip() if auth_enable_chk.isChecked() else ""
        new_password = password_edit.text().strip() if auth_enable_chk.isChecked() else ""
        new_addr_norm = _normalize_dns_csv(new_addr)
        if not new_addr_norm:
            QMessageBox.warning(self, DIALOG_TITLE, "Invalid IP(s) in address.")
            return
        if not self._is_valid_domain(new_domain):
            QMessageBox.warning(self, DIALOG_TITLE, "Invalid domain.")
            return

        data = {
            "type": "SLIPSTREAM",
            "remarks": new_remarks,
            "address": new_addr_norm,
            "domain": new_domain,
            "port": "53",
            "transport": transport_edit.currentText(),
            "cert": new_addr_norm,
            "username": new_username,
            "password": new_password,
        }
        self._add_proxy_row(data)
        row = self.proxy_table.rowCount() - 1
        if row >= 0:
            self.proxy_table.selectRow(row)

    def edit_proxy_row_dialog(self, row: int, col: int) -> None:
        if row < 0:
            return

        def _get_text(r: int, c: int) -> str:
            item = self.proxy_table.item(r, c)
            return item.text() if item else ""

        current_type = _get_text(row, 0)
        remarks_item = self.proxy_table.item(row, 1)
        current_remarks = ""
        if remarks_item is not None:
            current_remarks = str(remarks_item.data(Qt.UserRole + 3) or "").strip() or _get_text(row, 1)
        current_address = _get_text(row, 2)
        current_port = _get_text(row, 3)
        current_transport = _get_text(row, 4)
        addr_item = self.proxy_table.item(row, 2)
        current_domain = ""
        current_username = ""
        current_password = ""
        if addr_item is not None:
            current_domain = str(addr_item.data(Qt.UserRole + 1) or "").strip()
            current_username = str(addr_item.data(Qt.UserRole + 2) or "").strip()
            current_password = str(addr_item.data(Qt.UserRole + 3) or "").strip()

        dlg = QDialog(self)
        dlg.setWindowTitle("Edit Proxy")
        dlg.setWindowFlag(Qt.MSWindowsFixedSizeDialogHint, True)
        dlg.setSizeGripEnabled(False)
        form = QFormLayout(dlg)

        type_edit = QComboBox()
        type_edit.addItems(["SLIPSTREAM"])
        type_edit.setCurrentText("SLIPSTREAM")
        type_edit.setEnabled(False)
        remarks_edit = QLineEdit(current_remarks)
        auth_enable_chk = QCheckBox("Enable username/password")
        auth_enable_chk.setChecked(bool(current_username and current_password))
        username_edit = QLineEdit(current_username)
        password_edit = QLineEdit(current_password)
        password_edit.setEchoMode(QLineEdit.Password)
        username_edit.setEnabled(auth_enable_chk.isChecked())
        password_edit.setEnabled(auth_enable_chk.isChecked())
        auth_enable_chk.stateChanged.connect(
            lambda _:
            (username_edit.setEnabled(auth_enable_chk.isChecked()),
             password_edit.setEnabled(auth_enable_chk.isChecked()))
        )
        address_container = QWidget()
        address_layout = QVBoxLayout(address_container)
        address_layout.setContentsMargins(0, 0, 0, 0)
        address_layout.setSpacing(6)
        address_rows: List[Tuple[QWidget, QLineEdit]] = []

        def _add_address_row(value: str = "") -> None:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)
            edit = QLineEdit(value)
            btn_remove = QPushButton("-")
            btn_remove.setFixedWidth(28)

            def _remove_row() -> None:
                if len(address_rows) <= 1:
                    edit.clear()
                    return
                row_widget.setParent(None)
                for i, (w, _) in enumerate(address_rows):
                    if w is row_widget:
                        address_rows.pop(i)
                        break

            btn_remove.clicked.connect(_remove_row)
            row_layout.addWidget(edit)
            row_layout.addWidget(btn_remove)
            address_layout.addWidget(row_widget)
            address_rows.append((row_widget, edit))

        addr_parts = _split_dns_csv(current_address)
        if not addr_parts:
            addr_parts = [current_address] if current_address else [""]
        for part in addr_parts:
            _add_address_row(part)
        port_edit = QLineEdit(current_port)
        port_edit.setReadOnly(True)
        port_edit.setEnabled(False)
        transport_edit = QComboBox()
        transport_edit.addItems(["UDP", "TCP"])
        transport_edit.setCurrentText(current_transport if current_transport else "UDP")
        transport_edit.setEnabled(False)
        domain_edit = QLineEdit(current_domain)
        form.addRow("type", type_edit)
        form.addRow("Remarks", remarks_edit)
        form.addRow("", auth_enable_chk)
        form.addRow("username", username_edit)
        form.addRow("password", password_edit)
        form.addRow("address", address_container)
        add_addr_btn = QPushButton("Add DNS")
        add_addr_btn.clicked.connect(lambda: _add_address_row(""))
        form.addRow("", add_addr_btn)
        form.addRow("domain", domain_edit)
        form.addRow("port", port_edit)
        form.addRow("Transport", transport_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if dlg.exec() != QDialog.Accepted:
            return

        addr_list = [e.text().strip() for _, e in address_rows]
        addr_list = [a for a in addr_list if a]
        if not addr_list:
            QMessageBox.warning(self, DIALOG_TITLE, "Address cannot be empty.")
            return
        for a in addr_list:
            if not is_valid_ip(a):
                QMessageBox.warning(self, DIALOG_TITLE, "Invalid IP(s) in address.")
                return
        new_addr = ",".join(addr_list)
        new_domain = domain_edit.text().strip()
        new_remarks = remarks_edit.text().strip()
        if not new_remarks:
            QMessageBox.warning(self, DIALOG_TITLE, "Remarks cannot be empty.")
            return
        new_username = username_edit.text().strip() if auth_enable_chk.isChecked() else ""
        new_password = password_edit.text().strip() if auth_enable_chk.isChecked() else ""
        new_addr_norm = _normalize_dns_csv(new_addr)
        if not new_addr_norm:
            QMessageBox.warning(self, DIALOG_TITLE, "Invalid IP(s) in address.")
            return
        if not self._is_valid_domain(new_domain):
            QMessageBox.warning(self, DIALOG_TITLE, "Invalid domain.")
            return

        self._proxy_edit_guard = True
        try:
            def _set_item(r: int, c: int, value: str) -> None:
                item = self.proxy_table.item(r, c)
                if item is None:
                    item = QTableWidgetItem()
                    self.proxy_table.setItem(r, c, item)
                item.setText(value)
                if c == 2:
                    item.setData(Qt.UserRole, new_addr_norm)
                    item.setData(Qt.UserRole + 1, new_domain)
                    item.setData(Qt.UserRole + 2, new_username)
                    item.setData(Qt.UserRole + 3, new_password)
                if c == 1:
                    item.setData(Qt.UserRole + 3, value)
                    item.setFont(QFont("Segoe UI Emoji"))

            _set_item(row, 0, type_edit.currentText())
            _set_item(row, 1, new_remarks)
            _set_item(row, 2, new_addr_norm)
            _set_item(row, 3, port_edit.text())
            _set_item(row, 4, transport_edit.currentText())
        finally:
            self._proxy_edit_guard = False
        self._update_proxy_remark_display(row)

        self.on_proxy_cell_changed(row, 0)

    def _row_to_proxy_link(self, row: int) -> Optional[str]:
        type_item = self.proxy_table.item(row, 0)
        remarks_item = self.proxy_table.item(row, 1)
        addr_item = self.proxy_table.item(row, 2)
        port_item = self.proxy_table.item(row, 3)
        if not addr_item or not addr_item.text().strip():
            return None
        t = (type_item.text().strip().upper() if type_item else "SLIPSTREAM")
        if t != "SLIPSTREAM":
            return None
        port = "53"
        if port_item and port_item.text().strip() != "53":
            return None
        remarks = ""
        if remarks_item is not None:
            remarks = str(remarks_item.data(Qt.UserRole + 3) or "").strip()
            if not remarks:
                remarks = remarks_item.text().strip()
        cert_val = addr_item.data(Qt.UserRole) or addr_item.text().strip()
        cert_val = cert_val if str(cert_val).strip() else addr_item.text().strip()
        domain_val = addr_item.data(Qt.UserRole + 1) or ""
        domain_val = str(domain_val).strip()
        username_val = str(addr_item.data(Qt.UserRole + 2) or "").strip()
        password_val = str(addr_item.data(Qt.UserRole + 3) or "").strip()
        if not domain_val:
            return None
        cert_val = str(cert_val).strip()
        use_auth = bool(username_val and password_val)
        use_query = use_auth or ("," in cert_val)
        if use_query:
            auth_part = ""
            if use_auth:
                auth_part = f"{quote(username_val, safe='')}:{quote(password_val, safe='')}@"
            link = f"{t}://{auth_part}{domain_val}:{port}?dns={quote(cert_val, safe=',')}"
        else:
            link = f"{t}://{cert_val}@{domain_val}:{port}"
        if remarks:
            link += f"#{quote(remarks, safe='')}"
        return link

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        d = domain.strip()
        if not d or "." not in d:
            return False
        if len(d) > 253:
            return False
        parts = d.split(".")
        for p in parts:
            if not p or len(p) > 63:
                return False
            if p[0] == "-" or p[-1] == "-":
                return False
            for ch in p:
                if not (ch.isalnum() or ch == "-"):
                    return False
        return True

    def copy_selected_proxy_link(self) -> None:
        row = self.proxy_table.currentRow()
        if row < 0:
            return
        link = self._row_to_proxy_link(row)
        if not link:
            QMessageBox.warning(self, DIALOG_TITLE, "Selected row is invalid.")
            return
        QApplication.clipboard().setText(link)
        self.emitter.log.emit("INFO", "Proxy link copied to clipboard.")

    def copy_selected_proxy_configs(self) -> None:
        rows = self._get_selected_proxy_rows()
        if not rows:
            return
        links: List[str] = []
        for r in rows:
            link = self._row_to_proxy_link(r)
            if link:
                links.append(link)
        if not links:
            QMessageBox.warning(self, DIALOG_TITLE, "Selected rows are invalid.")
            return
        QApplication.clipboard().setText("\n".join(links))
        self.emitter.log.emit("INFO", f"Proxy: Copied {len(links)} config(s) to clipboard.")

    def remove_selected_proxy_rows(self) -> None:
        rows = self._get_selected_proxy_rows()
        if not rows:
            return
        removed_active = False
        for r in rows:
            remarks_item = self.proxy_table.item(r, 1)
            if remarks_item and bool(remarks_item.data(Qt.UserRole + 2)):
                removed_active = True
                break
        for r in sorted(rows, reverse=True):
            self.proxy_table.removeRow(r)
        self._save_proxy_rows_to_config()
        self.emitter.log.emit("INFO", f"Proxy: Removed {len(rows)} row(s).")
        if removed_active:
            self.config["last_selected_proxy"] = ""
            save_config(self.config)
        self._update_proxy_connect_state()

    def show_proxy_context_menu(self, pos) -> None:
        row = self.proxy_table.rowAt(pos.y())
        if row >= 0 and not self.proxy_table.selectionModel().isRowSelected(row, self.proxy_table.rootIndex()):
            self.proxy_table.selectRow(row)
        rows = self._get_selected_proxy_rows()
        menu = QMenu(self)

        act_edit = QAction("Edit [Double Click]", self)
        act_edit.triggered.connect(lambda: self.edit_proxy_row_dialog(self.proxy_table.currentRow(), 0))
        menu.addAction(act_edit)

        act_set = QAction("Set Config [Enter]", self)
        act_set.triggered.connect(self.set_proxy_from_selected_row)
        menu.addAction(act_set)

        act_delete = QAction("Delete [Del]", self)
        act_delete.triggered.connect(self.remove_selected_proxy_rows)
        menu.addAction(act_delete)

        act_copy = QAction("Copy Config [Ctrl+C]", self)
        act_copy.triggered.connect(self.copy_selected_proxy_configs)
        menu.addAction(act_copy)

        menu.addSeparator()

        act_tcp = QAction("Test tcping [Ctrl+O]", self)
        act_tcp.triggered.connect(self.test_tcping_selected_row)
        menu.addAction(act_tcp)

        act_delay = QAction("Test real delay [Ctrl+R]", self)
        act_delay.triggered.connect(self.test_delay_selected_row)
        menu.addAction(act_delay)

        act_speed = QAction("Test download speed [Ctrl+T]", self)
        act_speed.triggered.connect(self.test_speed_selected_row)
        menu.addAction(act_speed)

        if not rows:
            for a in (act_edit, act_set, act_delete, act_copy, act_tcp, act_delay, act_speed):
                a.setEnabled(False)
        elif len(rows) > 1:
            act_edit.setEnabled(False)

        menu.exec(self.proxy_table.viewport().mapToGlobal(pos))

    def _get_selected_proxy_rows(self) -> List[int]:
        rows = {i.row() for i in self.proxy_table.selectedIndexes()}
        return sorted(rows)

    def _get_proxy_row_data(self, row: int) -> Optional[Tuple[str, str]]:
        if row < 0 or row >= self.proxy_table.rowCount():
            return None
        addr_item = self.proxy_table.item(row, 2)
        if not addr_item:
            return None
        dns_ip = addr_item.text().strip()
        domain = str(addr_item.data(Qt.UserRole + 1) or "").strip()
        if not dns_ip or not domain:
            return None
        return dns_ip, domain

    def _get_active_proxy_domain(self) -> str:
        for r in range(self.proxy_table.rowCount()):
            remarks_item = self.proxy_table.item(r, 1)
            if remarks_item and bool(remarks_item.data(Qt.UserRole + 2)):
                data = self._get_proxy_row_data(r)
                if data:
                    return data[1].strip()
        return ""

    def _get_proxy_remark_for_dns_domain(self, dns_ip: str, domain: str) -> str:
        for r in range(self.proxy_table.rowCount()):
            data = self._get_proxy_row_data(r)
            if not data:
                continue
            if data[0] == dns_ip and data[1] == domain:
                remarks_item = self.proxy_table.item(r, 1)
                if remarks_item is None:
                    return ""
                base_remark = str(remarks_item.data(Qt.UserRole + 3) or "").strip()
                return base_remark if base_remark else remarks_item.text().strip()
        return ""

    def _get_proxy_type_for_dns_domain(self, dns_ip: str, domain: str) -> str:
        for r in range(self.proxy_table.rowCount()):
            data = self._get_proxy_row_data(r)
            if not data:
                continue
            if data[0] == dns_ip and data[1] == domain:
                type_item = self.proxy_table.item(r, 0)
                return type_item.text().strip().upper() if type_item else "SLIPSTREAM"
        return "SLIPSTREAM"

    def _get_proxy_auth_for_dns_domain(self, dns_ip: str, domain: str) -> Tuple[str, str]:
        for r in range(self.proxy_table.rowCount()):
            data = self._get_proxy_row_data(r)
            if not data:
                continue
            if data[0] == dns_ip and data[1] == domain:
                addr_item = self.proxy_table.item(r, 2)
                if addr_item is None:
                    return "", ""
                username = str(addr_item.data(Qt.UserRole + 2) or "").strip()
                password = str(addr_item.data(Qt.UserRole + 3) or "").strip()
                return username, password
        return "", ""

    @staticmethod
    def _mask_domain(domain: str) -> str:
        d = domain.strip()
        if not d:
            return ""
        compact = d.replace(".", "")
        if len(compact) <= 6:
            return compact
        return f"{compact[:3]}****{compact[-3:]}"

    def _format_active_proxy_display(self, dns_ip: str, domain: str) -> str:
        if not dns_ip or not domain:
            return ""
        ptype = self._get_proxy_type_for_dns_domain(dns_ip, domain)
        remarks = self.current_proxy_remark or self._get_proxy_remark_for_dns_domain(dns_ip, domain)
        masked_domain = self._mask_domain(domain)
        remarks_txt = f" {remarks}" if remarks else ""
        return f"[{ptype}]{remarks_txt} ({masked_domain}:53)"

    def set_proxy_from_selected_row(self) -> None:
        rows = self._get_selected_proxy_rows()
        if not rows:
            return
        last_ip = ""
        last_domain = ""
        for row in rows:
            data = self._get_proxy_row_data(row)
            if not data:
                QMessageBox.warning(self, DIALOG_TITLE, "Selected row is invalid.")
                return
            dns_ip, domain = data
            last_ip, last_domain = dns_ip, domain
        if not last_ip or not last_domain:
            return
        self.connect_dns_input.setText(last_ip)
        self.config["last_selected_proxy"] = self._make_proxy_key(last_ip, last_domain)
        save_config(self.config)
        self._bold_proxy_row(rows[-1])
        self._set_active_proxy_row(rows[-1])
        self.current_proxy_remark = self._get_proxy_remark_for_dns_domain(last_ip, last_domain)
        self.current_proxy_username, self.current_proxy_password = self._get_proxy_auth_for_dns_domain(last_ip, last_domain)
        if self.running or self.reconnecting:
            if self.proc_singbox and self.proc_singbox.poll() is None:
                self._restart_tunnel_only(last_ip, domain_override=last_domain)
            else:
                self.stop_connection()
                QTimer.singleShot(200, lambda: self.start_connection(ip_override=last_ip, domain_override=last_domain))
        else:
            QTimer.singleShot(0, self, lambda: self.start_connection(ip_override=last_ip, domain_override=last_domain))
        self.emitter.log.emit("INFO", f"Proxy: Set config to {last_ip} / {last_domain}")

    def test_delay_selected_row(self) -> None:
        rows = self._get_selected_proxy_rows()
        if not rows:
            return
        for row in rows:
            self._set_proxy_cell_text(row, 5, "Testing...")
            threading.Thread(target=self._test_delay_worker, args=(row,), daemon=True).start()
        self.emitter.log.emit("INFO", f"Proxy: Test Delay started for {len(rows)} row(s).")

    def test_tcping_selected_row(self) -> None:
        rows = self._get_selected_proxy_rows()
        if not rows:
            return
        for row in rows:
            self._set_proxy_cell_text(row, 5, "Testing...")
            threading.Thread(target=self._test_tcping_worker, args=(row,), daemon=True).start()
        self.emitter.log.emit("INFO", f"Proxy: Test tcping started for {len(rows)} row(s).")

    def test_speed_selected_row(self) -> None:
        rows = self._get_selected_proxy_rows()
        if not rows:
            return
        for row in rows:
            self._set_proxy_cell_text(row, 6, "Testing...")
            threading.Thread(target=self._test_speed_worker, args=(row,), daemon=True).start()
        self.emitter.log.emit("INFO", f"Proxy: Test Speed started for {len(rows)} row(s).")

    def _set_proxy_cell_text(self, row: int, col: int, text: str) -> None:
        def _apply():
            if 0 <= row < self.proxy_table.rowCount():
                item = self.proxy_table.item(row, col)
                if item is None:
                    item = QTableWidgetItem()
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.proxy_table.setItem(row, col, item)
                item.setText(text)
        if col == 5:
            self._apply_proxy_ping_color(row, text)
        if col == 6:
            self._apply_proxy_speed_color(row, text)
        if col not in (5, 6):
            self._save_proxy_rows_to_config()
        QTimer.singleShot(0, self, _apply)

    def _apply_proxy_ping_color(self, row: int, text: str) -> None:
        t = (text or "").strip().lower()
        if "ms" in t:
            try:
                ms = int(t.replace("ms", "").strip())
            except Exception:
                ms = -1
            if ms >= 0:
                if ms < 350:
                    color = QColor("#b9f6ca")
                elif ms < 700:
                    color = QColor("#bbdefb")
                else:
                    color = QColor("#fff9c4")
            else:
                color = QColor("#e0e0e0")
        elif "timeout" in t:
            color = QColor("#ffccbc")
        elif t.strip() == "-1":
            color = QColor("#ffcdd2")
        else:
            color = QColor("#e0e0e0")

        item = self.proxy_table.item(row, 5)
        if item:
            item.setBackground(QColor(0, 0, 0, 0))
            item.setForeground(color)

    def _apply_proxy_speed_color(self, row: int, text: str) -> None:
        t = (text or "").strip().lower()
        if t == "-1" or "timeout" in t or "fail" in t or "error" in t:
            color = QColor("#ffcdd2")
        else:
            color = QColor("#e0e0e0")
        item = self.proxy_table.item(row, 6)
        if item:
            item.setBackground(QColor(0, 0, 0, 0))
            item.setForeground(color)

    def _run_slipstream_test(
        self,
        dns_ip: str,
        domain: str,
        timeout: float,
        username: str = "",
        password: str = "",
    ) -> Tuple[Optional[subprocess.Popen], int, bool]:
        slip_path = bin_path(SLIPSTREAM_BIN)
        if not os.path.exists(slip_path):
            slip_path = SLIPSTREAM_BIN
        if not os.path.exists(slip_path):
            self.emitter.log.emit("ERROR", f"Proxy: {SLIPSTREAM_BIN} not found.")
            return None, 0, False

        port = get_free_port()
        self.internal_port = port
        self.slipstream_ready_event.clear()
        self.emitter.log.emit("INFO", f"Proxy: Starting SLIPSTREAM test -> {dns_ip} / {domain} (port {port})")
        resolver_args = _resolver_args_from_dns(dns_ip)
        if not resolver_args:
            self.emitter.log.emit("ERROR", "Proxy: Invalid DNS resolver list.")
            return None, 0, False
        cmd = [
            slip_path,
            *resolver_args,
            "--domain",
            domain,
            "--tcp-listen-port",
            str(port),
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=(subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == "nt" else 0,
            )
        except Exception as e:
            self.emitter.log.emit("ERROR", f"Proxy: Failed to start SLIPSTREAM ({e})")
            return None, 0, False

        def _reader():
            try:
                if not proc.stdout:
                    return
                for line in proc.stdout:
                    if "Connection ready" in line:
                        self.slipstream_ready_event.set()
                    if line.strip():
                        self.emitter.log.emit("DEBUG", f"[SLIPSTREAM-TEST] {line.rstrip()}")
            except Exception:
                pass

        threading.Thread(target=_reader, daemon=True).start()

        ready = self._wait_for_slipstream_ready_or_socks(timeout=timeout, username=username, password=password)
        if not ready:
            self.emitter.log.emit("WARN", "Proxy: SLIPSTREAM test TIMEOUT (not ready).")
        return proc, port, ready

    def _scan_realtest_worker_loop(self) -> None:
        self.emitter.scan_timer_start.emit()
        while not self.closing:
            if not (hasattr(self, "scan_realtest_chk") and self.scan_realtest_chk.isChecked()):
                break
            row_count = self.scan_table.rowCount()
            if self.scan_realtest_next_row >= row_count:
                if self.scan_running:
                    time.sleep(0.2)
                    continue
                if not self.scan_queue.empty() or self._scan_ui_tick_running:
                    time.sleep(0.2)
                    continue
                break

            row = self.scan_realtest_next_row
            ip_item = self.scan_table.item(row, 0)
            ip = ip_item.text().strip() if ip_item else ""
            ping_item = self.scan_table.item(row, 3)
            existing = ping_item.text().strip() if ping_item else ""
            if not ip:
                self.scan_realtest_next_row += 1
                continue
            if existing and existing not in ("Queued", "Testing..."):
                self.scan_realtest_next_row += 1
                continue

            while (self.running or self.reconnecting) and not self.closing:
                time.sleep(0.2)
            if self.closing:
                break

            domain = self.domain_input.text().strip()
            if not domain:
                self.ping_queue.put((row, "NO DOMAIN"))
                self.scan_realtest_next_row += 1
                continue

            self.emitter.real_ping_test_row.emit(row)
            ready_timeout_ms = int(self.num_real_ping_delay.value())
            timeout_s = max(0.2, ready_timeout_ms / 1000.0)
            proc = None
            port = 0
            try:
                with self.scan_realtest_lock:
                    proc, port, ready = self._run_slipstream_test(ip, domain, timeout=timeout_s)
                    if not ready or not proc or port <= 0:
                        self.ping_queue.put((row, "TIMEOUT"))
                        self.scan_realtest_next_row += 1
                        continue
                    ms, status = self._socks5_real_ping(
                        proxy_port=int(port),
                        timeout=5.0,
                        host="www.google.com",
                        port=443,
                    )
                    if status in ("SOCKS FAIL", "ERROR", "TIMEOUT"):
                        ms, status = self._http_connect_real_ping(
                            proxy_port=int(port),
                            timeout=5.0,
                            host="www.google.com",
                            port=443,
                        )
                    self.ping_queue.put((row, status))
            except Exception:
                self.ping_queue.put((row, "ERROR"))
            finally:
                try:
                    if proc and proc.poll() is None:
                        interrupt_process(proc)
                        proc.wait(timeout=2)
                except Exception:
                    pass
            self.scan_realtest_next_row += 1
        if not self.scan_running and not self.real_ping_running:
            QTimer.singleShot(0, self._scan_ui_tick)
            end_wait = time.monotonic() + 1.0
            while time.monotonic() < end_wait:
                if self.ping_queue.empty():
                    break
                time.sleep(0.05)
            self.emitter.scan_timer_stop.emit()

    def _tcp_ping_address(self, dns_ip: str, port: int = 53, timeout: float = 3.0) -> Tuple[int, str]:
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((dns_ip, int(port)))
            ms = int((time.monotonic() - start) * 1000)
            return ms, f"{ms} ms"
        except socket.timeout:
            return -1, "TIMEOUT"
        except Exception:
            return -1, "ERROR"
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _test_tcping_worker(self, row: int) -> None:
        data = self._get_proxy_row_data(row)
        if not data:
            self._set_proxy_cell_text(row, 5, "INVALID")
            return
        dns_ip, _domain = data
        try:
            primary_ip = _primary_dns(dns_ip)
            self.emitter.log.emit("INFO", f"Proxy: Test tcping running for {primary_ip}")
            ms, status = self._tcp_ping_address(primary_ip, port=53, timeout=3.0)
            if ms >= 0:
                self._set_proxy_cell_text(row, 5, f"{ms} ms")
                self.emitter.log.emit("INFO", f"Proxy: Test tcping result {ms} ms")
            else:
                self._set_proxy_cell_text(row, 5, "-1")
                self.emitter.log.emit("WARN", f"Proxy: Test tcping {status}")
        except Exception:
            self._set_proxy_cell_text(row, 5, "-1")
            self.emitter.log.emit("ERROR", "Proxy: Test tcping ERROR")

    def _test_delay_worker(self, row: int) -> None:
        data = self._get_proxy_row_data(row)
        if not data:
            self._set_proxy_cell_text(row, 5, "INVALID")
            return
        dns_ip, domain = data
        tunnel_proc = None
        sing_proc = None
        mixed_port = 0
        try:
            self.emitter.log.emit("INFO", f"Proxy: Test Delay running for {dns_ip} / {domain}")
            username, password = self._get_proxy_auth_for_dns_domain(dns_ip, domain)
            tunnel_proc, sing_proc, mixed_port = self._run_proxy_test_core(
                dns_ip,
                domain,
                timeout=10.0,
                username=username,
                password=password,
            )
            if not tunnel_proc or not sing_proc or mixed_port <= 0:
                self._set_proxy_cell_text(row, 5, "-1")
                self.emitter.log.emit("WARN", "Proxy: Test Delay TIMEOUT (proxy not ready).")
                return
            ms, status = self._proxy_real_ping_on_port(int(mixed_port), timeout=5.0)
            if ms >= 0:
                self._set_proxy_cell_text(row, 5, f"{ms} ms")
                self.emitter.log.emit("INFO", f"Proxy: Test Delay result {ms} ms")
            else:
                self._set_proxy_cell_text(row, 5, "-1")
                self.emitter.log.emit("WARN", "Proxy: Test Delay TIMEOUT (ping failed).")
        except Exception:
            self._set_proxy_cell_text(row, 5, "-1")
            self.emitter.log.emit("ERROR", "Proxy: Test Delay ERROR")
        finally:
            try:
                if sing_proc and sing_proc.poll() is None:
                    interrupt_process(sing_proc)
                    sing_proc.wait(timeout=2)
            except Exception:
                pass
            try:
                if tunnel_proc and tunnel_proc.poll() is None:
                    interrupt_process(tunnel_proc)
                    tunnel_proc.wait(timeout=2)
            except Exception:
                pass
            try:
                if mixed_port > 0:
                    os.remove(config_path(f"config_proxy_test_{mixed_port}.json"))
            except Exception:
                pass

    def _socks5_download_speed(self, proxy_port: int, url: str, timeout: float = 30.0) -> Tuple[float, str]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return -1.0, "ERROR"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        start = time.monotonic()
        last_log = start
        peak_mbps = 0.0
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(("127.0.0.1", proxy_port))
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
                sock.close()
                return -1.0, "SOCKS FAIL"

            host_bytes = host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")
            sock.sendall(req)
            resp = sock.recv(10)
            if len(resp) < 2 or resp[1] != 0x00:
                sock.close()
                return -1.0, "SOCKS FAIL"

            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)

            http_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(http_req)

            header = b""
            while b"\r\n\r\n" not in header:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                header += chunk
                if len(header) > 65536:
                    break
            body = b""
            if b"\r\n\r\n" in header:
                header, body = header.split(b"\r\n\r\n", 1)

            try:
                status_line = header.split(b"\r\n", 1)[0]
                if b"200" not in status_line:
                    return -1.0, "HTTP FAIL"
            except Exception:
                pass

            total = len(body)
            test_window = 10.0
            while True:
                now = time.monotonic()
                if now - start >= test_window:
                    break
                chunk = sock.recv(65536)
                if not chunk:
                    break
                total += len(chunk)
                elapsed = max(now - start, 0.001)
                inst_mbps = (total / (1024 * 1024)) / elapsed
                if inst_mbps > peak_mbps:
                    peak_mbps = inst_mbps
                if now - last_log >= 1.0:
                    self.emitter.log.emit("INFO", f"Proxy: Downloading... {inst_mbps:.2f} MB/s")
                    last_log = now

            if total <= 0:
                return -1.0, "-1"
            return peak_mbps, f"{peak_mbps:.2f} MB/s"
        except socket.timeout:
            return -1.0, "-1"
        except Exception:
            return -1.0, "-1"
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _test_speed_worker(self, row: int) -> None:
        data = self._get_proxy_row_data(row)
        if not data:
            self._set_proxy_cell_text(row, 6, "INVALID")
            return
        dns_ip, domain = data
        tunnel_proc = None
        sing_proc = None
        mixed_port = 0
        try:
            username, password = self._get_proxy_auth_for_dns_domain(dns_ip, domain)
            tunnel_proc, sing_proc, mixed_port = self._run_proxy_test_core(
                dns_ip,
                domain,
                timeout=10.0,
                username=username,
                password=password,
            )
            if not tunnel_proc or not sing_proc or mixed_port <= 0:
                self._set_proxy_cell_text(row, 5, "-1")
                self._set_proxy_cell_text(row, 6, "-1")
                return

            ms, status = self._proxy_real_ping_on_port(int(mixed_port), timeout=5.0)
            if ms >= 0:
                self._set_proxy_cell_text(row, 5, f"{ms} ms")
            else:
                self._set_proxy_cell_text(row, 5, "-1")
                self._set_proxy_cell_text(row, 6, "-1")
                return

            speed_value, speed_status = self._socks5_download_speed(int(mixed_port), SPEED_TEST_URL, timeout=30.0)
            self._set_proxy_cell_text(row, 6, speed_status)
            if speed_value < 0:
                self._apply_proxy_speed_color(row, speed_status)
        except Exception:
            self._set_proxy_cell_text(row, 6, "-1")
            self._apply_proxy_speed_color(row, "-1")
        finally:
            try:
                if sing_proc and sing_proc.poll() is None:
                    interrupt_process(sing_proc)
                    sing_proc.wait(timeout=2)
            except Exception:
                pass
            try:
                if tunnel_proc and tunnel_proc.poll() is None:
                    interrupt_process(tunnel_proc)
                    tunnel_proc.wait(timeout=2)
            except Exception:
                pass
            try:
                if mixed_port > 0:
                    os.remove(config_path(f"config_proxy_test_{mixed_port}.json"))
            except Exception:
                pass

    # ================= Logging =================
    def logw(self, level: str, msg: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        level = (level or "INFO").upper()

        color = "#00ff00"  # INFO
        if level == "WARN":
            color = "#ffb300"
        elif level == "ERROR":
            color = "#ff5252"
        elif level == "DEBUG":
            color = "#64b5f6"

        line = f"{ts} [{level}] {msg}"
        proxy_tags = ("Proxy", "SLIPSTREAM", "Hotspot Mode")
        connect_tags = ("CONNECT", "System Proxy", "Auto reconnect", "LAN Mode", "SING-BOX")

        target = "main"
        if any(tag in msg for tag in proxy_tags):
            target = "proxy"
        elif any(tag in msg for tag in connect_tags):
            target = "connect"

        if target == "main":
            self.log_box.append(f'<span style="color:{color};">{line}</span>')
            sb = self.log_box.verticalScrollBar()
            sb.setValue(sb.maximum())
        elif target == "connect":
            try:
                self.connect_log_box.append(line)
                sb2 = self.connect_log_box.verticalScrollBar()
                sb2.setValue(sb2.maximum())
            except Exception:
                pass
        else:
            try:
                self.proxy_log_box.append(line)
                sb3 = self.proxy_log_box.verticalScrollBar()
                sb3.setValue(sb3.maximum())
            except Exception:
                pass

    def on_proxy_action_selected(self, idx: int) -> None:
        if idx == 0:
            self.enable_system_proxy()
        elif idx == 1:
            self.disable_system_proxy()
        else:
            return
        return

    def open_proxy_settings_dialog(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Proxy Settings")
        dlg.setWindowFlag(Qt.MSWindowsFixedSizeDialogHint, True)
        dlg.setSizeGripEnabled(False)
        form = QFormLayout(dlg)

        port_spin = QSpinBox()
        port_spin.setRange(1, 65535)
        port_spin.setValue(int(self.mixed_port_input.value()))
        form.addRow("Mixed Port", port_spin)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if dlg.exec() != QDialog.Accepted:
            return
        self.mixed_port_input.setValue(int(port_spin.value()))

    def _sync_system_proxy_state(self) -> None:
        if os.name != "nt":
            return
        if not hasattr(self, "mixed_port_input") or self.mixed_port_input is None:
            return
        try:
            enabled, _ = winreg.QueryValueEx(INTERNET_SETTINGS, "ProxyEnable")
            server, _ = winreg.QueryValueEx(INTERNET_SETTINGS, "ProxyServer")
        except Exception:
            return
        try:
            expected = f"127.0.0.1:{int(self.mixed_port_input.value())}"
        except Exception:
            return
        is_set = bool(enabled == 1 and str(server).strip() == expected)
        self.config["proxy_system_set"] = is_set
        save_config(self.config)
        try:
            self.proxy_action_combo.blockSignals(True)
            self.proxy_action_combo.setCurrentIndex(0 if is_set else 1)
        finally:
            self.proxy_action_combo.blockSignals(False)

    def on_proxy_mode_changed(self) -> None:
        mode = self.proxy_mode_combo.currentText()
        self.config["proxy_mode"] = mode
        save_config(self.config)
        self.emitter.log.emit("INFO", f"Proxy: Mode set to {mode}")
        if self.running or self.reconnecting:
            dns_ip = self.current_dns_ip
            domain = self.current_domain
            if dns_ip and domain:
                self.emitter.log.emit("INFO", "Proxy: Restarting connection to apply mode...")
                self.stop_connection()
                QTimer.singleShot(300, lambda: self.start_connection(ip_override=dns_ip, domain_override=domain))

    # ================= DNS List =================
    def populate_dns_list(self) -> None:
        self._start_populate_dns_list()

    def _start_populate_dns_list(self) -> None:
        self.dns_list_widget.clear()
        self._populate_dns_ips = list(self._imported_dns_list)
        self._populate_saved_results = dict(self.config.get("saved_results", {}))  # type: ignore[arg-type]
        self._populate_last_selected = str(self.config.get("last_selected_dns", ""))
        self._populate_index = 0
        self._populate_batch = 200
        self._populate_running = True
        self.dns_list_widget.setEnabled(False)
        self.emitter.status.emit("Loading DNS list...")
        QTimer.singleShot(1, self._populate_dns_batch)

    def _populate_dns_batch(self) -> None:
        if not getattr(self, "_populate_running", False):
            return

        start = self._populate_index
        end = min(start + self._populate_batch, len(self._populate_dns_ips))

        for i in range(start, end):
            ip = self._populate_dns_ips[i]
            item = QListWidgetItem(ip)
            item.setData(Qt.UserRole, ip)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)

            if ip in self._populate_saved_results:
                res = self._populate_saved_results[ip]
                item.setText(f"{ip}   [{res}]")
                if is_success_result(res):
                    item.setForeground(QBrush(QColor("#66bb6a")))
                else:
                    item.setForeground(QBrush(QColor("#ef5350")))

            self.dns_list_widget.addItem(item)

            if ip == self._populate_last_selected:
                self.dns_list_widget.setCurrentItem(item)

        self._populate_index = end

        if end < len(self._populate_dns_ips):
            QTimer.singleShot(1, self._populate_dns_batch)
            return

        self._populate_running = False
        self.dns_list_widget.setEnabled(True)
        self.emitter.status.emit("Ready")
        self.emitter.log.emit("INFO", f"Loaded {len(self._populate_dns_ips)} DNS servers.")

    def get_selected_ip(self) -> Optional[str]:
        item = self.dns_list_widget.currentItem()
        if item:
            return str(item.data(Qt.UserRole))
        return None

    def get_checked_ips(self) -> List[str]:
        ips: List[str] = []
        for i in range(self.dns_list_widget.count()):
            it = self.dns_list_widget.item(i)
            if it.checkState() == Qt.Checked:
                ips.append(str(it.data(Qt.UserRole)))
        return ips

    def set_all_check_state(self, state: Qt.CheckState) -> None:
        for i in range(self.dns_list_widget.count()):
            self.dns_list_widget.item(i).setCheckState(state)

    # ================= Context Menu =================
    def show_dns_context_menu(self, pos) -> None:
        menu = QMenu(self)

        act_import = QAction("Import IP/CIDR File...", self)
        act_import.triggered.connect(self.import_ip_cidr_file)
        menu.addAction(act_import)
        menu.addSeparator()

        act_sel_all = QAction("Check All", self)
        act_unsel_all = QAction("Uncheck All", self)
        act_sel_all.triggered.connect(lambda: self.set_all_check_state(Qt.Checked))
        act_unsel_all.triggered.connect(lambda: self.set_all_check_state(Qt.Unchecked))
        menu.addAction(act_sel_all)
        menu.addAction(act_unsel_all)

        menu.exec(self.dns_list_widget.mapToGlobal(pos))

    # ================= Import IP/CIDR =================
    def set_import_busy(self, busy: bool) -> None:
        self.btn_import.setEnabled(not busy)
        self.btn_reload.setEnabled(not busy)
        self.dns_list_widget.setEnabled(not busy)

    def import_ip_cidr_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, APP_TITLE, "", "Text Files (*.txt *.csv *.cidrs);;All Files (*.*)")
        if not path:
            return
        self.set_import_busy(True)
        self.emitter.status.emit("Importing IP/CIDR... Please wait.")
        self.emitter.log.emit("INFO", f"Import started: {path}")

        threading.Thread(target=self._import_worker, args=(path,), daemon=True).start()

    def _import_worker(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
        except Exception as e:
            self.emitter.import_done.emit({"ok": False, "error": f"Failed to read file: {e}"})
            return

        # split tokens
        tokens: List[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#") or line.startswith("//"):
                continue
            # strip inline comments
            line = line.split("#", 1)[0].split("//", 1)[0].strip()
            for t in line.replace(";", " ").replace(",", " ").split():
                if t.strip():
                    tokens.append(t.strip())

        ips: List[str] = []
        cidrs: List[str] = []
        for t in tokens:
            if "/" in t:
                cidrs.append(t)
            else:
                if is_valid_ip(t):
                    ips.append(t)

        # keep CIDR as-is (no expansion here)
        valid_cidrs: List[str] = []
        for c in cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
                valid_cidrs.append(c)
            except Exception:
                continue

        all_new = _normalize_lines(ips + valid_cidrs)
        if not all_new:
            self.emitter.import_done.emit({"ok": True, "count": 0, "list": []})
            return

        self.emitter.import_done.emit({"ok": True, "count": len(all_new), "list": all_new})

    def on_import_done(self, payload: object) -> None:
        self.set_import_busy(False)
        self.emitter.status.emit("Ready")

        data = payload if isinstance(payload, dict) else {}
        if not data.get("ok"):
            err = data.get("error", "Unknown error")
            QMessageBox.critical(self, DIALOG_TITLE, str(err))
            return

        count = int(data.get("count", 0))
        if count <= 0:
            QMessageBox.information(self, DIALOG_TITLE, "No valid IP/CIDR found in file.")
            return

        new_list = data.get("list", [])
        if isinstance(new_list, list):
            self._imported_dns_list = _normalize_lines([str(x) for x in new_list])
        QTimer.singleShot(0, self.populate_dns_list)
        self.emitter.log.emit("INFO", f"Imported {count} items into memory (dns.txt disabled).")

    # ================= Scanner =================
    def persist_scan_settings(self) -> None:
        self.config["domain"] = self.domain_input.text().strip()
        self.config["fastscan_timeout_ms"] = int(self.num_timeout.value())
        self.config["fastscan_threads"] = int(self.num_parallelism.value())
        self.config["cidr_random_sample"] = int(self.num_random_count.value())
        self.config["real_ping_delay_ms"] = int(self.num_real_ping_delay.value())
        self.config["scan_realtest"] = bool(self.scan_realtest_chk.isChecked())
        save_config(self.config)

    def on_scan_realtest_changed(self) -> None:
        if self.scan_realtest_chk.isChecked() and (self.running or self.reconnecting):
            QMessageBox.warning(self, DIALOG_TITLE, "Disable proxy connection before enabling Real Test During Scan.")
            self.scan_realtest_chk.blockSignals(True)
            self.scan_realtest_chk.setChecked(False)
            self.scan_realtest_chk.blockSignals(False)
        if hasattr(self, "btn_real_ping"):
            self.btn_real_ping.setEnabled(not self.scan_realtest_chk.isChecked())

    def start_fast_scan(self, ips: Optional[List[str]] = None) -> None:
        if self.scan_running:
            self.stop_fast_scan()
            return

        if hasattr(self, "scan_realtest_chk") and self.scan_realtest_chk.isChecked():
            if self.running or self.reconnecting:
                QMessageBox.warning(self, DIALOG_TITLE, "Disable proxy connection to use Real Test During Scan.")
                return

        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.critical(self, DIALOG_TITLE, "Error: Domain cannot be empty.")
            return

        use_file = bool(self.scan_file_path and os.path.exists(self.scan_file_path))
        if not use_file and not self._has_dns_list_targets():
            QMessageBox.warning(self, DIALOG_TITLE, "Select File First!")
            return

        self.persist_scan_settings()

        self.scan_running = True
        self.scan_pause_event.set()
        self.scan_stop = threading.Event()
        self.btn_scan.setText("Stop Scan")
        self.btn_pause_scan.setEnabled(True)
        self.btn_pause_scan.setText("Pause Scan")
        self.scan_realtest_next_row = 0
        self.btn_browse.setEnabled(False)
        self.num_random_count.setEnabled(False)

        timeout_ms = int(self.num_timeout.value())
        threads = int(self.num_parallelism.value())
        random_count = int(self.num_random_count.value())
        use_random = random_count > 0
        cap = int(self.config.get("cidr_expand_cap", 4096))

        self.clear_scan_results(clear_log=False)
        self.emitter.log.emit("INFO", "Loading IPs...")

        self.scan_target_queue: Queue[str] = Queue(maxsize=10000)
        self.scan_producer_done = threading.Event()

        def _load_and_start():
            source = "file" if use_file else "dns"
            if source == "file":
                total = self._count_targets_in_file(self.scan_file_path, use_random, random_count)
                if total <= 0 and self._has_dns_list_targets():
                    source = "dns"
                    tokens = self._load_dns_list_tokens()
                    total = self._count_targets_in_tokens(tokens, use_random, random_count)
            else:
                tokens = self._load_dns_list_tokens()
                total = self._count_targets_in_tokens(tokens, use_random, random_count)
            if total <= 0:
                self.emitter.log.emit("WARN", "No IPs found.")
                self._scan_finish_ui_reset()
                return

            with self.scan_lock:
                self.scan_total = total
                self.scan_checked = 0
                self.scan_success = 0
                self.scan_fail = 0
                self.scan_produced = 0
                self.scan_processed = set()

            self.scan_progress.setRange(0, max(1, total))
            self.scan_progress.setValue(0)
            self.emitter.scan_timer_start.emit()

            src_label = "File" if source == "file" else "dns.txt"
            self.emitter.log.emit(
                "INFO",
                f"Fast scan started. Source: {src_label} | Targets: {total} | Threads: {threads} | Timeout: {timeout_ms}ms",
            )

            def producer():
                try:
                    if source == "file":
                        iterator = self._iter_targets_from_file(self.scan_file_path, use_random, random_count, cap)
                    else:
                        iterator = self._iter_targets_from_tokens(self._load_dns_list_tokens(), use_random, random_count, cap)
                    for ip in iterator:
                        if self.scan_stop.is_set():
                            break
                        self.scan_target_queue.put(ip)
                        with self.scan_lock:
                            self.scan_produced += 1
                except Exception as e:
                    if not self.closing:
                        self._enqueue_scan_log(f"Producer error: {e}")
                finally:
                    self.scan_producer_done.set()
                    with self.scan_lock:
                        produced = self.scan_produced
                        expected = self.scan_total
                    if not self.closing:
                        self._enqueue_scan_log(f"Producer done. Produced {produced} / Expected {expected}")

            def worker():
                while True:
                    if self.scan_stop.is_set() and self.scan_target_queue.empty():
                        return
                    if not self.scan_pause_event.wait(0.1):
                        continue
                    try:
                        ip = self.scan_target_queue.get(timeout=0.2)
                    except Exception:
                        if self.scan_producer_done.is_set():
                            return
                        continue

                    ok, res = fast_dns_tunnel_check(ip, domain, timeout_ms)
                    with self.scan_lock:
                        self.scan_checked += 1
                        if is_success_result(res):
                            self.scan_success += 1
                        else:
                            self.scan_fail += 1
                        self.scan_processed.add(ip)
                    self.scan_queue.put((ip, res, threading.get_ident()))

            threading.Thread(target=producer, daemon=True).start()

            self.scan_threads = []
            for _ in range(min(threads, max(1, total))):
                t = threading.Thread(target=worker, daemon=True)
                self.scan_threads.append(t)
                t.start()

            def waiter():
                for t in self.scan_threads:
                    t.join()
                self.emitter.scan_finished.emit()

            threading.Thread(target=waiter, daemon=True).start()

        threading.Thread(target=_load_and_start, daemon=True).start()

    def stop_fast_scan(self) -> None:
        if not self.scan_running:
            return
        self.emitter.log.emit("WARN", "Stopping scan...")
        self.scan_stop.set()
        self.scan_pause_event.set()
        try:
            if hasattr(self, "scan_producer_done"):
                self.scan_producer_done.set()
            if hasattr(self, "scan_target_queue"):
                while not self.scan_target_queue.empty():
                    try:
                        self.scan_target_queue.get_nowait()
                    except Exception:
                        break
        except Exception:
            pass

    def _scan_finish_ui_reset(self) -> None:
        self.scan_running = False
        self.btn_scan.setText("Start Scan")
        self.btn_scan.setEnabled(True)
        self.btn_pause_scan.setEnabled(False)
        self.btn_pause_scan.setText("Pause Scan")
        self.btn_browse.setEnabled(True)
        self.num_random_count.setEnabled(True)
        self.emitter.scan_timer_stop.emit()

    def _start_scan_ui_timer(self) -> None:
        if self.scan_ui_timer.isActive():
            self.scan_ui_timer.stop()
        self.scan_ui_timer.start()

    def _stop_scan_ui_timer(self) -> None:
        self.scan_ui_timer.stop()

    def stop_fast_scan(self) -> None:
        if not self.scan_running:
            return
        self.emitter.log.emit("WARN", "Stopping scan...")
        self.scan_stop.set()
        self.scan_pause_event.set()

    def _scan_finish_ui_reset(self) -> None:
        self.scan_running = False
        self.btn_scan.setText("Start Scan")
        self.btn_scan.setEnabled(True)
        self.btn_pause_scan.setEnabled(False)
        self.btn_pause_scan.setText("Pause Scan")
        self.btn_browse.setEnabled(True)
        self.num_random_count.setEnabled(True)
        self.scan_ui_timer.stop()

    def _count_targets_in_file(self, path: str, use_random: bool, random_count: int) -> int:
        try:
            f = open(path, "r", encoding="utf-8", errors="ignore")
        except Exception:
            return 0

        total = 0
        try:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#") or line.startswith("//"):
                    continue
                line = line.split("#", 1)[0].split("//", 1)[0].strip()
                for t in line.replace(";", " ").replace(",", " ").split():
                    if not t:
                        continue
                    kind, val = _parse_scan_token(t)
                    if kind == "cidr" and val:
                        try:
                            net = ipaddress.ip_network(val, strict=False)
                            if net.version != 4:
                                continue
                            total_addrs = int(net.num_addresses)
                            if use_random and random_count > 0:
                                total += min(random_count, total_addrs)
                            else:
                                total += total_addrs
                        except Exception:
                            continue
                    elif kind == "ip" and val:
                        total += 1
            return total
        finally:
            try:
                f.close()
            except Exception:
                pass

    def _iter_targets_from_file(self, path: str, use_random: bool, random_count: int, cap: int):
        try:
            f = open(path, "r", encoding="utf-8", errors="ignore")
        except Exception:
            return

        try:
            for line in f:
                if self.scan_stop.is_set():
                    return
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#") or line.startswith("//"):
                    continue
                line = line.split("#", 1)[0].split("//", 1)[0].strip()
                for t in line.replace(";", " ").replace(",", " ").split():
                    if not t:
                        continue
                    kind, val = _parse_scan_token(t)
                    if kind == "cidr" and val:
                        self._enqueue_scan_log(f"Reading CIDR: {val}...")
                        if use_random and random_count > 0:
                            for ip in _cidr_sample_ips(val, random_count, random_count):
                                if self.scan_stop.is_set():
                                    return
                                yield ip
                        else:
                            try:
                                net = ipaddress.ip_network(val, strict=False)
                            except Exception:
                                continue
                            if net.version != 4:
                                continue
                            total_addrs = int(net.num_addresses)
                            for off in range(0, total_addrs):
                                if self.scan_stop.is_set():
                                    return
                                yield str(net.network_address + int(off))
                    elif kind == "ip" and val:
                        yield val
        finally:
            try:
                f.close()
            except Exception:
                pass

    def toggle_pause_scan(self) -> None:
        if not self.scan_running:
            return
        if self.scan_pause_event.is_set():
            self.scan_pause_event.clear()
            self.btn_pause_scan.setText("Resume")
            self.emitter.log.emit("INFO", "Scan paused.")
        else:
            self.scan_pause_event.set()
            self.btn_pause_scan.setText("Pause Scan")
            self.emitter.log.emit("INFO", "Scan resumed.")

    def _scan_ui_tick(self) -> None:
        if self._scan_ui_tick_running:
            return
        self._scan_ui_tick_running = True
        with self.scan_lock:
            total = self.scan_total
            checked = self.scan_checked
            success = self.scan_success
            fail = self.scan_fail

        self.lbl_total.setText(f"Total: {total}")
        self.lbl_checked.setText(f"Checked: {checked}")
        self.lbl_success.setText(f"Success: {success}")
        self.lbl_fail.setText(f"Fail: {fail}")

        if not self.real_ping_running:
            if total > 0:
                self.scan_progress.setRange(0, total)
                self.scan_progress.setValue(min(checked, total))
            else:
                self.scan_progress.setRange(0, 0)
        else:
            rp_total = max(1, int(getattr(self, "real_ping_total", 0)))
            rp_done = int(getattr(self, "real_ping_done", 0))
            if rp_total <= 0:
                self.scan_progress.setRange(0, 0)
            else:
                self.scan_progress.setRange(0, rp_total)
                self.scan_progress.setValue(min(rp_done, rp_total))

        batch = 0
        while batch < 100:
            try:
                ip, res, tid = self.scan_queue.get_nowait()
            except Empty:
                break
            self._handle_scan_result(ip, res, tid)
            batch += 1

        log_batch = 0
        lines = []
        while log_batch < 500:
            try:
                line = self.scan_log_queue.get_nowait()
            except Empty:
                break
            lines.append(line)
            log_batch += 1
        if lines:
            self.log_box.setUpdatesEnabled(False)
            self.log_box.append("\n".join(lines))
            self.log_box.setUpdatesEnabled(True)

        ping_batch = 0
        while ping_batch < 100:
            try:
                row_idx, text = self.ping_queue.get_nowait()
            except Empty:
                break
            if 0 <= row_idx < self.scan_table.rowCount():
                self.scan_table.setItem(row_idx, 3, QTableWidgetItem(text))
                self._apply_real_ping_color(row_idx, text)
            ping_batch += 1
        self._scan_ui_tick_running = False

    def _center_scan_row(self, row: int) -> None:
        if row < 0 or row >= self.scan_table.rowCount():
            return
        for c in range(self.scan_table.columnCount()):
            item = self.scan_table.item(row, c)
            if item:
                item.setTextAlignment(Qt.AlignCenter)

    def _handle_scan_result(self, ip: str, result: str, thread_id: int) -> None:
        # log line (like source)
        self._enqueue_scan_log(f"[Th-{thread_id}] {ip} -> {result}")

        # add only success to grid (like original scanner)
        if is_success_result(result):
            time_ms = self._extract_ms(result)
            row = self.scan_table.rowCount()
            self.scan_table.insertRow(row)
            self.scan_table.setItem(row, 0, QTableWidgetItem(ip))
            time_item = QTableWidgetItem()
            time_item.setData(Qt.EditRole, time_ms)
            self.scan_table.setItem(row, 1, time_item)
            self.scan_table.setItem(row, 2, QTableWidgetItem(self._strip_ping_from_result(result)))
            self.scan_table.setItem(row, 3, QTableWidgetItem(""))
            # color row by ping
            if time_ms >= 0:
                if time_ms < 350:
                    color = QColor("#b9f6ca")
                elif time_ms < 700:
                    color = QColor("#bbdefb")
                else:
                    color = QColor("#fff9c4")
                for c in range(4):
                    item = self.scan_table.item(row, c)
                    if item:
                        item.setBackground(color)
                        item.setForeground(QColor("#111111"))
            self._center_scan_row(row)
            self._center_scan_row(row)
            if hasattr(self, "scan_realtest_chk") and self.scan_realtest_chk.isChecked():
                self.scan_table.setItem(row, 3, QTableWidgetItem("Queued"))
                if not self.scan_realtest_worker or not self.scan_realtest_worker.is_alive():
                    self.scan_realtest_worker = threading.Thread(target=self._scan_realtest_worker_loop, daemon=True)
                    self.scan_realtest_worker.start()

    def on_scan_finished(self) -> None:
        self._scan_finish_ui_reset()
        self._scan_ui_tick()
        try:
            if not (hasattr(self, "scan_realtest_chk") and self.scan_realtest_chk.isChecked()
                    and (self.scan_realtest_worker and self.scan_realtest_worker.is_alive()
                         or self.scan_realtest_next_row < self.scan_table.rowCount())):
                self.scan_table.sortItems(1, Qt.AscendingOrder)
            else:
                self.emitter.scan_timer_start.emit()
        except Exception:
            pass
        self.emitter.log.emit("INFO", "Scan finished.")

    def browse_scan_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, APP_TITLE, "", "Text Files (*.txt *.csv *.cidrs);;All Files (*.*)")
        if not path:
            return
        self.scan_file_path = path
        self.btn_browse.setText(os.path.basename(path))
        has_plain_ips = self._file_has_plain_ips(path)
        if has_plain_ips:
            self.num_random_count.setEnabled(False)
            self.emitter.log.emit("INFO", "Loaded file with IPs. Random selection disabled.")
        else:
            self.num_random_count.setEnabled(True)
        self.emitter.log.emit("INFO", "Loading IPs...")

        def _count_now():
            random_count = int(self.num_random_count.value())
            use_random = random_count > 0
            total = self._count_targets_in_file(self.scan_file_path, use_random, random_count)
            with self.scan_lock:
                self.scan_total = total
                self.scan_checked = 0
                self.scan_success = 0
                self.scan_fail = 0
            self.emitter.scan_stats_updated.emit()

        threading.Thread(target=_count_now, daemon=True).start()

    def _file_has_plain_ips(self, path: str) -> bool:
        try:
            f = open(path, "r", encoding="utf-8", errors="ignore")
        except Exception:
            return False
        try:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#") or line.startswith("//"):
                    continue
                line = line.split("#", 1)[0].split("//", 1)[0].strip()
                for t in line.replace(";", " ").replace(",", " ").split():
                    if not t:
                        continue
                    kind, val = _parse_scan_token(t)
                    if kind == "ip" and val:
                        return True
            return False
        finally:
            try:
                f.close()
            except Exception:
                pass

    def _load_dns_list_tokens(self) -> List[str]:
        return list(self._imported_dns_list)

    def _has_dns_list_targets(self) -> bool:
        tokens = self._load_dns_list_tokens()
        for t in tokens:
            if "/" in t:
                return True
            if is_valid_ip(_strip_port(t)):
                return True
        return False

    def _count_targets_in_tokens(self, tokens: List[str], use_random: bool, random_count: int) -> int:
        total = 0
        for t in tokens:
            if not t:
                continue
            kind, val = _parse_scan_token(t)
            if kind == "cidr" and val:
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if net.version != 4:
                        continue
                    total_addrs = int(net.num_addresses)
                    if use_random and random_count > 0:
                        total += min(random_count, total_addrs)
                    else:
                        total += total_addrs
                except Exception:
                    continue
            elif kind == "ip" and val:
                total += 1
        return total

    def _iter_targets_from_tokens(self, tokens: List[str], use_random: bool, random_count: int, cap: int):
        for t in tokens:
            if self.scan_stop.is_set():
                return
            if not t:
                continue
            if kind == "cidr" and val:
                self._enqueue_scan_log(f"Reading CIDR: {val}...")
                if use_random and random_count > 0:
                    for ip in _cidr_sample_ips(val, random_count, random_count):
                        if self.scan_stop.is_set():
                            return
                        yield ip
                else:
                    try:
                        net = ipaddress.ip_network(val, strict=False)
                    except Exception:
                        continue
                    if net.version != 4:
                        continue
                    total_addrs = int(net.num_addresses)
                    for off in range(0, total_addrs):
                        if self.scan_stop.is_set():
                            return
                        yield str(net.network_address + int(off))
            elif kind == "ip" and val:
                yield val

    def save_scan_results(self) -> None:
        if self.scan_table.rowCount() == 0:
            return
        path, _ = QFileDialog.getSaveFileName(self, APP_TITLE, "Sorted_Scan_Results.txt", "Text Files (*.txt)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for r in range(self.scan_table.rowCount()):
                ip_item = self.scan_table.item(r, 0)
                time_item = self.scan_table.item(r, 1)
                detail_item = self.scan_table.item(r, 2)
                if not ip_item:
                    continue
                ip = ip_item.text()
                t = time_item.text() if time_item else ""
                detail = detail_item.text() if detail_item else ""
                f.write(f"{ip} - {t} - {detail}\n")
        QMessageBox.information(self, DIALOG_TITLE, "Saved successfully with format: IP - Time - Details")

    def show_save_ips_menu(self) -> None:
        menu = QMenu(self)
        act_all = QAction("Save All IPs", self)
        act_all.triggered.connect(self.save_scan_results)
        menu.addAction(act_all)
        act_ok = QAction("Save Real Test OK IPs", self)
        act_ok.triggered.connect(self.save_real_ping_ok_results)
        menu.addAction(act_ok)
        menu.exec(self.btn_save.mapToGlobal(self.btn_save.rect().bottomLeft()))

    def save_real_ping_ok_results(self) -> None:
        if self.scan_table.rowCount() == 0:
            return
        path, _ = QFileDialog.getSaveFileName(self, APP_TITLE, "RealPing_OK_IPs.txt", "Text Files (*.txt)")
        if not path:
            return
        saved = 0
        with open(path, "w", encoding="utf-8") as f:
            for r in range(self.scan_table.rowCount()):
                ip_item = self.scan_table.item(r, 0)
                ping_item = self.scan_table.item(r, 3)
                if not ip_item or not ping_item:
                    continue
                ping = ping_item.text().strip()
                if not ping or "ms" not in ping:
                    continue
                f.write(f"{ip_item.text()}\n")
                saved += 1
        QMessageBox.information(self, DIALOG_TITLE, f"Saved {saved} IPs with Real Ping.")

    def clear_scan_results(self, clear_log: bool = True) -> None:
        self.scan_table.setRowCount(0)
        if clear_log:
            self.log_box.clear()
            while not self.scan_log_queue.empty():
                try:
                    self.scan_log_queue.get_nowait()
                except Empty:
                    break
            self._scan_ui_tick_running = False
        while not self.ping_queue.empty():
            try:
                self.ping_queue.get_nowait()
            except Empty:
                break
        self.scan_realtest_next_row = 0
        with self.scan_lock:
            self.scan_total = 0
            self.scan_checked = 0
            self.scan_success = 0
            self.scan_fail = 0
            self.scan_processed = set()
        self._scan_ui_tick()

    def _enqueue_scan_log(self, text: str) -> None:
        try:
            self.scan_log_queue.put_nowait(text)
        except Exception:
            pass

    def toggle_scan_logs(self) -> None:
        return

    def save_remaining_project(self) -> None:
        if not self.scan_file_path:
            return
        path, _ = QFileDialog.getSaveFileName(self, APP_TITLE, f"Remaining_{time.strftime('%H%M')}.txt", "Text Files (*.txt)")
        if not path:
            return
        random_count = int(self.num_random_count.value())
        use_random = random_count > 0
        cap = int(self.config.get("cidr_expand_cap", 4096))
        remaining_count = 0
        with open(path, "w", encoding="utf-8") as f:
            for ip in self._iter_targets_from_file(self.scan_file_path, use_random, random_count, cap):
                if ip not in self.scan_processed:
                    f.write(ip + "\n")
                    remaining_count += 1
        QMessageBox.information(self, DIALOG_TITLE, f"Saved {remaining_count} IPs.")

    @staticmethod
    def _extract_ms(result: str) -> int:
        try:
            if "[" in result and "ms" in result:
                inner = result.split("[", 1)[1].split("]", 1)[0]
                inner = inner.replace("ms", "").strip()
                return int(inner)
        except Exception:
            pass
        return -1

    @staticmethod
    def _strip_ping_from_result(result: str) -> str:
        try:
            if "[" in result and "]" in result:
                return result.split("[", 1)[0].strip()
        except Exception:
            pass
        return result

    def show_scan_context_menu(self, pos) -> None:
        row = self.scan_table.rowAt(pos.y())
        if row >= 0 and not self.scan_table.selectionModel().isRowSelected(row, self.scan_table.rootIndex()):
            self.scan_table.selectRow(row)
        rows = {i.row() for i in self.scan_table.selectedIndexes()}
        rows = sorted(rows)
        if not rows:
            return
        menu = QMenu(self)
        act_add = QAction("Add Config To Proxy", self)
        act_add.triggered.connect(lambda: self.add_scan_rows_to_proxy(rows))
        menu.addAction(act_add)
        if len(rows) > 1:
            act_add_multi = QAction("Add Config To Proxy (Multi DNS)", self)
            act_add_multi.triggered.connect(lambda: self.add_scan_rows_to_proxy_multi(rows))
            menu.addAction(act_add_multi)
        menu.exec(self.scan_table.mapToGlobal(pos))

    def add_scan_row_to_proxy(self, row: int) -> None:
        if row < 0 or row >= self.scan_table.rowCount():
            return
        ip_item = self.scan_table.item(row, 0)
        if not ip_item:
            return
        dns_ip = ip_item.text().strip()
        if not dns_ip:
            return
        scan_domain = self.domain_input.text().strip()
        if not scan_domain:
            QMessageBox.warning(self, DIALOG_TITLE, "Domain cannot be empty.")
            return
        real_ping_item = self.scan_table.item(row, 3)
        real_ping = real_ping_item.text().strip() if real_ping_item else ""
        remarks = dns_ip if not real_ping else f"{dns_ip} [{real_ping}]"
        data = {
            "type": "SLIPSTREAM",
            "remarks": remarks,
            "address": dns_ip,
            "domain": scan_domain,
            "port": "53",
            "cert": dns_ip,
        }
        self._add_proxy_row(data)
        self.emitter.log.emit("INFO", f"Proxy: Added config from scan {dns_ip} / {scan_domain}")

    def add_scan_rows_to_proxy(self, rows: List[int]) -> None:
        for r in rows:
            self.add_scan_row_to_proxy(r)

    def add_scan_rows_to_proxy_multi(self, rows: List[int]) -> None:
        dns_list: List[str] = []
        for r in rows:
            if r < 0 or r >= self.scan_table.rowCount():
                continue
            ip_item = self.scan_table.item(r, 0)
            if not ip_item:
                continue
            dns_ip = ip_item.text().strip()
            if dns_ip and is_valid_ip(dns_ip):
                dns_list.append(dns_ip)
        dns_csv = _normalize_dns_csv(",".join(dns_list))
        if not dns_csv:
            return
        scan_domain = self.domain_input.text().strip()
        if not scan_domain:
            QMessageBox.warning(self, DIALOG_TITLE, "Domain cannot be empty.")
            return
        remarks = f"{len(_split_dns_csv(dns_csv))} DNS"
        data = {
            "type": "SLIPSTREAM",
            "remarks": remarks,
            "address": dns_csv,
            "domain": scan_domain,
            "port": "53",
            "cert": dns_csv,
        }
        self._add_proxy_row(data)
        self.emitter.log.emit("INFO", f"Proxy: Added multi DNS config from scan ({remarks}) / {scan_domain}")

    def set_dns_to_connect(self, ip: str) -> None:
        if self.real_ping_running:
            self.emitter.log.emit("WARN", "Real Ping is running. Wait for it to finish.")
            return
        self.connect_dns_input.setText(ip)
        self._bold_scan_row_for_ip(ip)
        if self.running or self.reconnecting:
            self.emitter.log.emit("INFO", "DNS changed. Reconnecting...")
            if self.proc_singbox and self.proc_singbox.poll() is None:
                self._restart_tunnel_only(ip)
            else:
                self.stop_connection()
                QTimer.singleShot(300, lambda: self.start_connection(ip_override=ip, force_scan_domain=True))
        else:
            QTimer.singleShot(200, lambda: self.start_connection(ip_override=ip, force_scan_domain=True))

    def _restart_tunnel_only(self, ip: str, domain_override: Optional[str] = None) -> None:
        self.current_dns_ip = ip
        self.graceful_stop = False
        self.set_status(f"Starting connection to {ip}...")
        self.slipstream_ready_event.clear()

        # stop only slipstream (keep sing-box running)
        if self.proc_tunnel:
            try:
                if self.proc_tunnel.poll() is None:
                    interrupt_process(self.proc_tunnel)
                    self.proc_tunnel.wait(timeout=2)
            except Exception:
                pass
        if os.name == "nt":
            taskkill_names([SLIPSTREAM_BIN])
        self.proc_tunnel = None

        domain = (domain_override or self.domain_input.text().strip()).strip()
        if not domain:
            return
        self.current_domain = domain
        if not self.current_proxy_remark:
            self.current_proxy_remark = self._get_proxy_remark_for_dns_domain(ip, domain)
        self.current_proxy_username, self.current_proxy_password = self._get_proxy_auth_for_dns_domain(ip, domain)
        self.spawn_slipstream_tunnel(ip, domain)

        # sing-box is already running, so proxy is up
        lan_mode = bool(self.config.get("lan_mode", False))
        listen_ip = "0.0.0.0" if lan_mode else "127.0.0.1"
        active_txt = self._format_active_proxy_display(ip, domain)
        suffix = f" | {active_txt}" if active_txt else ""
        self.set_status(f"CONNECTED | Mixed: {listen_ip}:{self.mixed_port_input.value()}{suffix}")

    def _bold_scan_row_for_ip(self, ip: str) -> None:
        if not ip:
            return
        for r in range(self.scan_table.rowCount()):
            ip_item = self.scan_table.item(r, 0)
            if not ip_item:
                continue
            font = ip_item.font()
            font.setBold(ip_item.text().strip() == ip)
            for c in range(4):
                item = self.scan_table.item(r, c)
                if item:
                    item.setFont(font)

    def _on_connect_request(self, ip: str) -> None:
        self.connect_dns_input.setText(ip)
        # If sing-box is already running, only restart slipstream (faster)
        if self.proc_singbox and self.proc_singbox.poll() is None:
            if self.current_domain:
                self.current_proxy_remark = self._get_proxy_remark_for_dns_domain(ip, self.current_domain)
                self.current_proxy_username, self.current_proxy_password = self._get_proxy_auth_for_dns_domain(ip, self.current_domain)
            self._restart_tunnel_only(ip, domain_override=self.current_domain)
            return
        if self.running or self.reconnecting:
            self.stop_connection()
        QTimer.singleShot(200, lambda: self.start_connection(ip_override=ip, force_scan_domain=True))

    def _on_disconnect_request(self) -> None:
        if self.running or self.reconnecting:
            self.stop_connection()

    def test_real_ping(self) -> None:
        was_connected = bool(self.running or self.reconnecting)
        prev_dns = self.current_dns_ip
        prev_domain = self.current_domain
        prev_remark = self.current_proxy_remark
        if was_connected:
            self.emitter.log.emit("INFO", "Real Ping: Disconnecting active proxy before test...")
            self.stop_connection()
        if self.scan_running:
            self.emitter.log.emit("WARN", "Scan is running. Stop scan first.")
            return
        if self.real_ping_running:
            self.emitter.log.emit("WARN", "Stopping Real Ping...")
            self.real_ping_stop.set()
            return
        if self.scan_table.rowCount() == 0:
            self.emitter.log.emit("WARN", "Table is empty. Nothing to test.")
            return

        self.real_ping_running = True
        self.real_ping_stop.clear()
        # clear previous real-test results
        for r in range(self.scan_table.rowCount()):
            self.scan_table.setItem(r, 3, QTableWidgetItem(""))
            for c in range(4):
                item = self.scan_table.item(r, c)
                if item:
                    item.setBackground(QBrush())
                    item.setForeground(QBrush())
        self.btn_real_ping.setText("Stop Real Ping")
        self.emitter.log.emit("INFO", "Starting Real Ping (slipstream SOCKS test)...")
        self.emitter.scan_timer_start.emit()
        self.real_ping_total = self.scan_table.rowCount()
        self.real_ping_done = 0
        self.scan_progress.setRange(0, max(1, self.real_ping_total))
        self.scan_progress.setValue(0)
        ready_timeout_ms = int(self.num_real_ping_delay.value())
        orig_dns = self.connect_dns_input.text()
        orig_port = int(self.mixed_port_input.value())
        orig_internal_port = getattr(self, "internal_port", None)
        orig_api_port = getattr(self, "api_port", None)

        def _worker():
            total_rows = self.scan_table.rowCount()
            done_rows = 0
            for row in range(total_rows):
                if self.closing:
                    break
                if self.scan_running:
                    break
                if self.real_ping_stop.is_set():
                    break
                ip_item = self.scan_table.item(row, 0)
                if not ip_item:
                    done_rows += 1
                    self.emitter.real_ping_progress.emit(done_rows)
                    continue
                ip = ip_item.text().strip()
                if not ip:
                    done_rows += 1
                    self.emitter.real_ping_progress.emit(done_rows)
                    continue
                self.emitter.real_ping_test_row.emit(row)
                # slipstream-only test: no sing-box required
                self.internal_port = get_free_port()
                self._restart_tunnel_only(ip)
                timeout_s = max(0.2, ready_timeout_ms / 1000.0)
                if not self._wait_for_slipstream_ready_or_socks(timeout=timeout_s):
                    self.ping_queue.put((row, "TIMEOUT"))
                    done_rows += 1
                    self.emitter.real_ping_progress.emit(done_rows)
                    continue
                ms, status = self._socks5_real_ping(
                    proxy_port=int(self.internal_port),
                    timeout=5.0,
                    host="www.google.com",
                    port=443,
                )
                if status in ("SOCKS FAIL", "ERROR", "TIMEOUT"):
                    ms, status = self._http_connect_real_ping(
                        proxy_port=int(self.internal_port),
                        timeout=5.0,
                        host="www.google.com",
                        port=443,
                    )
                self.ping_queue.put((row, status))
                done_rows += 1
                self.emitter.real_ping_progress.emit(done_rows)
            # restore original dns/port in UI + reconnect
            end_wait = time.monotonic() + 2.0
            while time.monotonic() < end_wait:
                if self.ping_queue.empty():
                    break
                self.emitter.scan_stats_updated.emit()
                time.sleep(0.05)
            self.connect_dns_input.setText(orig_dns)
            self.mixed_port_input.setValue(orig_port)
            if was_connected and prev_dns and prev_domain:
                self.current_proxy_remark = prev_remark
                self.emitter.log.emit("INFO", "Real Ping: Restoring previous proxy connection...")
                self.emitter.connect_request.emit(prev_dns)
            if orig_internal_port is not None:
                self.internal_port = orig_internal_port
            if orig_api_port is not None:
                self.api_port = orig_api_port
            self.real_ping_running = False
            self.real_ping_total = 0
            self.real_ping_done = 0
            self.btn_real_ping.setText("Test Real Ping")
            QTimer.singleShot(0, self._scan_ui_tick)
            self.emitter.scan_timer_stop.emit()
            if self.real_ping_stop.is_set():
                self.emitter.log.emit("INFO", "Real Ping stopped.")
            else:
                self.emitter.log.emit("INFO", "Real Ping finished.")

        threading.Thread(target=_worker, daemon=True).start()

    def _set_real_ping_testing_row(self, row: int) -> None:
        if 0 <= row < self.scan_table.rowCount():
            self.scan_table.selectRow(row)
            self.scan_table.setItem(row, 3, QTableWidgetItem("Testing..."))
            for c in range(4):
                item = self.scan_table.item(row, c)
                if item:
                    item.setBackground(QColor("#fff59d"))
                    item.setForeground(QColor("#111111"))
            self._center_scan_row(row)

    def _apply_real_ping_color(self, row: int, text: str) -> None:
        t = (text or "").strip().lower()
        if "ms" in t:
            try:
                ms = int(t.replace("ms", "").strip())
            except Exception:
                ms = -1
            if ms >= 0:
                if ms < 350:
                    color = QColor("#b9f6ca")
                elif ms < 700:
                    color = QColor("#bbdefb")
                else:
                    color = QColor("#fff9c4")
            else:
                color = QColor("#e0e0e0")
        elif "timeout" in t:
            color = QColor("#ffccbc")
        elif "fail" in t or "error" in t:
            color = QColor("#ffcdd2")
        else:
            color = QColor("#e0e0e0")

        for c in range(4):
            item = self.scan_table.item(row, c)
            if item:
                item.setBackground(color)
                item.setForeground(QColor("#111111"))
        self._center_scan_row(row)

    def _set_real_ping_progress(self, value: int) -> None:
        self.real_ping_done = int(value)
        total = max(1, int(getattr(self, "real_ping_total", 0)))
        self.scan_progress.setRange(0, total)
        self.scan_progress.setValue(min(self.real_ping_done, total))

    def _wait_for_slipstream_ready_or_socks(
        self,
        timeout: float = 15.0,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        user = self.current_proxy_username if username is None else username
        pwd = self.current_proxy_password if password is None else password
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.slipstream_ready_event.is_set():
                return True
            try:
                if self._socks5_probe(
                    int(self.internal_port),
                    timeout=0.8,
                    username=user,
                    password=pwd,
                ):
                    return True
            except Exception:
                pass
            time.sleep(0.2)
        return False

    def _socks5_probe(self, proxy_port: int, timeout: float = 1.0, username: str = "", password: str = "") -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(("127.0.0.1", proxy_port))
            if username and password:
                sock.sendall(b"\x05\x02\x00\x02")
                resp = sock.recv(2)
                if len(resp) != 2 or resp[0] != 0x05:
                    return False
                if resp[1] == 0x00:
                    return True
                if resp[1] != 0x02:
                    return False
                u = username.encode("utf-8")
                p = password.encode("utf-8")
                if len(u) > 255 or len(p) > 255:
                    return False
                auth_req = b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p
                sock.sendall(auth_req)
                auth_resp = sock.recv(2)
                return len(auth_resp) == 2 and auth_resp[1] == 0x00
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            return len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _proxy_real_ping(self, timeout: float = 5.0) -> Tuple[int, str]:
        start = time.monotonic()
        try:
            proxy_host = "127.0.0.1"
            proxy_port = int(self.mixed_port_input.value())
            # use random local port for test socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.bind(("", 0))
            except Exception:
                pass
            sock.connect((proxy_host, proxy_port))
            connect_req = (
                "CONNECT www.google.com:443 HTTP/1.1\r\n"
                "Host: www.google.com:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"
            ).encode("ascii")
            sock.sendall(connect_req)
            resp = sock.recv(4096)
            if b"200" not in resp.split(b"\r\n", 1)[0]:
                sock.close()
                return -1, "PROXY FAIL"
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(sock, server_hostname="www.google.com")
            try:
                tls.settimeout(timeout)
            except Exception:
                pass
            req = b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            tls.sendall(req)
            tls.recv(64)
            tls.close()
            ms = int((time.monotonic() - start) * 1000)
            return ms, f"{ms} ms"
        except socket.timeout:
            return -1, "TIMEOUT"
        except Exception:
            return -1, "ERROR"

    def _proxy_real_ping_on_port(self, proxy_port: int, timeout: float = 5.0) -> Tuple[int, str]:
        start = time.monotonic()
        try:
            proxy_host = "127.0.0.1"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.bind(("", 0))
            except Exception:
                pass
            sock.connect((proxy_host, int(proxy_port)))
            connect_req = (
                "CONNECT www.google.com:443 HTTP/1.1\r\n"
                "Host: www.google.com:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"
            ).encode("ascii")
            sock.sendall(connect_req)
            resp = sock.recv(4096)
            if b"200" not in resp.split(b"\r\n", 1)[0]:
                sock.close()
                return -1, "PROXY FAIL"
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(sock, server_hostname="www.google.com")
            req = b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            tls.sendall(req)
            tls.recv(64)
            tls.close()
            ms = int((time.monotonic() - start) * 1000)
            return ms, f"{ms} ms"
        except socket.timeout:
            return -1, "TIMEOUT"
        except Exception:
            return -1, "ERROR"

    def _run_proxy_test_core(
        self,
        dns_ip: str,
        domain: str,
        timeout: float,
        username: str = "",
        password: str = "",
    ) -> Tuple[Optional[subprocess.Popen], Optional[subprocess.Popen], int]:
        tunnel_proc, internal_port, ready = self._run_slipstream_test(
            dns_ip,
            domain,
            timeout=timeout,
            username=username,
            password=password,
        )
        if not ready or not tunnel_proc:
            return tunnel_proc, None, 0

        mixed_port = get_free_port()
        config = {
            "log": {"level": "error"},
            "inbounds": [
                {
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "listen_port": int(mixed_port),
                    "sniff": True,
                    "sniff_override_destination": True,
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "server": "127.0.0.1",
                    "server_port": int(internal_port),
                    "version": "5",
                }
            ],
        }
        if username and password:
            config["outbounds"][0]["username"] = username
            config["outbounds"][0]["password"] = password

        test_cfg = config_path(f"config_proxy_test_{mixed_port}.json")
        with open(test_cfg, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        singbox_path = bin_path("sing-box.exe")
        if not os.path.exists(singbox_path):
            singbox_path = "sing-box.exe"

        try:
            sing_proc = subprocess.Popen(
                [singbox_path, "run", "-c", test_cfg],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except Exception:
            try:
                os.remove(test_cfg)
            except Exception:
                pass
            return tunnel_proc, None, 0

        end = time.monotonic() + 5.0
        ready = False
        while time.monotonic() < end:
            try:
                if self._socks5_probe(int(mixed_port), timeout=0.5):
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.2)

        if not ready:
            return tunnel_proc, sing_proc, 0
        return tunnel_proc, sing_proc, mixed_port
    def _http_connect_real_ping(self, proxy_port: int, timeout: float, host: str, port: int) -> Tuple[int, str]:
        start = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.bind(("", 0))
            except Exception:
                pass
            sock.connect(("127.0.0.1", proxy_port))
            connect_req = (
                f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"
            ).encode("ascii")
            sock.sendall(connect_req)
            resp = sock.recv(4096)
            if b"200" not in resp.split(b"\r\n", 1)[0]:
                sock.close()
                return -1, "PROXY FAIL"
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(sock, server_hostname=host)
            req = b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            tls.sendall(req)
            tls.recv(64)
            tls.close()
            ms = int((time.monotonic() - start) * 1000)
            return ms, f"{ms} ms"
        except socket.timeout:
            return -1, "TIMEOUT"
        except Exception:
            return -1, "ERROR"

    def _socks5_real_ping(self, proxy_port: int, timeout: float, host: str, port: int) -> Tuple[int, str]:
        start = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.bind(("", 0))
            except Exception:
                pass
            sock.connect(("127.0.0.1", proxy_port))

            # SOCKS5 handshake (no auth)
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
                sock.close()
                return -1, "SOCKS FAIL"

            host_bytes = host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")
            sock.sendall(req)
            resp = sock.recv(10)
            if len(resp) < 2 or resp[1] != 0x00:
                sock.close()
                return -1, "SOCKS FAIL"

            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(sock, server_hostname=host)
            req = b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            tls.sendall(req)
            tls.recv(64)
            tls.close()
            ms = int((time.monotonic() - start) * 1000)
            return ms, f"{ms} ms"
        except socket.timeout:
            return -1, "TIMEOUT"
        except Exception:
            return -1, "ERROR"



    # ================= Connection / Hotspot =================
    def on_lan_mode_changed(self) -> None:
        sender = self.sender()
        if sender is self.lan_mode_chk_proxy:
            self.lan_mode_chk.blockSignals(True)
            self.lan_mode_chk.setChecked(self.lan_mode_chk_proxy.isChecked())
            self.lan_mode_chk.blockSignals(False)
        self.config["lan_mode"] = bool(self.lan_mode_chk.isChecked())
        save_config(self.config)
        self.update_lan_info()
        if self.config["lan_mode"]:
            ip = self.get_lan_ip()
            port = int(self.mixed_port_input.value())
            self.emitter.log.emit("INFO", f"Hotspot Mode enabled. Phone proxy => {ip}:{port}")
            self.emitter.log.emit("INFO", f"Hotspot Mode listening on 0.0.0.0:{port}")
        else:
            self.emitter.log.emit("INFO", "Hotspot Mode disabled.")
        if hasattr(self, "lan_mode_chk_proxy"):
            if self.lan_mode_chk_proxy.isChecked() != self.lan_mode_chk.isChecked():
                self.lan_mode_chk_proxy.blockSignals(True)
                self.lan_mode_chk_proxy.setChecked(self.lan_mode_chk.isChecked())
                self.lan_mode_chk_proxy.blockSignals(False)

    def on_auto_reconnect_changed(self) -> None:
        sender = self.sender()
        if sender is self.auto_reconnect_chk_proxy:
            self.auto_reconnect_chk.blockSignals(True)
            self.auto_reconnect_chk.setChecked(self.auto_reconnect_chk_proxy.isChecked())
            self.auto_reconnect_chk.blockSignals(False)
        self.config["auto_reconnect"] = bool(self.auto_reconnect_chk.isChecked())
        save_config(self.config)
        state = "enabled" if self.config["auto_reconnect"] else "disabled"
        self.emitter.log.emit("INFO", f"Auto reconnect {state}.")
        if hasattr(self, "auto_reconnect_chk_proxy"):
            if self.auto_reconnect_chk_proxy.isChecked() != self.auto_reconnect_chk.isChecked():
                self.auto_reconnect_chk_proxy.blockSignals(True)
                self.auto_reconnect_chk_proxy.setChecked(self.auto_reconnect_chk.isChecked())
                self.auto_reconnect_chk_proxy.blockSignals(False)

    @staticmethod
    def get_all_local_ipv4() -> List[str]:
        ips: List[str] = []
        try:
            host = socket.gethostname()
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                if fam == socket.AF_INET:
                    ip = sockaddr[0]
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private and not ip_obj.is_loopback:
                            if ip not in ips:
                                ips.append(ip)
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private and not ip_obj.is_loopback and ip not in ips:
                ips.insert(0, ip)
        except Exception:
            pass
        return ips

    @classmethod
    def get_lan_ip(cls) -> str:
        ips = cls.get_all_local_ipv4()
        for ip in ips:
            if ip.startswith("192.168.137."):
                return ip
        return ips[0] if ips else ""

    def update_lan_info(self) -> None:
        ip = self.get_lan_ip()
        port = self.mixed_port_input.value()
        if ip:
            self.lan_info_lbl.setText(f"LAN IP: {ip} | Mixed Port: {port}  (Use this on phone)")
        else:
            self.lan_info_lbl.setText("LAN: Not available (No private IPv4 detected)")

    def open_hotspot_settings(self) -> None:
        try:
            subprocess.Popen(["cmd", "/c", "start", "ms-settings:network-mobilehotspot"], shell=False)
            self.emitter.log.emit("INFO", "Opened Windows Mobile Hotspot settings.")
            self.emitter.log.emit(
                "INFO",
                "Tip: Enable Mobile Hotspot, connect your phone, then set phone proxy to your PC LAN IP + Mixed Port.",
            )
        except Exception as e:
            self.emitter.log.emit("ERROR", f"Failed to open hotspot settings: {e}")

    def enable_system_proxy(self) -> None:
        port = self.mixed_port_input.value()
        if set_system_proxy(port):
            self.emitter.log.emit("INFO", f"System Proxy set to 127.0.0.1:{port}")
            self.tray_icon.showMessage(APP_TITLE, "System Proxy Enabled", QSystemTrayIcon.Information, 1000)
            self.config["proxy_system_set"] = True
            save_config(self.config)
            try:
                self.proxy_action_combo.blockSignals(True)
                self.proxy_action_combo.setCurrentIndex(0)
            finally:
                self.proxy_action_combo.blockSignals(False)
        else:
            self.emitter.log.emit("ERROR", "Failed to set System Proxy.")

    def disable_system_proxy(self) -> None:
        if clear_system_proxy():
            self.emitter.log.emit("INFO", "System Proxy cleared.")
            self.tray_icon.showMessage(APP_TITLE, "System Proxy Cleared", QSystemTrayIcon.Information, 1000)
            self.config["proxy_system_set"] = False
            save_config(self.config)
            try:
                self.proxy_action_combo.blockSignals(True)
                self.proxy_action_combo.setCurrentIndex(1)
            finally:
                self.proxy_action_combo.blockSignals(False)
        else:
            self.emitter.log.emit("ERROR", "Failed to clear System Proxy.")

    def on_connect_clicked(self) -> None:
        if self.running or self.reconnecting:
            self.stop_connection()
        else:
            self.start_connection()

    def start_connection(
        self,
        ip_override: Optional[str] = None,
        *,
        is_reconnect: bool = False,
        domain_override: Optional[str] = None,
        force_scan_domain: bool = False,
    ) -> None:
        if domain_override:
            domain = domain_override.strip()
        elif force_scan_domain:
            domain = self.domain_input.text().strip()
        else:
            domain = ""
            if self.current_domain:
                domain = self.current_domain.strip()
            if not domain:
                active_domain = self._get_active_proxy_domain()
                if active_domain:
                    domain = active_domain
            if not domain:
                domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.critical(self, DIALOG_TITLE, "Error: Domain cannot be empty.")
            return

        typed_ip = self.connect_dns_input.text().strip()
        target_ip = ip_override if ip_override else (typed_ip if typed_ip else self.get_selected_ip())
        if not target_ip:
            QMessageBox.warning(self, DIALOG_TITLE, "Please select a DNS server first.")
            return
        target_ip_norm = _normalize_dns_csv(target_ip)
        if not target_ip_norm:
            QMessageBox.warning(self, DIALOG_TITLE, "Invalid DNS resolver list.")
            return
        target_ip = target_ip_norm

        # persist settings (scan domain only)
        if domain_override is None:
            self.config["domain"] = domain
        self.config["mixed_port"] = int(self.mixed_port_input.value())
        self.config["lan_mode"] = bool(self.lan_mode_chk.isChecked())
        self.config["last_selected_dns"] = target_ip
        save_config(self.config)

        if not is_reconnect:
            self.reconnect_attempts = 0
            self.running = True
            self.reconnecting = False
        else:
            self.running = True
            self.reconnecting = True

        self.current_dns_ip = target_ip
        self.current_domain = domain
        self.current_proxy_remark = self._get_proxy_remark_for_dns_domain(target_ip, domain)
        self.current_proxy_username, self.current_proxy_password = self._get_proxy_auth_for_dns_domain(target_ip, domain)
        self.graceful_stop = False

        lan_mode = bool(self.config.get("lan_mode", False))
        listen_ip = "0.0.0.0" if lan_mode else "127.0.0.1"

        # if sing-box is already running, keep ports stable
        if not self.proc_singbox or self.proc_singbox.poll() is not None:
            self.internal_port = get_free_port()
            self.api_port = get_free_port()

        self.set_status(f"Starting connection to {target_ip}...")
        self.connect_btn.setText("⛔ DISCONNECT")
        self.connect_btn.setStyleSheet("background-color: #c62828; color: white; font-weight: bold; padding: 12px;")
        if hasattr(self, "proxy_connect_btn"):
            self.proxy_connect_btn.setText("DISCONNECT")
            self.proxy_connect_btn.setStyleSheet("background-color: #c62828; color: white; font-weight: bold; padding: 6px 12px;")

        self.update_traffic_labels("0.00 B/s", "0.00 B/s", "0.00 B", "0.00 B")

        self.spawn_slipstream_tunnel(target_ip, domain)
        if not self.proc_singbox or self.proc_singbox.poll() is not None:
            threading.Timer(1.0, self.spawn_singbox).start()
        else:
            self.running = True
            self.reconnecting = False
            self.reconnect_attempts = 0
            active_txt = self._format_active_proxy_display(target_ip, domain)
            suffix = f" | {active_txt}" if active_txt else ""
            self.set_status(f"CONNECTED | Mixed: {listen_ip}:{self.mixed_port_input.value()}{suffix}")
            if lan_mode:
                ip = self.get_lan_ip()
                self.emitter.log.emit("INFO", f"LAN Mode enabled. Phone proxy => {ip}:{self.mixed_port_input.value()}")

            def _start_tm():
                if not self.running:
                    return
                self.traffic_thread = TrafficMonitor(int(self.api_port), self.emitter)
                self.traffic_thread.start()

            if not self.traffic_thread or not self.traffic_thread.is_alive():
                threading.Timer(1.5, _start_tm).start()
        self.start_monitor_thread()

    def spawn_slipstream_tunnel(self, dns_ip: str, domain: str) -> None:
        slip_path = bin_path(SLIPSTREAM_BIN)
        if not os.path.exists(slip_path):
            slip_path = SLIPSTREAM_BIN

        resolver_args = _resolver_args_from_dns(dns_ip)
        if not resolver_args:
            self.emitter.log.emit("ERROR", "Invalid DNS resolver list.")
            return
        cmd = [
            slip_path,
            *resolver_args,
            "--domain",
            domain,
            "--tcp-listen-port",
            str(self.internal_port),
        ]
        taskkill_names(["slipstream-client-windows-amd64.exe"])
        self.emitter.log.emit("INFO", f"Executing SLIPSTREAM with DNS: {dns_ip}")
        self.slipstream_ready_event.clear()
        try:
            self.proc_tunnel = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=(subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == "nt" else 0,
            )
            threading.Thread(target=self.pipe_reader, args=(self.proc_tunnel, "SLIPSTREAM"), daemon=True).start()
        except FileNotFoundError:
            self.emitter.log.emit("ERROR", f"{SLIPSTREAM_BIN} not found.")
            self.stop_connection()

    def spawn_singbox(self) -> None:
        if not self.running and not self.reconnecting:
            return

        lan_mode = bool(self.config.get("lan_mode", False))
        listen_ip = "0.0.0.0" if lan_mode else "127.0.0.1"

        proxy_mode = str(self.config.get("proxy_mode", "Global"))
        outbounds = [
            {
                "type": "socks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": int(self.internal_port),
                "version": "5",
            },
            {"type": "direct", "tag": "direct"},
        ]
        if self.current_proxy_username and self.current_proxy_password:
            outbounds[0]["username"] = self.current_proxy_username
            outbounds[0]["password"] = self.current_proxy_password

        route = None
        if proxy_mode == "IR-Direct":
            rules = []
            rule_set = []

            geoip_srs = resource_path(os.path.join("geo", "srss", "geoip-ir.srs"))
            if os.path.exists(geoip_srs):
                rule_set.append(
                    {
                        "tag": "geoip-ir",
                        "type": "local",
                        "format": "binary",
                        "path": geoip_srs,
                    }
                )
                rules.append({"rule_set": ["geoip-ir"], "outbound": "direct"})
            else:
                self.emitter.log.emit("WARN", "Proxy: geo/srss/geoip-ir.srs not found.")

            geosite_srs = resource_path(os.path.join("geo", "srss", "geosite-ir.srs"))
            if os.path.exists(geosite_srs):
                rule_set.append(
                    {
                        "tag": "geosite-ir",
                        "type": "local",
                        "format": "binary",
                        "path": geosite_srs,
                    }
                )
                rules.append({"rule_set": ["geosite-ir"], "outbound": "direct"})
            else:
                self.emitter.log.emit("WARN", "Proxy: geo/srss/geosite-ir.srs not found.")

            route = {
                "rule_set": rule_set,
                "rules": rules,
                "final": "proxy",
            }

        config = {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "mixed",
                    "listen": listen_ip,
                    "listen_port": int(self.mixed_port_input.value()),
                    "sniff": True,
                    "sniff_override_destination": True,
                }
            ],
            "outbounds": outbounds,
            "experimental": {
                "clash_api": {
                    "external_controller": f"127.0.0.1:{int(self.api_port)}",
                }
            },
        }
        if route:
            config["route"] = route

        cfg_path = config_path(RUNTIME_CONFIG_NAME)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        singbox_path = bin_path("sing-box.exe")
        if not os.path.exists(singbox_path):
            singbox_path = "sing-box.exe"

        try:
            self.proc_singbox = subprocess.Popen(
                [singbox_path, "run", "-c", cfg_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            threading.Thread(target=self.pipe_reader, args=(self.proc_singbox, "SING-BOX"), daemon=True).start()
            self.running = True
            self.reconnecting = False
            self.reconnect_attempts = 0
            active_txt = self._format_active_proxy_display(self.current_dns_ip, self.current_domain)
            suffix = f" | {active_txt}" if active_txt else ""
            self.set_status(f"CONNECTED | Mixed: {listen_ip}:{self.mixed_port_input.value()}{suffix}")
            if lan_mode:
                ip = self.get_lan_ip()
                self.emitter.log.emit("INFO", f"LAN Mode enabled. Phone proxy => {ip}:{self.mixed_port_input.value()}")

            def _start_tm():
                if not self.running:
                    return
                self.traffic_thread = TrafficMonitor(int(self.api_port), self.emitter)
                self.traffic_thread.start()

            threading.Timer(2.0, _start_tm).start()
        except FileNotFoundError:
            self.emitter.log.emit("ERROR", "sing-box.exe not found.")
            self.stop_connection()

    def stop_connection(self) -> None:
        if not (self.running or self.reconnecting):
            return
        self.graceful_stop = True
        self.cancel_reconnect_timer()
        self.force_stop()
        self.running = False
        self.reconnecting = False
        self.current_dns_ip = None
        self.current_domain = None
        self.current_proxy_username = ""
        self.current_proxy_password = ""
        self.reconnect_attempts = 0
        self.graceful_stop = False
        self.set_status("Stopped")
        self.connect_btn.setText("🚀 CONNECT (Slipstream)")
        self.connect_btn.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 12px;")
        if hasattr(self, "proxy_connect_btn"):
            self.proxy_connect_btn.setText("CONNECT")
            self.proxy_connect_btn.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 6px 12px;")
        self._update_proxy_connect_state()

    def force_stop(self) -> None:
        self.stop_monitor_thread()
        if self.traffic_thread:
            self.traffic_thread.stop()
            self.traffic_thread = None

        for p in [self.proc_tunnel, self.proc_singbox]:
            if p:
                try:
                    if p.poll() is None:
                        interrupt_process(p)
                        p.wait(timeout=2)
                except Exception:
                    pass
        if os.name == "nt":
            taskkill_names([SLIPSTREAM_BIN, SINGBOX_BIN])
        self.proc_tunnel = None
        self.proc_singbox = None

    # --- reconnect monitor ---
    def cancel_reconnect_timer(self) -> None:
        if self.reconnect_timer:
            try:
                self.reconnect_timer.cancel()
            except Exception:
                pass
            self.reconnect_timer = None

    def start_monitor_thread(self) -> None:
        self.stop_monitor_thread()
        self.monitor_stop_event = threading.Event()
        self.monitor_thread = threading.Thread(target=self.connection_monitor_worker, daemon=True)
        self.monitor_thread.start()

    def stop_monitor_thread(self) -> None:
        if getattr(self, "monitor_thread", None) and self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_stop_event.set()
            self.monitor_thread.join(timeout=2)
        self.monitor_thread = None
        self.monitor_stop_event = threading.Event()

    def connection_monitor_worker(self) -> None:
        while not self.monitor_stop_event.wait(3):
            if not self.running:
                continue
            tunnel_dead = self.proc_tunnel and (self.proc_tunnel.poll() is not None)
            singbox_dead = self.proc_singbox and (self.proc_singbox.poll() is not None)
            if tunnel_dead or singbox_dead:
                if self.graceful_stop:
                    break
                reason = "Tunnel process stopped unexpectedly." if tunnel_dead else "Proxy core stopped unexpectedly."
                self.emitter.connection_drop.emit(reason)
                break

    def handle_connection_drop(self, reason: str) -> None:
        if not self.running:
            return
        self.emitter.log.emit("WARN", reason)
        if not self.auto_reconnect_chk.isChecked():
            self.emitter.log.emit("WARN", "Auto reconnect disabled. Connection stopped.")
            self.stop_connection()
            return

        self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        if not self.current_dns_ip:
            self.emitter.log.emit("ERROR", "No target DNS stored for reconnect. Stopping connection.")
            self.stop_connection()
            return

        if self.reconnect_attempts >= self.max_reconnect_attempts:
            self.emitter.log.emit("ERROR", f"Auto reconnect failed after {self.max_reconnect_attempts} attempts. Giving up.")
            self.stop_connection()
            return

        self.reconnect_attempts += 1
        self.reconnecting = True
        self.emitter.log.emit("INFO", f"Auto reconnect attempt {self.reconnect_attempts}/{self.max_reconnect_attempts}...")

        if self.traffic_thread:
            self.traffic_thread.stop()
            self.traffic_thread = None

        self.graceful_stop = True
        self.force_stop()
        self.graceful_stop = False

        delay = min(5, self.reconnect_attempts * 2)
        self.cancel_reconnect_timer()
        self.reconnect_timer = threading.Timer(delay, lambda: self.start_connection(self.current_dns_ip, is_reconnect=True))
        self.reconnect_timer.start()

    # ================= UI helpers =================
    def pipe_reader(self, proc: subprocess.Popen, tag: str) -> None:
        try:
            if not proc.stdout:
                return
            for line in proc.stdout:
                if not line:
                    continue
                msg = line.rstrip()
                if tag == "SLIPSTREAM":
                    if "Connection ready" in msg:
                        self.slipstream_ready_event.set()
                    if "Server certificate pinning is disabled" in msg:
                        continue
                low = msg.lower()
                lvl = "DEBUG"
                if "forcibly closed" in low or "closed" in low:
                    lvl = "WARN"
                elif "error" in low or "fail" in low:
                    lvl = "ERROR"
                elif "warn" in low:
                    lvl = "WARN"
                self.emitter.log.emit(lvl, f"[{tag}] {msg}")
        except Exception:
            pass

    def set_status(self, s: str) -> None:
        self.status_lbl.setText(s)
        upper = s.upper()
        if "STARTING" in upper or "RECONNECT" in upper:
            self.status_lbl.setStyleSheet("color: orange; font-weight: bold;")
            with self.conn_state_lock:
                self.conn_state = "starting"
                self.conn_connected_event.clear()
        elif "CONNECTED" in upper:
            self.status_lbl.setStyleSheet("color: #00e676; font-weight: bold;")
            with self.conn_state_lock:
                self.conn_state = "connected"
                self.conn_connected_event.set()
        elif "STOPPED" in upper:
            self.status_lbl.setStyleSheet("color: #ffeb3b; font-weight: bold;")
            with self.conn_state_lock:
                self.conn_state = "stopped"
                self.conn_connected_event.clear()
        else:
            self.status_lbl.setStyleSheet("color: white; font-weight: bold;")

    def update_traffic_labels(self, up_speed: str, down_speed: str, total_up: str, total_down: str) -> None:
        self.lbl_up_speed.setText(f"↑ Speed: {up_speed}")
        self.lbl_down_speed.setText(f"↓ Speed: {down_speed}")
        self.lbl_total_up.setText(f"Total Up: {total_up}")
        self.lbl_total_down.setText(f"Total Down: {total_down}")
        if hasattr(self, "proxy_traffic_lbl"):
            self.proxy_traffic_lbl.setText(f"↑ {up_speed}  ↓ {down_speed}   Total ↑ {total_up}  ↓ {total_down}")

    # ================= Tray & Window =================
    def changeEvent(self, event) -> None:
        if event.type() == QEvent.WindowStateChange:
            pass
        super().changeEvent(event)

    def closeEvent(self, event) -> None:
        # Minimize to tray instead of closing
        self.hide()
        self.tray_icon.showMessage(APP_TITLE, "App minimized to tray.", QSystemTrayIcon.Information, 1000)
        event.ignore()

    def show_window(self) -> None:
        self.showNormal()
        self.activateWindow()

    def on_tray_click(self, reason) -> None:
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_window()

    def close_app(self) -> None:
        self.cancel_reconnect_timer()
        self.force_stop()
        self.disable_system_proxy()
        QApplication.quit()

    def show_log_context_menu(self, pos) -> None:
        menu = QMenu(self)
        act_copy_all = QAction("Copy All", self)
        act_copy_all.triggered.connect(lambda: QApplication.clipboard().setText(self.log_box.toPlainText()))
        act_export = QAction("Export Log...", self)

        def _export():
            path, _ = QFileDialog.getSaveFileName(self, APP_TITLE, "scanner_log.txt", "Text Files (*.txt)")
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.log_box.toPlainText())
                self.emitter.log.emit("INFO", f"Log exported: {path}")

        act_export.triggered.connect(_export)
        act_clear = QAction("Clear Log", self)
        act_clear.triggered.connect(self.log_box.clear)

        menu.addAction(act_copy_all)
        menu.addAction(act_export)
        menu.addSeparator()
        menu.addAction(act_clear)
        menu.exec(self.log_box.mapToGlobal(pos))


if __name__ == "__main__":
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass

    if sys.platform == "linux":
        # Force X11 backend to avoid Wayland/Input Method segfaults on some distros
        os.environ["QT_QPA_PLATFORM"] = "xcb"

    app = QApplication(sys.argv)
    shared = QSharedMemory(APP_ID)
    if not shared.create(1):
        QMessageBox.critical(None, DIALOG_TITLE, "Slipstream Plus already is running !")
        sys.exit(0)
    app.setApplicationName("Scanner")
    app.setApplicationDisplayName(APP_TITLE)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)

    w = App()
    w.show()

    # Allow Ctrl+C to close the app
    def signal_handler(sig, frame):
        print("\nCtrl+C caught. Exiting...")
        w.close_app()

    signal.signal(signal.SIGINT, signal_handler)

    # Timer to let Python interpreter run periodically to catch signals
    timer = QTimer()
    timer.start(200)
    timer.timeout.connect(lambda: None)

    sys.exit(app.exec())
