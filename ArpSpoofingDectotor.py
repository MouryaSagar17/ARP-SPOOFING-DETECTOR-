import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from tkinter import ttk   # <-- added for CSV viewer
import threading
import os
import csv
import subprocess
import smtplib
import cv2  # type: ignore
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import time
import socket
import uuid
import base64
import tempfile
import webbrowser
from typing import Dict, List, Tuple

# safe scapy imports with graceful fallback (do NOT exit if scapy missing)
sniff = None
ARP = None
conf = None
get_if_list = lambda: []
get_windows_if_list = None
try:
    from scapy.all import sniff as _sniff, ARP as _ARP, conf as _conf, get_if_list as _get_if_list  # pyright: ignore[reportMissingImports]
    sniff = _sniff
    ARP = _ARP
    conf = _conf
    get_if_list = _get_if_list
    try:
        from scapy.all import get_windows_if_list as _gw  # pyright: ignore[reportMissingImports]
        get_windows_if_list = _gw
    except Exception:
        try:
            from scapy.arch.windows import get_windows_if_list as _gw  # pyright: ignore[reportMissingImports]
            get_windows_if_list = _gw
        except Exception:
            get_windows_if_list = None
except Exception:
    # scapy not available; UI should still start and ARP-table scanner will work.
    print("[STARTUP WARN] scapy not available; packet sniffing disabled. ARP-table monitor still works.")
    pass

# ================= GLOBALS =================
monitoring = False
baseline_arp = {}
LOG_FILE = "arp_logs.csv"
VIDEO_PATH = "background.mp4"

# file used for duplicate-MAC incidents
ARP_DUP_LOG = "arp_duplicate_mac.csv"

# internal control for monitor thread
arp_monitor_thread = None

# track MACs already emailed during current monitoring session (prevent duplicate emails)
ALERTED_MACS = set()

# ======== EMAIL CONFIG (EDIT) ========
# Use environment variables (set in the same PowerShell session where you run the script)
# Accept multiple common names (fallbacks) so both persistent setx and ad-hoc names work.
SMTP_SERVER = os.environ.get("SMTP_SERVER") or os.environ.get("SMTP_HOST")
SMTP_PORT = None
_port_raw = os.environ.get("SMTP_PORT") or os.environ.get("PORT") or os.environ.get("SMTP_PORT_ALT")
if _port_raw:
    try:
        SMTP_PORT = int(_port_raw)
    except Exception:
        SMTP_PORT = None

SENDER_EMAIL = os.environ.get("SENDER_EMAIL") or os.environ.get("SMTP_USER") or os.environ.get("FROM_EMAIL")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD") or os.environ.get("SMTP_PASS")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL") or os.environ.get("ADMIN") or os.environ.get("FROM_EMAIL")

# safe log function (GUI log_box may not exist at import time)
def log_message(msg):
    # print to console for debugging/CLI visibility
    print(msg)
    try:
        # write into GUI log if available and configured
        if "log_box" in globals() and log_box:
            low = (msg or "").lower()
            # classify suspicious messages (make these red)
            if ("arp spoof" in low) or ("spoof" in low) or ("⚠️" in msg) or ("[arp mon error]" in low) or ("[arp spoof]" in low) or ("arp spoofing detected" in low):
                tag = "suspicious"
            # informational messages (neon green)
            elif ("[info]" in low) or ("[sniff]" in low) or ("[arp mon]" in low) or ("starting" in low) or ("started" in low):
                tag = "info"
            else:
                tag = None

            if tag:
                log_box.insert("end", msg + "\n", tag)
            else:
                log_box.insert("end", msg + "\n")
            log_box.see("end")
    except Exception:
        pass

def save_log(row):
    """
    Append CSV row and write a styled 'hacker theme' plain-text log matching the screenshot.
    Expected row format: [Date, Time, IP, Expected MAC, Spoofed MAC, Status]
    """
    # CSV write (preserve existing behavior)
    file_exists = os.path.exists(LOG_FILE)
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Date", "Time", "IP", "Expected MAC", "Spoofed MAC", "Status"])
            writer.writerow(row)
    except Exception as e:
        log_message(f"[LOG ERROR] Failed to write CSV log: {e}")

    # Styled hacker-theme plain-text log
    SPOOF_LOG_FILE = "spoofing_logs.txt"
    try:
        # defensive extraction
        date = str(row[0]) if len(row) > 0 else ""
        t = str(row[1]) if len(row) > 1 else ""
        ip = str(row[2]) if len(row) > 2 else "unknown"
        expected = str(row[3]) if len(row) > 3 else "unknown"
        spoofed = str(row[4]) if len(row) > 4 else "unknown"
        status = str(row[5]) if len(row) > 5 else "ALERT"

        timestamp = f"{date} {t}".strip()

        # normalize MAC to dash-separated lower-case (08-00-27-..)
        def mac_dash(m):
            m = (m or "").strip().lower()
            compact = re.sub(r"[^0-9a-f]", "", m)
            if len(compact) == 12:
                return "-".join(compact[i:i+2] for i in range(0, 12, 2))
            return m or "unknown"

        expected_fmt = mac_dash(expected)
        spoofed_fmt = mac_dash(spoofed)

        # Compose log lines similar to the image
        header = f"[{timestamp}] ALERT: IP {ip} | Expected: {expected_fmt} | Spoofed: {spoofed_fmt}"
        detail = f"Victim IP: {ip} | Original: {expected_fmt} | Spoofed: {spoofed_fmt}"
        sep = "-" * max(60, len(detail) + 4)

        with open(SPOOF_LOG_FILE, "a", encoding="utf-8") as tf:
            tf.write(f"{header}\n")
            tf.write(f"{detail}\n")
            tf.write(f"{sep}\n")
    except Exception as e:
        log_message(f"[LOG ERROR] Failed to write styled log: {e}")

# ================= EMAIL ALERT =================
def send_email_alert(ip, real_mac, fake_mac):
    try:
        if not (SMTP_SERVER and SMTP_PORT and SENDER_EMAIL and SENDER_PASSWORD and ADMIN_EMAIL):
            log_message("[EMAIL] SMTP credentials not configured in environment variables.")
            return

        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        body = f"""
ARP Spoofing Detected!

Time: {time_str}

Attacker IP   : {ip}
Original MAC  : {real_mac}
Spoofed MAC   : {fake_mac}

Immediate action required.
"""
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ADMIN_EMAIL
        msg["Subject"] = "⚠️ ARP Spoofing Detected"
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()

        log_message("[EMAIL] Alert sent to admin")

    except Exception as e:
        log_message(f"[EMAIL ERROR] {e}")

# ================= BASELINE =================
def snapshot_baseline():
    baseline_arp.clear()
    try:
        output = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
        for line in output.splitlines():
            parts = line.split()
            # Windows arp -a lines containing IP and MAC typically
            if len(parts) >= 2 and "." in parts[0] and ("-" in parts[1] or ":" in parts[1]):
                ip = parts[0]
                mac = parts[1].replace("-", ":").lower()
                baseline_arp[ip] = mac
        log_message("[INFO] ARP Baseline Loaded")
        log_message(f"[INFO] Baseline entries: {len(baseline_arp)}")
    except Exception as e:
        log_message(f"[BASELINE ERROR] {e}")

# ================= PACKET HANDLER =================
def process_packet(pkt):
    if not monitoring:
        return
    try:
        if pkt.haslayer(ARP):
            op = pkt[ARP].op
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.lower()
            log_message(f"[PKT] ARP op={op} ip={ip} mac={mac}")
            # ARP reply (2) indicates mapping announcement
            if op == 2:
                if ip in baseline_arp and baseline_arp[ip] != mac:
                    now = datetime.now()
                    log_message("⚠️ ARP SPOOFING DETECTED")
                    log_message(f"IP: {ip}")
                    log_message(f"Expected MAC: {baseline_arp[ip]}")
                    log_message(f"Spoofed MAC : {mac}")
                    log_message("-" * 40)
                    save_log([
                        now.date().isoformat(), now.time().isoformat(), ip,
                        baseline_arp[ip], mac,
                        "ARP Spoofing Detected"
                    ])
                    send_email_alert(ip, baseline_arp[ip], mac)
    except Exception as e:
        log_message(f"[PKT ERROR] {e}")

# ================= INTERFACE SELECTION =================
def choose_interface():
    try:
        # Prefer friendly Windows listing with IPs if available
        if get_windows_if_list:
            try:
                win_list = get_windows_if_list()
                for info in win_list:
                    ip = info.get("ip")
                    name = info.get("name")
                    if ip and ip != "127.0.0.1":
                        conf.iface = name
                        log_message(f"[IFACE] Selected {name} (IP: {ip})")
                        return
            except Exception:
                pass
    except NameError:
        pass

    # Fallback: pick the first non-loopback NPF device
    for iface in get_if_list():
        if "Loopback" in iface or "loopback" in iface or "NPF_Loopback" in iface:
            continue
        conf.iface = iface
        log_message(f"[IFACE] Fallback selected {iface}")
        return

# ================= SNIFF THREAD =================
def sniff_packets():
    try:
        if not sniff:
            log_message("[SNIFF] scapy not available — packet sniffing disabled")
            return
        log_message("[SNIFF] Starting packet sniffing")
        log_message(f"[SNIFF] Default iface: {conf.iface}")
        log_message(f"[SNIFF] Available ifaces: {get_if_list()}")
        sniff(prn=process_packet, store=0, iface=conf.iface)
    except Exception as e:
        log_message(f"[SNIFF ERROR] {e}")

# ================= UI BUTTONS =================
def start_monitoring():
    global monitoring
    if not monitoring:
        monitoring = True
        status_label.config(text="Status: Monitoring", fg="#2ecc71")
        log_message("[INFO] Monitoring Started")
        snapshot_baseline()
        choose_interface()
        # start packet sniffing only if scapy is available
        if sniff:
            threading.Thread(target=sniff_packets, daemon=True).start()
        else:
            log_message("[INFO] Packet sniffing disabled; relying on ARP-table scanning")
        start_arp_monitor_thread()

def stop_monitoring():
    global monitoring, ALERTED_MACS
    monitoring = False
    # clear per-session alerted MACs so future monitoring sessions can re-alert if needed
    ALERTED_MACS.clear()
    status_label.config(text="Status: Stopped", fg="#ff3b30")
    log_message("[INFO] Monitoring Stopped")

def view_logs():
    """
    Display logs as 4 columns: Timestamp | Alert IP | Original MAC | Spoofed MAC.
    Sources:
      - LOG_FILE (preferred): expects rows [Date, Time, IP, Expected MAC, Spoofed MAC, ...]
      - ARP_DUP_LOG fallback: rows [timestamp, suspicious_mac, ips] where ips are ";" separated.
    Expands ARP_DUP_LOG to one row per IP and uses baseline_arp to fill Original MAC when possible.
    """
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        script_dir = os.getcwd()

    path_log = os.path.join(script_dir, LOG_FILE)
    path_dup = os.path.join(script_dir, ARP_DUP_LOG)

    if os.path.exists(path_log):
        source = path_log
        mode = "log_file"
    elif os.path.exists(path_dup):
        source = path_dup
        mode = "dup_file"
    else:
        messagebox.showinfo("Logs", f"No logs found ({LOG_FILE} or {ARP_DUP_LOG})")
        return

    try:
        with open(source, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            rows = list(reader)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read log file:\n{e}")
        return

    if not rows:
        messagebox.showinfo("Logs", "Log file is empty")
        return

    # prepare unified rows: [(timestamp, ip, original_mac, spoofed_mac), ...]
    unified = []
    if mode == "log_file":
        # try detect header row; if present skip it
        header = rows[0]
        start = 1 if any(re.search(r"[A-Za-z]", h or "") for h in header) else 0
        for r in rows[start:]:
            # defensive extraction
            date = r[0] if len(r) > 0 else ""
            t = r[1] if len(r) > 1 else ""
            ip = r[2] if len(r) > 2 else ""
            orig = r[3] if len(r) > 3 else "unknown"
            spoof = r[4] if len(r) > 4 else ""
            ts = f"{date} {t}".strip() if date or t else (r[0] if r else "")
            unified.append((ts, ip, orig or "unknown", spoof or "unknown"))
    else:
        # ARP_DUP_LOG: expect [timestamp, suspicious_mac, ips]
        header = rows[0]
        start = 1 if any(re.search(r"[A-Za-z]", h or "") for h in header) else 0
        for r in rows[start:]:
            ts = r[0] if len(r) > 0 else ""
            suspicious_mac = r[1] if len(r) > 1 else ""
            ips_field = r[2] if len(r) > 2 else ""
            ips = [p.strip() for p in ips_field.split(";") if p.strip()]
            for ip in ips:
                # try baseline_arp lookup for original mac if available
                orig = baseline_arp.get(ip, "unknown") if isinstance(baseline_arp, dict) else "unknown"
                unified.append((ts, ip, orig or "unknown", suspicious_mac or "unknown"))

    # Build UI
    win = tk.Toplevel(root)
    win.title("ARP Logs - Viewer")
    win.geometry("920x520")
    win.configure(bg="#000000")

    style = ttk.Style(win)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("arp.Treeview",
                    background="#000000",
                    foreground="#39ff14",
                    fieldbackground="#000000",
                    font=("Consolas", 11))
    style.configure("arp.Treeview.Heading",
                    background="#111111",
                    foreground="#ffffff",
                    font=("Segoe UI", 10, "bold"))

    container = tk.Frame(win, bg="#000000")
    container.pack(fill="both", expand=True, padx=6, pady=6)

    cols = ("timestamp", "alert_ip", "original_mac", "spoofed_mac")
    tree = ttk.Treeview(container, columns=cols, show="headings", style="arp.Treeview")
    vsb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

    # headings
    tree.heading("timestamp", text="Timestamp")
    tree.heading("alert_ip", text="Alert IP")
    tree.heading("original_mac", text="Original MAC")
    tree.heading("spoofed_mac", text="Spoofed MAC")

    tree.column("timestamp", width=260, anchor="w")
    tree.column("alert_ip", width=180, anchor="center")
    tree.column("original_mac", width=220, anchor="center")
    tree.column("spoofed_mac", width=220, anchor="center")

    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")

    container.grid_rowconfigure(0, weight=1)
    container.grid_columnconfigure(0, weight=1)

    # tag for red mismatches
    tree.tag_configure("mismatch", foreground="#ff3b30", font=("Consolas", 11, "bold"))
    tree.tag_configure("normal", foreground="#39ff14")

    def is_mismatch(orig: str, spoof: str) -> bool:
        if not orig or orig.lower() in ("unknown", "none"):
            return False
        return orig.lower().replace("-", ":").replace(".", ":") != spoof.lower().replace("-", ":").replace(".", ":")

    for ts, ip, orig, spoof in unified:
        tag = "mismatch" if is_mismatch(orig, spoof) else "normal"
        tree.insert("", "end", values=(ts, ip, orig, spoof), tags=(tag,))

    # bottom close
    btn_frame = tk.Frame(win, bg="#000000")
    btn_frame.pack(fill="x", padx=8, pady=(6,8))
    tk.Button(btn_frame, text="Close", command=win.destroy,
              bg="#333333", fg="white", relief="flat").pack(side="right")

# ================= VIDEO BACKGROUND =================
cap = None

def play_video():
    global cap
    if cap is None:
        try:
            cap = cv2.VideoCapture(VIDEO_PATH)
        except Exception as e:
            cap = None
            log_message(f"[VIDEO ERROR] {e}")
            return

    if not cap or not cap.isOpened():
        log_message(f"[VIDEO] Could not open {VIDEO_PATH} — background video disabled")
        cap = None
        return

    ret, frame = cap.read()
    if not ret:
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
        ret, frame = cap.read()
    if not ret:
        return

    # scale to window size
    h_win, w_win = 700, 1000
    frame = cv2.resize(frame, (w_win, h_win))
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    img = ImageTk.PhotoImage(Image.fromarray(frame))
    video_label.img = img
    video_label.config(image=img)
    root.after(30, play_video)

# New: Project info HTML export / open
def open_project_file():
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "company_logo.png")
        logo_base64 = ""
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as img_file:
                logo_base64 = base64.b64encode(img_file.read()).decode("utf-8")

        # build img tag outside the f-string to avoid backslash/escape issues
        img_tag = f'<img src="data:image/png;base64,{logo_base64}" alt="Company Logo" class="logo">' if logo_base64 else ""

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Project Information</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, Helvetica, sans-serif; background: #fff; margin: 0; padding: 20px; }}
        .logo {{ width: 90px; float: right; margin: 10px 18px 0 0; }}
        .container {{ max-width: 900px; margin: auto; }}
        h1 {{ color: #b30000; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
<div class="container">
    {img_tag}
    <h1>Project Information</h1>
    <p>This project was developed by 
        <b>Mr. Adimulam Mourya</b>, 
        <b>Ms. Syeda Afeefa Anjum</b>, 
        <b>Mr. Patan Akram Khan</b>, and 
        <b>Mr. Savarapu Vivek</b> 
        as part of a <b>Cyber Security Internship</b>.
    </p>
    <table>
        <tr><th>Project Details</th><th>Value</th></tr>
        <tr><td>Project Name</td><td>USB Port Security Framework with OTP Authentication and Intruder Detection</td></tr>
        <tr><td>Project Description</td><td>A Python-based USB port security system that integrates OTP-based authentication, user management, intruder detection using webcam, and USB enable/disable control through Windows registry, ensuring strong physical and logical protection of devices.</td></tr>
        <tr><td>Project Start Date</td><td>23-JUNE-2025</td></tr>
        <tr><td>Project End Date</td><td>06-SEP-2025</td></tr>
        <tr><td>Project Status</td><td>Completed</td></tr>
    </table>

    <h2>Developer Details</h2>
    <table>
        <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
        <tr><td>Mr. Adimulam Mourya</td><td>ST#IS#8128</td><td>mouryamourya289@gmail.com</td></tr>
        <tr><td>Ms. Syeda Afeefa Anjum</td><td>ST#IS#8127</td><td>22691a3747@mits.ac.in</td></tr>
        <tr><td>Mr. Patan Akram Khan</td><td>ST#IS#8142</td><td>22691a3701@mits.ac.in</td></tr>
        <tr><td>Mr. Savarapu Vivek</td><td>ST#IS#8143</td><td>22691a3757@mits.ac.in</td></tr>
    </table>

    <h2>Company Details</h2>
    <table>
        <tr><th>Company</th><th>Value</th></tr>
        <tr><td>Name</td><td>Supraja Technologies</td></tr>
        <tr><td>Email</td><td>contact@suprajatechnologies.com</td></tr>
    </table>
</div>
</body>
</html>"""

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html", encoding="utf-8") as tmp:
            tmp.write(html_content)
            temp_path = tmp.name

        webbrowser.open_new_tab(f"file:///{temp_path.replace(os.sep, '/')}")

    except Exception as e:
        messagebox.showerror("Error", f"Cannot open Project Information:\n{e}")

# ================= ARP MONITORING =================
def scan_arp_table() -> Dict[str, str]:
    """
    Scan the OS ARP table and return a mapping of ip -> mac (lowercase, : separated).
    Works on Windows and Linux (tries 'ip neigh' then 'arp -a' on Linux).
    Defensive: returns empty dict on error.
    """
    try:
        system = os.name  # 'nt' for Windows, 'posix' for Linux
        output = ""
        if system == "nt":
            # Windows
            output = subprocess.check_output(["arp", "-a"], shell=False, stderr=subprocess.DEVNULL).decode(errors="ignore")
            # parse lines like:  192.168.1.1           00-11-22-33-44-55     dynamic
            ip_mac = {}
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and "." in parts[0] and ("-" in parts[1] or ":" in parts[1]):
                    ip = parts[0].strip()
                    mac = parts[1].replace("-", ":").lower()
                    ip_mac[ip] = mac
            return ip_mac

        else:
            # POSIX (Linux/Unix) - prefer ip neigh, fallback to arp -a
            try:
                output = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode(errors="ignore")
                # parse lines like: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                ip_mac = {}
                for line in output.splitlines():
                    m = re.search(r"^(\d+\.\d+\.\d+\.\d+).*(?:lladdr|lladdr:)\s*([0-9a-fA-F:]{17}|[0-9a-fA-F:]{14})", line)
                    if not m:
                        # simpler fallback: find ip and mac tokens
                        parts = line.split()
                        if parts and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                            ip = parts[0]
                            mac = None
                            for p in parts:
                                if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", p):
                                    mac = p.lower()
                                    break
                            if mac:
                                ip_mac[ip] = mac
                    else:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        ip_mac[ip] = mac
                if ip_mac:
                    return ip_mac
            except Exception:
                pass

            # fallback arp -a on POSIX
            try:
                output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors="ignore")
                ip_mac = {}
                for line in output.splitlines():
                    # examples differ by distro; try to find ip and mac with regex
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).replace("-", ":").lower()
                        ip_mac[ip] = mac
                return ip_mac
            except Exception:
                return {}

    except Exception:
        return {}


def _sanitize_arp_map(ip_mac_map: Dict[str, str]) -> Dict[str, str]:
    """
    Filter out noisy ARP entries:
    - ignore broadcast / all-FF and all-zero MACs
    - ignore multicast MAC prefixes (01:00:5e...) and link-local IPs (169.254.*)
    - ignore 255.255.255.255 and empty entries
    Returns cleaned ip->mac map with normalized mac (lowercase, colon).
    """
    IGNORE_IP_PREFIXES = ("169.254.",)  # add more if needed
    clean: Dict[str, str] = {}

    for ip, mac in (ip_mac_map or {}).items():
        try:
            if not ip or not mac:
                continue
            ip = ip.strip()
            # ignore broadcast/full broadcast address
            if ip == "255.255.255.255":
                continue
            if any(ip.startswith(p) for p in IGNORE_IP_PREFIXES):
                continue

            # normalize mac to lowercase colon separated
            mac_norm = mac.lower().replace("-", ":").replace(".", ":")
            # remove any accidental whitespace
            mac_norm = re.sub(r"\s+", "", mac_norm)

            # normalized compact form for content checks (12 hex chars)
            compact = re.sub(r"[^0-9a-f]", "", mac_norm)

            # ignore obvious noisy MACs
            if not compact or len(compact) < 12:
                continue
            # all-FF or all-00
            if compact == "ffffffffffff" or compact == "000000000000":
                continue
            # multicast prefix 01:00:5e => IPv4 multicast
            if compact.startswith("01005e"):
                continue

            # now reformat into standard colon form (xx:xx:...)
            mac_std = ":".join(compact[i:i+2] for i in range(0, 12, 2))
            clean[ip] = mac_std
        except Exception:
            continue

    return clean


def detect_duplicate_mac(ip_mac_map: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Invert ip->mac map to mac -> [ips] and return entries where a MAC maps
    to exactly 2 distinct valid unicast IPs (user requirement).
    Uses _sanitize_arp_map to remove broadcast/multicast/noise.
    """
    ip_mac_map = _sanitize_arp_map(ip_mac_map)
    mac_map: Dict[str, List[str]] = {}
    for ip, mac in ip_mac_map.items():
        if not mac:
            continue
        mac_map.setdefault(mac, []).append(ip)

    # keep only macs mapped to exactly 2 distinct ips
    dup = {}
    for mac, ips in mac_map.items():
        unique_ips = sorted(set(ips))
        if len(unique_ips) == 2:
            dup[mac] = unique_ips
    return dup


def _get_local_ip_and_mac() -> Tuple[str, str]:
    """
    Determine local primary IP and MAC.
    - IP: UDP socket trick (no packets sent).
    - MAC: prefer ARP-table lookup for that IP (scan_arp_table()),
      fallback to scapy get_if_hwaddr(conf.iface) if available,
      finally fallback to uuid.getnode().
    Returns (ip, mac) with mac in lowercase colon format or 'unknown'.
    """
    local_ip = "unknown"
    local_mac = "unknown"

    # determine local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't send packets but forces OS to pick an outgoing IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        pass

    # try to get MAC from ARP table first (most reliable if present)
    try:
        ip_mac = scan_arp_table()
        if local_ip and local_ip in ip_mac and ip_mac[local_ip]:
            local_mac = ip_mac[local_ip].lower()
            return local_ip, local_mac
    except Exception:
        pass

    # try scapy helper if configured
    try:
        if conf and getattr(conf, "iface", None):
            try:
                from scapy.all import get_if_hwaddr  # pyright: ignore[reportMissingImports]
                local_mac = get_if_hwaddr(conf.iface).lower()
                return local_ip, local_mac
            except Exception:
                pass
    except Exception:
        pass

    # final fallback: uuid.getnode()
    try:
        node = uuid.getnode()
        if (node >> 40) & 0xff:  # simple sanity check
            mac = ":".join(f"{(node >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
            local_mac = mac.lower()
    except Exception:
        pass

    return local_ip, local_mac


def _get_arp_section_for_local_ip(local_ip: str) -> str:
    """
    Run 'arp -a' (Windows) or 'arp -a'/'ip neigh' (POSIX) and return the section
    that corresponds to the local interface (the 'Interface: ...' block on Windows)
    or the full arp listing on POSIX. Returns a safe string (or 'Unavailable').
    """
    try:
        system = os.name  # 'nt' for Windows
        if system == "nt":
            raw = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors="ignore")
            lines = raw.splitlines()
            section_lines = []
            collecting = False
            for ln in lines:
                # Windows uses lines like "Interface: 10.52.102.97 --- 0x7"
                if ln.strip().lower().startswith("interface:"):
                    # start/stop collecting when we see the interface header
                    if local_ip and local_ip in ln:
                        collecting = True
                        section_lines = [ln.rstrip()]
                        continue
                    else:
                        if collecting:
                            # we've reached next interface block -> stop
                            break
                        collecting = False
                elif collecting:
                    section_lines.append(ln.rstrip())
            if section_lines:
                return "\n".join(section_lines)
            # fallback: return entire arp -a if no specific section found
            return raw.strip() or "ARP output empty"
        else:
            # POSIX: try ip neigh first for cleaner output
            try:
                raw = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode(errors="ignore")
                return raw.strip() or "ip neigh output empty"
            except Exception:
                raw = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors="ignore")
                return raw.strip() or "arp -a output empty"
    except Exception:
        return "ARP table unavailable"


def send_arp_table_alert(suspicious_mac: str, ips: List[str]):
    """
    Compose and send an email alert matching the requested format.
    - Uses ARP table to populate per-IP MACs and to extract relevant arp -a rows.
    - Sends only once per suspicious_mac per monitoring session (ALERTED_MACS).
    """
    global ALERTED_MACS
    try:
        # prevent duplicates in same monitoring session
        if suspicious_mac in ALERTED_MACS:
            log_message(f"[EMAIL] Already alerted for {suspicious_mac}, skipping")
            return

        if not (SMTP_SERVER and SMTP_PORT and SENDER_EMAIL and SENDER_PASSWORD and ADMIN_EMAIL):
            log_message("[EMAIL] SMTP credentials not configured in environment variables.")
            return

        # latest ARP map and local info
        try:
            arp_map = scan_arp_table()
        except Exception:
            arp_map = {}

        local_ip, local_mac = _get_local_ip_and_mac()
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Attacker: choose representative IP (first in ips) or "unknown"
        attacker_ip = ips[0] if ips else "unknown"

        # Build associated IPs block showing current & baseline MACs
        ips_lines = []
        for ip in ips:
            cur_mac = arp_map.get(ip, "unknown")
            base_mac = baseline_arp.get(ip, "unknown")
            cur_mac = cur_mac.lower() if cur_mac and cur_mac != "unknown" else "unknown"
            base_mac = base_mac.lower() if base_mac and base_mac != "unknown" else "unknown"
            ips_lines.append(f" - {ip}\n     Current MAC    : {cur_mac}\n     Baseline MAC   : {base_mac}")
        ips_text = "\n\n".join(ips_lines) if ips_lines else " - none"

        # get relevant arp -a section and rows matching the suspicious MAC
        arp_section = _get_arp_section_for_local_ip(local_ip)
        arp_rows_for_email = _format_arp_rows_for_mac(arp_section, suspicious_mac)

        # Try to infer an "original MAC" for impersonated device:
        # if any listed IP has a baseline MAC different from suspicious_mac, use first such value.
        original_mac = "unknown"
        for ip in ips:
            b = baseline_arp.get(ip)
            if b and b.lower() != suspicious_mac.lower():
                original_mac = b.lower()
                break

        # Compose email body matching requested layout
        body = f"""An ARP spoofing attack has been detected on your network.

📅 Time Detected: {time_str}

🚨 Attacker Information
------------------------
IP Address           : {attacker_ip}
MAC Address          : {suspicious_mac}
Spoofed IP Address   : {attacker_ip}

🎯 Target (Your Device)
------------------------
IP Address           : {local_ip}
MAC Address           : {local_mac}

👤 Impersonated Device
------------------------
Associated IPs:
{ips_text}

Original MAC Address : {original_mac}
Spoofed MAC Address  : {suspicious_mac}


ARP table (selected entries):
{arp_rows_for_email}

Please take immediate action to investigate this intrusion.
"""

        # send
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ADMIN_EMAIL
        msg["Subject"] = "⚠️ ARP Spoofing Detected on Your Network"
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()

        ALERTED_MACS.add(suspicious_mac)
        log_message("[EMAIL] ARP-table alert sent to admin")
    except Exception as e:
        log_message(f"[EMAIL ERROR] {e}")


def _arp_monitor_loop():
    """
    Background loop: every 10 seconds scan ARP table and detect duplicate MACs.
    Runs only while global 'monitoring' is True.
    Stops cleanly when 'monitoring' becomes False.
    """
    global arp_monitor_thread
    log_message("[ARP MON] ARP table monitor started")
    try:
        while monitoring:
            try:
                ip_mac = scan_arp_table()
                if not ip_mac:
                    log_message("[ARP MON] No ARP entries found or scan failed")
                else:
                    dup = detect_duplicate_mac(ip_mac)
                    if dup:
                        for mac, ips in dup.items():
                            # Avoid flooding: save/send once per detection iteration
                            msg = f"[ARP SPOOF] Duplicate MAC {mac} mapped to IPs: {', '.join(ips)}"
                            log_message(msg)
                            save_arp_incident(mac, ips)
                            send_arp_table_alert(mac, ips)
                    else:
                        # optional quiet log for debug
                        log_message("[ARP MON] No duplicate MACs detected")
            except Exception as e:
                log_message(f"[ARP MON ERROR] {e}")

            # sleep up to 10s but break early if monitoring is turned off
            for _ in range(10):
                if not monitoring:
                    break
                time.sleep(1)
    finally:
        log_message("[ARP MON] ARP table monitor stopped")
        arp_monitor_thread = None


def start_arp_monitor_thread():
    """
    Start the ARP monitor thread if not already started.
    Call this when monitoring is started (e.g. in start_monitoring()).
    """
    global arp_monitor_thread
    if arp_monitor_thread and arp_monitor_thread.is_alive():
        return
    arp_monitor_thread = threading.Thread(target=_arp_monitor_loop, daemon=True)
    arp_monitor_thread.start()
def save_arp_incident(suspicious_mac: str, ips: List[str]) -> None:
    """
    Append a duplicate-MAC incident to ARP_DUP_LOG.
    Format: timestamp, suspicious_mac, semicolon-separated IP list.
    Defensive: logs errors instead of raising.
    Must be defined before the ARP monitor thread runs.
    """
    try:
        file_exists = os.path.exists(ARP_DUP_LOG)
        with open(ARP_DUP_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "suspicious_mac", "ips"])
            writer.writerow([datetime.now().isoformat(), suspicious_mac, ";".join(ips)])
        log_message(f"[ARP LOG] Saved incident for {suspicious_mac}")
    except Exception as e:
        log_message(f"[ARP LOG ERROR] {e}")

# ================= GUI =================
root = tk.Tk()
root.title("ARP Spoofing Detector")
root.geometry("1000x700")
root.resizable(False, False)

# ensure main window is fully opaque
root.attributes("-alpha", 1.0)

# Background label (video) remains; keep it fullscreen
video_label = tk.Label(root, bd=0)
video_label.place(x=0, y=0, relwidth=1, relheight=1)

# Top ribbon frame for Project Info (center top)
top_frame = tk.Frame(root, bd=0)
top_frame.place(relx=0.5, y=12, anchor="n")

project_btn = tk.Button(top_frame, text="Project Info",
                        bg="#00bcd4", fg="black",
                        font=("Segoe UI", 11, "bold"),
                        padx=14, pady=6,
                        relief="flat", bd=0,
                        activebackground="#00a6b0", cursor="hand2",
                        command=open_project_file)
project_btn.pack()

# Create semi-transparent overlay images and use them as the background for the control panel
from PIL import Image, ImageTk  # ...existing import already present above

# sizes (same as original panel/log sizes)
PANEL_W, PANEL_H = 460, 240
LOG_W, LOG_H = 920, 240 

# helper to create a semi-transparent overlay image
def _create_overlay_image(w: int, h: int, rgba=(0, 0, 0, 160)):
    # rgba: last value is alpha (0..255). 160 ~ ~62% opacity (you can adjust)
    img = Image.new("RGBA", (w, h), rgba)
    return ImageTk.PhotoImage(img)

# create overlay images once (keeps references on root to avoid GC)
# make overlays fully opaque (alpha=255) so video does not show through
panel_overlay_img = _create_overlay_image(PANEL_W, PANEL_H, rgba=(0, 0, 0, 255))
log_overlay_img = _create_overlay_image(LOG_W, LOG_H, rgba=(0, 0, 0, 255))

# place overlays over the video_label (they sit above the video and act as backgrounds)
panel_bg_label = tk.Label(root, image=panel_overlay_img, bd=0)
panel_bg_label.image = panel_overlay_img
# same placement as previous panel/log: centered near top
panel_bg_label.place(relx=0.5, rely=0.08, anchor="n", width=PANEL_W, height=PANEL_H)

# Now create the actual control panel as children of the overlay label so the overlay acts as the background
# Use a dark solid panel bg, thicker border and larger fonts to improve visibility
panel = tk.Frame(panel_bg_label, bg="#050505", bd=4, relief="ridge")
panel.place(relx=0.5, rely=0.03, anchor="n", width=PANEL_W - 10, height=PANEL_H - 10)

# Title (high contrast, larger)
tk.Label(panel, text="ARP Spoofing Detector",
         fg="#ffffff",
         bg="#050505",
         font=("Arial", 24, "bold")).pack(pady=(12, 6))

# Status label (bolder, larger)
status_label = tk.Label(panel, text="Status: Stopped",
                        fg="#ff3b30", bg="#050505",
                        font=("Segoe UI", 14, "bold"))
status_label.pack()

# Buttons grid (place directly into panel) — larger buttons for visibility
btn_frame = tk.Frame(panel, bg="#050505", bd=0)
btn_frame.pack(pady=12)

tk.Button(btn_frame, text="Start Monitoring", bg="#28a745", fg="white",
          font=("Segoe UI", 12, "bold"), width=18,
          relief="raised", bd=2, activebackground="#27ae60",
          command=start_monitoring).grid(row=0, column=0, padx=8, pady=6)

tk.Button(btn_frame, text="Stop Monitoring", bg="#e74c3c", fg="white",
          font=("Segoe UI", 12, "bold"), width=18,
          relief="raised", bd=2, activebackground="#c0392b",
          command=stop_monitoring).grid(row=0, column=1, padx=8, pady=6)

tk.Button(btn_frame, text="View Logs", bg="#3498db", fg="white",
          font=("Segoe UI", 12, "bold"), width=38,
          relief="raised", bd=2, activebackground="#2980b9",
          command=view_logs).grid(row=1, column=0, columnspan=2, pady=8)

# small spacer to align the rest of the controls nicely inside overlay
tk.Frame(panel, height=6, bg="#050505").pack()

# create the Live ARP Monitor Log overlay and place it near the bottom
# add a bright neon-green frame highlight and thicker border for high contrast
log_bg_label = tk.Label(root, image=log_overlay_img, bd=0, relief="flat")
log_bg_label.image = log_overlay_img
log_bg_label.place(relx=0.5, rely=0.60, anchor="n", width=LOG_W, height=LOG_H)
# neon border using a separate frame for compatibility
log_border = tk.Frame(root, bg="#00ff41", bd=3)
log_border.place(relx=0.5, rely=0.60, anchor="n", width=LOG_W + 8, height=LOG_H + 8)
# put the log overlay on top of the neon border
log_bg_label.lift(log_border)

# Header text on top of log overlay (bright neon-green box)
header_lbl = tk.Label(log_bg_label, text=" Live ARP Monitor Log ", fg="#000000",
                      bg="#00ff41", font=("Consolas", 12, "bold"))
header_lbl.place(x=8, y=6)

# The live log Text is placed onto the overlay so the overlay acts as background
log_area_frame = tk.Frame(log_bg_label, bg="#000000", bd=0)
log_area_frame.place(x=8, y=36, width=LOG_W - 16, height=LOG_H - 44)

log_scroll_y = tk.Scrollbar(log_area_frame, orient="vertical")
log_scroll_x = tk.Scrollbar(log_area_frame, orient="horizontal")

# Text widget: bold, larger font, brighter neon-green text for readability
log_box = tk.Text(log_area_frame, height=8,
                  bg="#000000", fg="#00ff41",
                  insertbackground="#00ff41",
                  font=("Consolas", 12, "bold"), bd=0,
                  yscrollcommand=log_scroll_y.set,
                  xscrollcommand=log_scroll_x.set, wrap="none", relief="sunken")
log_box.pack(side="left", fill="both", expand=True, padx=(4,0), pady=(2,2))

# configure tags for colored output
log_box.tag_configure("suspicious", foreground="#ff3b30", font=("Consolas", 12, "bold"))
log_box.tag_configure("info", foreground="#00ff41", font=("Consolas", 12))

log_scroll_y.config(command=log_box.yview)
log_scroll_y.pack(side="right", fill="y")
log_scroll_x.config(command=log_box.xview)
log_scroll_x.pack(side="bottom", fill="x")

# Ensure log_message writes to this log_box (log_message already checks globals)

# New: format ARP rows for specific IPs
def _format_arp_rows_for_ips(arp_section: str, ips: List[str]) -> str:
    """
    From a full 'arp -a' section, return only the lines that contain any of the
    given ips. Keeps original spacing/punctuation (Windows style uses dashes).
    """
    if not arp_section:
        return "  (ARP output unavailable)"
    lines = arp_section.splitlines()
    matched = []
    for ln in lines:
        for ip in ips:
            if ip in ln:
                matched.append(ln.rstrip())
                break
    if not matched:
        return "  (no matching ARP entries found)"
    # indent each line for email readability
    return "\n".join("  " + l for l in matched)

def _format_arp_rows_for_mac(arp_section: str, mac: str) -> str:
    """
    From a full 'arp -a' section, return only the lines that contain the given MAC.
    Matches both dash-separated (08-00-27-..) and colon-separated (08:00:27:..) formats.
    Returns nicely indented lines for inclusion in the email body.
    """
    if not arp_section:
        return "  (ARP output unavailable)"
    if not mac:
        return "  (no mac provided)"

    normalized_dash = mac.lower().replace(":", "-")
    normalized_colon = mac.lower().replace("-", ":")

    matched = []
    for ln in arp_section.splitlines():
        low = ln.lower()
        if normalized_dash in low or normalized_colon in low:
            matched.append(ln.rstrip())

    if not matched:
        return "  (no matching ARP entries found)"
    return "\n".join("  " + l for l in matched)

# start UI and video loop
try:
    # start background video if available (play_video is safe if VIDEO_PATH is missing)
    play_video()
except Exception as e:
    log_message(f"[START ERROR] play_video() failed: {e}")

# start Tk mainloop (this blocks and shows the window)
root.mainloop()


