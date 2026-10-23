import os
import re
import bz2
import base64
import html as htmllib
import lzma
import json
import zlib
import time
import uuid
import queue
import struct
import shutil
import bisect
import tarfile
import hashlib
import itertools
import threading
import requests
import zstandard as zstd
from datetime import datetime
from urllib.parse import urlparse, unquote, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from remotezip import RemoteZip
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import HfApi, hf_hub_url, hf_hub_download

try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

app = FastAPI(title="MY API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HF_TOKEN = os.getenv("HF_TOKEN", "").strip()
DATASET_REPO = os.getenv("DATASET_REPO", "Yash10101/xiaomi-firmware-cache").strip()
hf_api = HfApi(token=HF_TOKEN if HF_TOKEN else None)

JOBS = {}
MB = 1024 * 1024
NO_STORE = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}

# ---------------- POST-DOWNLOAD IP ROTATION ENGINE ---------------- #
TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
PROXY_LIST = [p.strip() for p in os.getenv("PROXY_POOL", "").split(",") if p.strip()]
PROXY_CYCLE = itertools.cycle(PROXY_LIST) if PROXY_LIST else None
ALWAYS_ROTATE_PIXELDRAIN = os.getenv("ALWAYS_ROTATE_PIXELDRAIN", "0").strip() == "1"
PIXELDRAIN_DIRECT_LIMIT = int(float(os.getenv("PIXELDRAIN_LIMIT_GB", "5.0")) * 1024 * MB)

IP_ROTATOR_LOCK = threading.Lock()
IP_STATE = {
    "direct_pixeldrain_bytes": 0,
    "force_rotated_ip": ALWAYS_ROTATE_PIXELDRAIN,
    "active_proxy": PROXY_LIST[0] if PROXY_LIST else None,
    "rotations_count": 0,
    "last_exit_ip": "Direct Server IP",
}

def is_throttled_host(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return any(h in host for h in ("pixeldrain.com", "pixeldrain.net", "pixeldrain.dev"))

def tor_socks_alive() -> bool:
    try:
        s = requests.Session()
        s.proxies = {"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}
        r = s.get("https://api.ipify.org?format=json", timeout=8)
        if r.status_code == 200:
            IP_STATE["last_exit_ip"] = r.json().get("ip", "Tor Exit Node")
            return True
    except Exception:
        pass
    return False

def rotate_ip_after_job(job_id: str = "", raw_url: str = "", throttled_triggered: bool = False):
    """
    Strictly called ONLY after a download finishes, errors, or is cancelled.
    Never called during an active stream.
    """
    with IP_ROTATOR_LOCK:
        if throttled_triggered:
            IP_STATE["force_rotated_ip"] = True

        # 1. If user configured a custom PROXY_POOL, cycle to the next proxy for the next job
        if PROXY_CYCLE is not None:
            next_p = next(PROXY_CYCLE)
            IP_STATE["active_proxy"] = next_p
            IP_STATE["rotations_count"] += 1
            if job_id and job_id in JOBS:
                job_log(job_id, "HTTP", f"[IP-Rotator] Download stopped → Switched to next proxy in pool (#{IP_STATE['rotations_count']}).")
            return

        # 2. Signal local Tor daemon (NEWNYM) to build a fresh circuit with a new Exit IP for the next download
        if STEM_AVAILABLE:
            try:
                with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
                    controller.authenticate()
                    if controller.is_newnym_available():
                        controller.signal(Signal.NEWNYM)
                    IP_STATE["rotations_count"] += 1
                if job_id and job_id in JOBS:
                    job_log(job_id, "HTTP", f"[IP-Rotator] Download stopped → Rotated Tor circuit to a fresh Exit IP (#{IP_STATE['rotations_count']}) for the next job.")
            except Exception as e:
                if job_id and job_id in JOBS:
                    job_log(job_id, "INFO", f"[IP-Rotator] Tor circuit rotation note: {e}")

# Official KHwang9883/MobileModels Xiaomi English Database URL
KHWANG_XIAOMI_URL = "https://raw.githubusercontent.com/KHwang9883/MobileModels/master/brands/xiaomi_en.md"

# Fallback dictionary pre-populated; replaced/merged with full KHwang9883 database on startup
KHWANG_XIAOMI_MAP = {
    "air": "Redmi 13C 5G / Redmi 13R 5G / POCO M6 5G",
    "atmos": "Redmi 13C 5G",
    "gale": "Redmi 13C / POCO C65",
    "pond": "Redmi 14C / POCO C75",
    "lake": "Redmi 14C / POCO C75",
    "flame": "Redmi 14R 5G / Redmi 14C 5G / POCO M7 5G",
    "sky": "Redmi 12 5G / Redmi 12R / POCO M6 Pro 5G",
    "river": "Redmi 12 5G",
    "fire": "Redmi 12",
    "breeze": "Redmi 13 5G / POCO M6 Plus 5G",
    "moon": "Redmi 13 / POCO M6",
    "camellia": "Redmi Note 10 5G / Redmi Note 10T 5G / POCO M3 Pro 5G",
    "camellian": "Redmi Note 10 5G",
    "alioth": "Mi 11X / POCO F3 / Redmi K40",
    "aliothin": "Mi 11X",
    "marble": "POCO F5 / Redmi Note 12 Turbo",
    "garnet": "Redmi Note 13 Pro 5G / POCO X6 5G",
    "gold": "Redmi Note 13 5G / POCO X6 Neo",
    "peridot": "POCO F6 / Redmi Turbo 3",
    "duchamp": "POCO X6 Pro 5G / Redmi K70E",
    "beryllium": "POCO F1",
    "sweet": "Redmi Note 10 Pro / Redmi Note 10 Pro Max",
    "vince": "Redmi 5 Plus / Redmi Note 5",
    "courbet": "Mi 11 Lite",
    "lisa": "Xiaomi 11 Lite 5G NE",
    "haydn": "Mi 11i / Mi 11X Pro / Redmi K40 Pro",
    "vili": "Xiaomi 11T Pro",
    "fuxi": "Xiaomi 13",
    "nuwa": "Xiaomi 13 Pro",
    "ishtar": "Xiaomi 13 Ultra",
    "houji": "Xiaomi 14",
    "shennong": "Xiaomi 14 Pro",
    "aurora": "Xiaomi 14 Ultra",
    "dada": "Xiaomi 15",
    "haotian": "Xiaomi 15 Pro",
    "xuanyuan": "Xiaomi 15 Ultra",
}

class ExtractRequest(BaseModel):
    rom_url: str
    target: str
    device_name: str = ""
    rom_version: str = ""
    rom_category: str = "stock"
    rom_format: str = "fastboot"

def load_khwang_xiaomi_db():
    """
    Downloads and parses https://raw.githubusercontent.com/KHwang9883/MobileModels/master/brands/xiaomi_en.md
    Format example in file: **[ C3V ] Redmi 13C 5G / Redmi 13R 5G ( `air` ):**
    """
    try:
        r = requests.get(KHWANG_XIAOMI_URL, timeout=15)
        if r.status_code != 200:
            return
        parsed_map = {}
        for raw_line in r.text.splitlines():
            if "(" not in raw_line or ")" not in raw_line or "[" not in raw_line:
                continue
            clean = raw_line.replace("*", "").replace("`", "").strip()
            m = re.match(r"^\[[^\]]+\]\s*([^(]+?)\s*(\([^)]+\)(?:\s*\([^)]+\))*)\s*:?$", clean)
            if not m:
                continue
            model_names_raw = m.group(1).strip()
            codenames_part = m.group(2)
            codenames = re.findall(r"\(\s*([a-zA-Z0-9_-]+)\s*\)", codenames_part)
            names_list = [n.strip() for n in model_names_raw.split("/") if n.strip()]
            for code in codenames:
                c_low = code.lower()
                if c_low not in parsed_map:
                    parsed_map[c_low] = []
                for nm in names_list:
                    if nm not in parsed_map[c_low]:
                        parsed_map[c_low].append(nm)
        for k, v_list in parsed_map.items():
            KHWANG_XIAOMI_MAP[k] = " / ".join(v_list)
        print(f"[KHwang9883 DB] Loaded {len(KHWANG_XIAOMI_MAP)} Xiaomi/Redmi/POCO codenames from xiaomi_en.md!")
    except Exception as e:
        print(f"[KHwang9883 DB] Sync warning: {e}")

def ensure_dataset_exists():
    if not HF_TOKEN or not DATASET_REPO:
        return
    try:
        hf_api.create_repo(repo_id=DATASET_REPO, repo_type="dataset", private=False, exist_ok=True)
    except Exception as e:
        print(f"Dataset init note: {e}")

@app.on_event("startup")
def on_startup():
    threading.Thread(target=ensure_dataset_exists, daemon=True).start()
    threading.Thread(target=load_khwang_xiaomi_db, daemon=True).start()

def job_log(job_id: str, level: str, message: str):
    if not job_id or job_id not in JOBS:
        return
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    JOBS[job_id]["logs"].append({"ts": ts, "level": level, "message": message})

def job_add_code(job_id: str, stage_title: str, code_snippet: str):
    if not job_id or job_id not in JOBS:
        return
    block = f"# === [{stage_title}] ===\n{code_snippet}\n"
    if block not in JOBS[job_id]["cmd_history"]:
        JOBS[job_id]["cmd_history"].append(block)
        JOBS[job_id]["cmd"] = "\n".join(JOBS[job_id]["cmd_history"])

def stage(job, key, pct, label=None):
    """Sets one of the four progress bars: search | cont | ext | fin."""
    job[f"{key}_progress"] = max(0, min(100, int(pct)))
    if label is not None:
        job[f"{key}_label"] = label

def mark_direct(job):
    """The wanted file sits directly in the ROM, so there is no container file to download."""
    job["cont_skip"] = True
    job["cont_name"] = ""
    stage(job, "cont", 100, "Not needed — the file is directly inside the ROM")

# ---------------- KHWANG9883 CODENAME LOOKUP & CUSTOM ROM VERSION PARSER ---------------- #

def lookup_codename_in_khwang(raw_code: str):
    """Returns (official_device_name, matched_codename) or ("Unknown", "Unknown")."""
    if not raw_code:
        return "Unknown", "Unknown"
    c = raw_code.strip().lower()
    if c in KHWANG_XIAOMI_MAP:
        return KHWANG_XIAOMI_MAP[c], c

    stripped = re.sub(r"_(in|global|eea|ru|id|tw|tr|jp|kr|cn)_global$", "", c)
    stripped = re.sub(r"_(in|global|eea|ru|id|tw|tr|jp|kr|cn)$", "", stripped)
    if stripped in KHWANG_XIAOMI_MAP:
        return KHWANG_XIAOMI_MAP[stripped], stripped

    if stripped.endswith("in") and stripped[:-2] in KHWANG_XIAOMI_MAP:
        return KHWANG_XIAOMI_MAP[stripped[:-2]], stripped[:-2]

    return "Unknown", "Unknown"

def extract_custom_rom_version(text_blob: str, rom_filename: str):
    combined = f"{rom_filename} {text_blob}"
    patterns = [
        (r"\b(lineage-\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(LineageOS[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1).replace(" ", "-")),
        (r"\b(PixelOS[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(PixelExperience(?:_Plus)?[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(crDroidAndroid-\d+\.\d+-\d+-[a-zA-Z0-9_]+-(v\d+\.\d+))\b", lambda m: f"crDroid-{m.group(2)}"),
        (r"\b(crDroid[\s_-]*v?\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(EvolutionX[\s_-]*\d+(?:\.\d+)?(?:[\s_-]*v\d+(?:\.\d+)?)?)\b", lambda m: m.group(1)),
        (r"\b(Arrow-v\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(paranoid[\s_-]*[a-zA-Z0-9.-]+)\b", lambda m: m.group(1)),
        (r"\b(ProjectElixir[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(DerpFest[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(RisingOS[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(Cherish-OS-v\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
        (r"\b(Infinity[\s_-]*X[\s_-]*\d+(?:\.\d+)?)\b", lambda m: m.group(1)),
    ]
    for pat, fmt_fn in patterns:
        m = re.search(pat, combined, re.IGNORECASE)
        if m:
            return fmt_fn(m)
    return None

# Stock version tag. Uses look-arounds instead of \b because "_" counts as a word character,
# so "tornado_OS4.0.0.3.XPSCNXM.zip" never matched with \b.
STOCK_VER_RE = r"(?<![A-Za-z0-9])(OS\d+\.\d+\.\d+\.\d+\.[A-Z]{5,9}|V\d+\.\d+\.\d+\.\d+\.[A-Z]{5,9})(?![A-Za-z0-9])"

def parse_meta_texts(meta_text: str, script_text: str, job_id: str):
    """Parses META-INF/com/android/metadata and updater-script text (already read)."""
    meta_info = {"codename": None, "version": None, "raw_text": ""}

    if meta_text:
        meta_info["raw_text"] += "\n" + meta_text
        kv = {}
        for line in meta_text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
        job_log(job_id, "META", f"Parsed META-INF/com/android/metadata: {json.dumps(kv)[:160]}")

        pre_dev = kv.get("pre-device", "").split(",")[0].strip()
        if pre_dev:
            meta_info["codename"] = pre_dev

        post_inc = kv.get("post-build-incremental", "").strip()
        post_build = kv.get("post-build", "").strip()
        ota_id = kv.get("ota-id", "").strip()

        for candidate in (ota_id, post_inc, post_build):
            if not candidate:
                continue
            stock_m = re.search(STOCK_VER_RE, candidate)
            if stock_m:
                meta_info["version"] = stock_m.group(1)
                break
            cust_v = extract_custom_rom_version(candidate, "")
            if cust_v:
                meta_info["version"] = cust_v
                break
        if not meta_info["version"] and post_inc:
            meta_info["version"] = post_inc

    if script_text:
        meta_info["raw_text"] += "\n" + script_text[:4000]
        if not meta_info["codename"]:
            dev_m = re.search(r'ro\.(?:product\.device|build\.product)"\)\s*==\s*"([a-zA-Z0-9_-]+)"', script_text)
            if dev_m:
                meta_info["codename"] = dev_m.group(1)
        if not meta_info["version"]:
            cust_v = extract_custom_rom_version(script_text[:4000], "")
            if cust_v:
                meta_info["version"] = cust_v
        job_log(job_id, "META", "Scanned updater-script for Custom ROM assertions.")

    return meta_info

def inspect_zip_internal_metadata(zf, job_id: str):
    """Range mode: reads the two small metadata files straight from the remote ZIP."""
    namelist = zf.namelist()
    meta_text, script_text = "", ""
    try:
        if "META-INF/com/android/metadata" in namelist:
            meta_text = zf.read("META-INF/com/android/metadata").decode("utf-8", errors="ignore")
    except Exception as e:
        job_log(job_id, "INFO", f"metadata read note: {e}")
    try:
        up = "META-INF/com/google/android/updater-script"
        if up in namelist:
            script_text = zf.read(up).decode("utf-8", errors="ignore")
    except Exception:
        pass
    return parse_meta_texts(meta_text, script_text, job_id)

def reconcile_metadata(user_meta: dict, rom_filename: str, archive_root: str, internal_zip_meta: dict = None, job_id: str = ""):
    """
    Verifies Device Name, Codename and ROM Version against the ROM's own files and the
    KHwang9883/MobileModels database. Unlisted codenames are saved as 'Unknown'.
    """
    if internal_zip_meta is None:
        internal_zip_meta = {}
    combined = f"{archive_root} {rom_filename}"
    raw_codename = internal_zip_meta.get("codename") if internal_zip_meta else None
    detected_ver = internal_zip_meta.get("version") if internal_zip_meta else None
    detected_cat = None
    detected_fmt = None

    lower_fn = rom_filename.lower()
    if lower_fn.endswith((".tgz", ".tar.gz", ".tar")):
        detected_fmt = "FASTBOOT"
    elif lower_fn.endswith(".zip"):
        detected_fmt = "RECOVERY / PAYLOAD ZIP"

    fb_match = re.search(r"([a-zA-Z0-9_]+?)_images_([A-Za-z0-9._-]+?)_(?:20\d{6}|1\d\.0)", combined)
    if fb_match:
        if not raw_codename:
            raw_codename = fb_match.group(1)
        detected_ver = fb_match.group(2)
        detected_cat = "Stock ROM"
        detected_fmt = "FASTBOOT"

    if not detected_ver:
        ver_m = re.search(STOCK_VER_RE, combined)
        if ver_m:
            detected_ver = ver_m.group(1)

    cust_ver = extract_custom_rom_version(internal_zip_meta.get("raw_text", "") if internal_zip_meta else "", rom_filename)
    if cust_ver or any(k in lower_fn for k in ("lineage", "pixel", "crdroid", "evolution", "port")):
        detected_cat = "Custom ROM"
        if not detected_fmt:
            detected_fmt = "CUSTOM ROM"
        if cust_ver and (not detected_ver or not detected_ver.startswith(("OS", "V1"))):
            detected_ver = cust_ver

    if not raw_codename:
        ota_m = re.search(r"\b([a-z0-9_]+?)-ota_full-", lower_fn)
        if ota_m:
            raw_codename = ota_m.group(1)
        else:
            tokens = re.split(r"[^a-zA-Z0-9]+", combined.lower())
            for tok in tokens:
                dev_check, code_check = lookup_codename_in_khwang(tok)
                if dev_check != "Unknown":
                    raw_codename = code_check
                    break

    official_device_name, verified_codename = lookup_codename_in_khwang(raw_codename)

    user_dev = user_meta.get("device_name", "").strip()
    user_ver = user_meta.get("rom_version", "").strip()

    if detected_ver:
        final_ver = detected_ver
    else:
        if user_ver and ("." in user_ver or "-" in user_ver) and len(user_ver) <= 32:
            final_ver = user_ver
        else:
            final_ver = "Verified-Build"

    final_cat = detected_cat or ("Stock ROM" if user_meta.get("rom_category") == "stock" else "Custom ROM")
    final_fmt = detected_fmt or (user_meta.get("rom_format", "fastboot").upper() if final_cat == "Stock ROM" else "CUSTOM ROM")

    if official_device_name == "Unknown":
        auto_status = "Codename Not in KHwang9883 List → Marked 'Unknown'"
        job_log(job_id, "META", f"⚠️ Codename '{raw_codename or 'none'}' not found in KHwang9883 xiaomi_en.md → Saved as 'Unknown'")
    else:
        auto_status = f"Auto-Verified via KHwang9883 DB ({verified_codename})"
        job_log(job_id, "META", f"✨ Auto-Matched in KHwang9883 DB: {official_device_name} [{verified_codename}] | Version: {final_ver}")

    resolved = {
        "user_input_summary": f"{user_dev or '(Blank)'} / {user_ver or '(Blank)'}",
        "device_name": official_device_name,
        "codename": verified_codename,
        "rom_version": final_ver,
        "rom_category": final_cat,
        "rom_format": final_fmt,
        "auto_status": auto_status
    }
    if job_id and job_id in JOBS:
        JOBS[job_id]["resolved_meta"] = resolved
    return resolved

# ---------------- URL & GOOGLE DRIVE RESOLVERS ---------------- #

def make_session(target_url: str = "", job_id: str = "", force_proxy: bool = False):
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Encoding": "identity",
    })
    retry = Retry(total=3, backoff_factor=0.4, status_forcelist=(500, 502, 503, 504), allowed_methods=frozenset(["GET", "HEAD"]))
    ad = HTTPAdapter(pool_connections=8, pool_maxsize=16, max_retries=retry)
    s.mount("https://", ad)
    s.mount("http://", ad)

    if force_proxy or (ALWAYS_ROTATE_PIXELDRAIN and is_throttled_host(target_url)):
        if IP_STATE["active_proxy"]:
            p = IP_STATE["active_proxy"]
            s.proxies = {"http": p, "https": p}
        elif STEM_AVAILABLE and IP_STATE["last_exit_ip"] != "Direct Server IP":
            s.proxies = {"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}
    return s

def extract_gdrive_id(url: str):
    for pat in (r"/file/d/([a-zA-Z0-9_-]{20,})", r"/d/([a-zA-Z0-9_-]{20,})", r"[?&]id=([a-zA-Z0-9_-]{20,})"):
        m = re.search(pat, url)
        if m:
            return m.group(1)
    return None

def parse_filename_from_cd(cd: str):
    if not cd:
        return None
    m_utf8 = re.search(r"filename\*=UTF-8''([^;]+)", cd, re.IGNORECASE)
    if m_utf8:
        return unquote(m_utf8.group(1)).strip('"')
    m_std = re.search(r'filename="?([^";]+)"?', cd, re.IGNORECASE)
    if m_std:
        return unquote(m_std.group(1)).strip('"')
    return None

def resolve_direct_url(url: str, job_id: str, session=None):
    session = session or make_session(url, job_id)
    parsed = urlparse(url)
    if parsed.netloc in ("bigota.d.miui.com", "hugeota.d.miui.com", "cdnorg.d.miui.com"):
        fast_mirror = f"https://bkt-sgp-miui-ota-update-alisgp.oss-ap-southeast-1.aliyuncs.com{parsed.path}"
        try:
            r = session.head(fast_mirror, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                job_log(job_id, "STREAM", f"Auto-routed throttled '{parsed.netloc}' to Xiaomi High-Speed Singapore CDN!")
                url = fast_mirror
        except Exception:
            pass

    resp = session.get(url, stream=True, allow_redirects=True, timeout=30)
    if resp.status_code in (403, 429) and is_throttled_host(url) and not session.proxies:
        resp.close()
        job_log(job_id, "HTTP", f"[IP-Rotator] Host returned HTTP {resp.status_code} (bandwidth limit reached) → switching to rotated IP session...")
        rotate_ip_after_job(job_id, url, throttled_triggered=True)
        session = make_session(url, job_id, force_proxy=True)
        resp = session.get(url, stream=True, allow_redirects=True, timeout=30)

    if resp.status_code >= 400:
        resp.close()
        raise Exception(f"ROM Server returned HTTP {resp.status_code}.")
    if "text/html" in resp.headers.get("Content-Type", "").lower():
        resp.close()
        raise Fatal("That link opens a web page, not a file, and no download button could be followed from it.")
    final_url = resp.url
    total_size = int(resp.headers.get("Content-Length", 0) or 0)
    accept_ranges = resp.headers.get("Accept-Ranges", "none")
    filename = parse_filename_from_cd(resp.headers.get("Content-Disposition", ""))
    resp.close()

    if not filename:
        filename = unquote(os.path.basename(urlparse(final_url).path))
    if not filename:
        filename = unquote(os.path.basename(urlparse(url).path))

    job_log(job_id, "HTTP", f"HTTP 200 OK | File: {filename} | Size: {total_size / MB:.1f} MB | Ranges: {accept_ranges}")
    return final_url, filename, total_size, session

def gdrive_html_reason(html: str):
    """Turns a Google Drive web page (returned instead of the file) into a plain-English reason."""
    low = html.lower()
    if "quota exceeded" in low or "too many users" in low or "download quota" in low:
        return ("Google Drive blocked this download: the file hit its download quota (too many people downloaded it recently). "
                "Open the file in Drive, choose 'Make a copy', share YOUR copy with 'Anyone with the link' and paste that link. "
                "Or wait about 24 hours.")
    if "accounts.google.com" in low or "request access" in low or "you need access" in low or "sign in" in low:
        return "Google Drive asked for a sign-in, so the link is not public. Set sharing to 'Anyone with the link'."
    return None

def resolve_gdrive_stream(file_id: str, job_id: str):
    session = make_session("", job_id)
    direct_url = f"https://drive.usercontent.google.com/download?id={file_id}&export=download&confirm=t"
    resp = session.get(direct_url, stream=True, timeout=30)
    for _ in range(2):
        if "text/html" not in resp.headers.get("Content-Type", "").lower():
            break
        html = resp.text
        resp.close()
        reason = gdrive_html_reason(html)
        if reason:
            raise Fatal(reason)
        # Virus-scan / confirm page: submit its hidden form exactly like the Download anyway button does
        action_m = re.search(r'<form[^>]*action="([^"]+)"', html)
        params = {n: v for n, v in re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html)}
        if not params:
            uuid_match = re.search(r'name="uuid"\s+value="([^"]+)"', html)
            if uuid_match:
                params = {"id": file_id, "export": "download", "confirm": "t", "uuid": uuid_match.group(1)}
        if not params:
            break
        action = (action_m.group(1) if action_m else "https://drive.usercontent.google.com/download").replace("&amp;", "&")
        resp = session.get(action, params=params, stream=True, timeout=30)
    if "text/html" in resp.headers.get("Content-Type", "").lower():
        html = resp.text[:20000]
        resp.close()
        raise Fatal(gdrive_html_reason(html) or "Google Drive returned a web page instead of the ROM file. Check that sharing is 'Anyone with the link'.")
    if resp.status_code != 200:
        resp.close()
        raise Exception("Unable to access Google Drive link. Ensure sharing is set to 'Anyone with the link'.")
    direct_url = resp.url
    filename = parse_filename_from_cd(resp.headers.get("Content-Disposition", "")) or f"gdrive_{file_id}.zip"
    total_size = int(resp.headers.get("Content-Length", 0) or 0)
    resp.close()
    job_log(job_id, "HTTP", f"Google Drive Stream Ready | File: {filename} | Size: {total_size / MB:.1f} MB")
    return direct_url, filename, total_size, session

def supports_ranges(session, url: str):
    """Real probe: only a 206 + Content-Range answer counts as range support."""
    try:
        with session.get(url, headers={"Range": "bytes=0-1"}, stream=True, timeout=30) as r:
            return r.status_code == 206 and r.headers.get("Content-Range", "").lower().startswith("bytes")
    except Exception:
        return False

# ---------------- SMART LINK FINDER (download PAGES -> real file URL) ---------------- #

FILE_EXT_RE = re.compile(r"\.(zip|tgz|tar\.gz|tar|7z|zst|img|bin)$", re.I)
JUNK_EXT_RE = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?|ttf|json|xml|txt|md|html?)$", re.I)

def known_host_url(url: str):
    """Hosts whose real file URL can be built without opening the page."""
    p = urlparse(url)
    host = p.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    if host.endswith(("pixeldrain.com", "pixeldrain.net", "pixeldrain.dev")):
        m = re.match(r"^/(?:u|api/file)/([A-Za-z0-9_-]+)", p.path)
        if m:
            return f"https://{p.netloc}/api/file/{m.group(1)}?download"
    if host == "sourceforge.net":
        m = re.match(r"^/projects/([^/]+)/files/(.+?)(?:/download)?/?$", p.path)
        if m:
            return f"https://downloads.sourceforge.net/project/{m.group(1)}/{m.group(2)}"
    if host.endswith("dropbox.com"):
        if "dl=0" in p.query:
            return url.replace("dl=0", "dl=1")
        if "dl=1" not in p.query and "raw=1" not in p.query:
            return url + ("&" if p.query else "?") + "dl=1"
    return None

def extract_candidates(page: str, base: str):
    """Scores every link on a page that might be the real download. Returns [(score, url)] best first."""
    found = {}

    def add(score, u):
        u = urljoin(base, htmllib.unescape(u.strip()))
        if not u.startswith(("http://", "https://")):
            return
        path = urlparse(u).path
        if JUNK_EXT_RE.search(path):
            return
        if u not in found or found[u] < score:
            found[u] = score

    for m in re.finditer(r'data-scrambled-url="([^"]+)"', page):       # MediaFire
        try:
            add(100, base64.b64decode(m.group(1)).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    m = re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*?url=([^"\'>]+)', page, re.I)
    if m:
        add(90, m.group(1))
    for m in re.finditer(r'<a\b([^>]*)>(.*?)</a>', page, re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        hm = re.search(r'(?:href|data-href|data-url|data-download-url)=["\']([^"\']+)["\']', attrs, re.I)
        if not hm:
            continue
        href = hm.group(1)
        if href.startswith(("javascript:", "#", "mailto:")):
            continue
        text = (re.sub(r"<[^>]+>", " ", inner) + " " + attrs).lower()
        path = urlparse(urljoin(base, htmllib.unescape(href))).path
        score = 0
        if FILE_EXT_RE.search(path):
            score += 60
        if "download" in text:
            score += 25
        if "downloadbutton" in attrs.lower().replace("-", "").replace("_", ""):
            score += 40
        if re.search(r"/(download|dl|get|file)s?(/|$)", path.lower()):
            score += 10
        if score >= 25:
            add(score, href)
    plain = page.replace("\\/", "/")
    for m in re.finditer(r'https?://[^\s"\'<>\\]+?\.(?:zip|tgz|tar\.gz)(?:\?[^\s"\'<>\\]*)?', plain, re.I):
        add(55, m.group(0))
    return sorted(((sc, u) for u, sc in found.items()), key=lambda x: -x[0])

def probe_link(session, url: str, referer=None):
    """Opens a link just long enough to see what it is. Returns ('file', final_url, None),
    ('html', final_url, page_text) or None when it cannot be opened."""
    hdr = {"Referer": referer} if referer else {}
    try:
        r = session.get(url, headers=hdr, stream=True, allow_redirects=True, timeout=30)
    except Exception:
        return None
    try:
        if r.status_code >= 400:
            return None
        ct = r.headers.get("Content-Type", "").lower()
        if "text/html" in ct or "application/xhtml" in ct:
            body, got = [], 0
            for c in r.iter_content(chunk_size=65536):
                body.append(c)
                got += len(c)
                if got > 1_500_000:
                    break
            return "html", r.url, b"".join(body).decode(r.encoding or "utf-8", errors="ignore")
        return "file", r.url, None
    finally:
        r.close()

def find_download_url(session, url: str, job_id: str, depth: int = 0, seen=None):
    """Turns a page link (SourceForge, PixelDrain, MediaFire, any page with a download button...)
    into the real file URL. Direct file links are returned untouched."""
    seen = seen if seen is not None else set()
    fast = known_host_url(url)
    if fast:
        job_log(job_id, "HTTP", f"Recognised download host → direct link: {fast[:110]}")
        url = fast
    elif FILE_EXT_RE.search(urlparse(url).path):
        return url  # already looks like a file link: skip the probe request

    res = probe_link(session, url)
    if res is None:
        raise Fatal("Could not open that link (the site refused the request or is down).")
    kind, final, page = res
    if kind == "file":
        session.headers["Referer"] = final
        return final
    if depth >= 2:
        raise Fatal("Followed the page links but never reached a file. The site may need a captcha or a login.")

    cands = extract_candidates(page, final)
    job_log(job_id, "HTTP", f"Download page detected → checking {min(len(cands), 8)} candidate link(s)...")
    tried, hops = 0, 0
    for score, cu in cands:
        if cu in seen or tried >= 8:
            continue
        seen.add(cu)
        tried += 1
        r = probe_link(session, cu, final)
        if r is None:
            continue
        if r[0] == "file":
            job_log(job_id, "HTTP", f"Found the real download link (score {score}): {r[1][:110]}")
            session.headers["Referer"] = final
            return r[1]
        if hops < 3:  # an intermediate page (e.g. 'Your download is ready') -> look one level deeper
            hops += 1
            try:
                return find_download_url(session, cu, job_id, depth + 1, seen)
            except Fatal:
                continue
    raise Fatal("No download button or file link could be found on that page. It may build the link with JavaScript, "
                "need a captcha / countdown, or need a login. Open the page, start the download, copy the file's real link "
                "(from the browser's download list) and paste that instead.")

def sniff_format(session, url: str, filename: str):
    """Decides 'zip' or 'tgz'. A clear file extension wins, so no extra request is sent to the server."""
    low = filename.lower()
    if low.endswith((".tgz", ".tar.gz", ".tar")):
        return "tgz"
    if low.endswith(".zip"):
        return "zip"
    head = b""
    try:
        with session.get(url, stream=True, timeout=30) as r:
            for c in r.iter_content(chunk_size=512):
                head = c
                break
    except Exception:
        pass
    if head[:2] == b"PK":
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "tgz"
    if head[:1] == b"<":
        snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", head.decode("utf-8", errors="ignore"))).strip()[:120]
        raise Fatal(f"The server returned a web page instead of the ROM ({snippet or 'HTML'}). Drive quota or link is not public.")
    raise Fatal("Unsupported ROM archive format. Must be .tgz/.tar.gz or .zip.")

# ================================================================================ #
# ENGINE:BEGIN — streaming readers, sparse images, super.img (LP) and payload.bin   #
# ================================================================================ #

PIECE = 4 << 20          # 4 MB network/disk pieces keep fast links (300 Mbps - 1 Gbps) saturated
SPARSE_MAGIC = 0xED26FF3A
LP_GEOMETRY_MAGIC = 0x616C4467
LP_HEADER_MAGIC = 0x414C5030
HEAD_BYTES = 1 << 20
SUPER_RE = re.compile(r"^super(_sparse)?(\.img)?(\.zst)?$")

class Fatal(Exception):
    """Deterministic failure: do not retry in another mode."""

class Cancelled(Fatal):
    """The user pressed Cancel."""

class NotInSource(Fatal):
    def __init__(self, msg, available=None):
        super().__init__(msg)
        self.available = available or []

def check_cancel(job):
    if job.get("cancel"):
        raise Cancelled("Cancelled by user.")

class IterFile:
    """File-like read()/skip() on top of an iterator of byte chunks (no big copies)."""
    def __init__(self, it):
        self.it = iter(it)
        self.left = b""
        self.off = 0

    def read(self, n=-1):
        if n is None or n < 0:
            parts = [self.left[self.off:]] + list(self.it)
            self.left, self.off = b"", 0
            return b"".join(parts)
        parts, need = [], n
        while need > 0:
            if self.off >= len(self.left):
                try:
                    self.left = next(self.it)
                    self.off = 0
                except StopIteration:
                    break
                continue
            take = self.left[self.off:self.off + need]
            self.off += len(take)
            need -= len(take)
            parts.append(take)
        return b"".join(parts)

    def skip(self, n):
        while n > 0:
            if self.off >= len(self.left):
                try:
                    self.left = next(self.it)
                    self.off = 0
                except StopIteration:
                    return
                continue
            k = min(n, len(self.left) - self.off)
            self.off += k
            n -= k

    def close(self):
        pass

class Stream:
    """Forward-only reader with peek/unread/skip. skip() seeks when the source supports it."""
    def __init__(self, fp, seek_ok=False):
        self.fp = fp
        self.seek_ok = seek_ok
        self.pb = b""
        self.pos = 0

    def read(self, n):
        parts, got = [], 0
        if self.pb:
            take = self.pb[:n]
            self.pb = self.pb[len(take):]
            parts.append(take)
            got = len(take)
        while got < n:
            c = self.fp.read(n - got)
            if not c:
                break
            parts.append(c)
            got += len(c)
        data = parts[0] if len(parts) == 1 else b"".join(parts)
        self.pos += len(data)
        return data

    def unread(self, data):
        self.pb = data + self.pb
        self.pos -= len(data)

    def peek(self, n):
        d = self.read(n)
        self.unread(d)
        return d

    def skip(self, n):
        if n <= 0:
            return
        if self.pb:
            k = min(n, len(self.pb))
            self.pb = self.pb[k:]
            n -= k
            self.pos += k
        if n <= 0:
            return
        if hasattr(self.fp, "skip"):
            self.fp.skip(n)
            self.pos += n
            return
        if self.seek_ok:
            try:
                self.fp.seek(n, os.SEEK_CUR)
                self.pos += n
                return
            except Exception:
                pass
        left = n
        while left > 0:
            c = self.fp.read(min(left, PIECE))
            if not c:
                break
            left -= len(c)
        self.pos += n - left

    def close(self):
        pass

def zst_stream(stream):
    return Stream(zstd.ZstdDecompressor().stream_reader(stream, read_across_frames=True))

def _speed(job, nbytes, t0):
    el = max(0.05, time.time() - t0)
    job["speed"] = f"{(nbytes * 8) / (el * 1_000_000):.0f} Mbps ({nbytes / MB / el:.1f} MB/s)"

def net_chunks(session, url, job_id, total_size):
    """Network byte source. Drives the 'Locating file' bar until the file is found.
    If the server closes early (fewer bytes than Content-Length) it raises, so a cut-off
    download can never be mistaken for a complete ROM."""
    job = JOBS[job_id]
    t0, done, last = time.time(), 0, 0.0
    is_pd = is_throttled_host(url) and not session.proxies
    with session.get(url, stream=True, timeout=(30, 120)) as resp:
        resp.raise_for_status()
        if "text/html" in resp.headers.get("Content-Type", "").lower():
            page = resp.text[:20000]
            reason = gdrive_html_reason(page)
            snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)).strip()[:120]
            raise Fatal(reason or f"The server returned a web page instead of the ROM ({snippet or 'HTML'}). The link may have expired or is not public.")
        for c in resp.iter_content(chunk_size=PIECE):
            if not c:
                continue
            check_cancel(job)
            done += len(c)
            if is_pd:
                IP_STATE["direct_pixeldrain_bytes"] += len(c)
            now = time.time()
            if now - last >= 0.25:
                last = now
                mb_done = done / MB
                job["bytes_streamed_mb"] = f"{mb_done:.1f} MB"
                job["hex_offset"] = f"0x{done:08X}"
                _speed(job, done, t0)
                if job["search_progress"] < 100:
                    if total_size > 0:
                        stage(job, "search", min(99, done / total_size * 100),
                              f"Scanning ROM for the file: {mb_done:.0f} MB / {total_size / MB:.0f} MB")
                    else:
                        stage(job, "search", min(95, mb_done / 40), f"Scanning ROM for the file: {mb_done:.0f} MB streamed")
            yield c
    if total_size and done < total_size:
        raise Exception(f"Download ended early ({done / MB:.1f} of {total_size / MB:.1f} MB). The server closed the connection; nothing was saved.")

def prefetch(gen, depth=24):
    """Pulls the network in a background thread, so the link keeps downloading while the main
    thread decompresses and writes to disk."""
    q = queue.Queue(maxsize=depth)
    stop = threading.Event()
    END = object()

    def put(item):
        while not stop.is_set():
            try:
                q.put(item, timeout=0.5)
                return True
            except queue.Full:
                continue
        return False

    def pump():
        try:
            for c in gen:
                if not put(c):
                    return
            put(END)
        except BaseException as e:
            put(e)
        finally:
            try:
                gen.close()
            except Exception:
                pass

    threading.Thread(target=pump, daemon=True).start()

    def consume():
        try:
            while True:
                try:
                    item = q.get(timeout=1)
                except queue.Empty:
                    continue
                if item is END:
                    return
                if isinstance(item, BaseException):
                    raise item
                yield item
        finally:
            stop.set()

    return consume()

def copy_to_file(job_id, reader, out_path, size, label):
    job = JOBS[job_id]
    t0, copied, last = time.time(), 0, 0.0
    with open(out_path, "wb") as dst:
        while True:
            check_cancel(job)
            buf = reader.read(PIECE)
            if not buf:
                break
            dst.write(buf)
            copied += len(buf)
            now = time.time()
            if now - last >= 0.25:
                last = now
                pct = (copied / size * 99) if size else min(95, copied / (300 * MB) * 95)
                stage(job, "ext", pct, f"Extracting {label}: {copied / MB:.1f}" + (f" / {size / MB:.1f} MB" if size else " MB"))
                job["bytes_streamed_mb"] = f"{copied / MB:.1f} MB"
                _speed(job, copied, t0)
    stage(job, "ext", 100, f"Extracted {label} ({copied / MB:.1f} MB)")
    return copied

# ---------------- Android sparse + raw image expansion ---------------- #

class ExpandedReader:
    """
    Yields (offset, data) pieces of the *expanded* image, in order, from either a raw
    or an Android-sparse stream. If .need(off, len) says a piece is not wanted it is
    skipped (seek on range-capable sources). .stop_at ends the scan early.
    """
    def __init__(self, stream, size_hint=None):
        self.stream = stream
        self.size_hint = size_hint
        self.need = None
        self.stop_at = None
        self.tick = lambda off: None
        self.total = None

    def _wanted(self, off, n):
        return self.need is None or self.need(off, n)

    def pieces(self):
        s = self.stream
        magic = s.peek(4)
        if len(magic) == 4 and struct.unpack("<I", magic)[0] == SPARSE_MAGIC:
            hdr = s.read(28)
            if len(hdr) < 28:
                raise Exception("Sparse image truncated (file header).")
            (_m, _maj, _min, fhs, chs, blk, tblks, tchunks, _crc) = struct.unpack("<IHHHHIIII", hdr)
            if fhs > 28:
                s.skip(fhs - 28)
            self.total = tblks * blk
            off = 0
            for _ in range(tchunks):
                if self.stop_at is not None and off >= self.stop_at:
                    return
                ch = s.read(chs)
                if len(ch) < chs:
                    raise Exception("Sparse image truncated (chunk header).")
                ctype, _r, csz, tsz = struct.unpack("<HHII", ch[:12])
                nbytes = csz * blk
                if ctype == 0xCAC1:  # RAW
                    done = 0
                    while done < nbytes:
                        if self.stop_at is not None and off + done >= self.stop_at:
                            return
                        n = min(PIECE, nbytes - done)
                        if self._wanted(off + done, n):
                            d = s.read(n)
                            if len(d) < n:
                                raise Exception("Sparse image truncated (raw data).")
                            yield off + done, d
                        else:
                            s.skip(n)
                        done += n
                        self.tick(off + done)
                elif ctype == 0xCAC2:  # FILL
                    fill = s.read(4)
                    if fill != b"\x00\x00\x00\x00":
                        pat = fill * (PIECE // 4)
                        done = 0
                        while done < nbytes:
                            n = min(PIECE, nbytes - done)
                            if self._wanted(off + done, n):
                                yield off + done, pat[:n]
                            done += n
                elif ctype == 0xCAC3:  # DONT_CARE
                    pass
                elif ctype == 0xCAC4:  # CRC32
                    s.skip(tsz - chs)
                else:
                    raise Exception(f"Unknown sparse chunk type 0x{ctype:04X}")
                off += nbytes
                self.tick(off)
            return

        # Raw image
        off = 0
        size = self.size_hint
        while True:
            if self.stop_at is not None and off >= self.stop_at:
                return
            if size is not None:
                if off >= size:
                    return
                n = min(PIECE, size - off)
            else:
                n = PIECE
            if size is not None and not self._wanted(off, n):
                s.skip(n)
                off += n
                self.tick(off)
                continue
            d = s.read(n)
            if not d:
                return
            yield off, d
            off += len(d)
            self.tick(off)

# ---------------- LP (dynamic partitions) metadata ---------------- #

def parse_lp(head: bytes):
    """
    Parses liblp metadata of an expanded super image.
      geometry @ 4096 | backup geometry @ 8192 | primary metadata slot 0 @ 12288
    Returns {partition_name: [(target_type, num_sectors, physical_sector), ...]}.
    """
    if len(head) < 12288 + 256:
        raise Fatal("Image is too small to be a super.img.")
    gmagic = struct.unpack_from("<I", head, 4096)[0]
    if gmagic != LP_GEOMETRY_MAGIC:
        raise Fatal("No LP geometry found: this super.img is not a dynamic-partition image.")
    m = 4096 + 8192
    hmagic, _maj, _min, hsize = struct.unpack_from("<IHHI", head, m)
    if hmagic != LP_HEADER_MAGIC:
        raise Fatal("LP metadata header not found at slot 0.")
    tables_size = struct.unpack_from("<I", head, m + 44)[0]
    (p_off, p_n, p_sz, e_off, e_n, e_sz, _g_off, _g_n, _g_sz, _b_off, _b_n, _b_sz) = struct.unpack_from("<12I", head, m + 80)
    tbl = m + hsize
    if tbl + tables_size > len(head):
        raise Fatal("LP metadata tables are larger than the scanned header area.")
    parts = {}
    for i in range(p_n):
        b = tbl + p_off + i * p_sz
        name = head[b:b + 36].split(b"\x00")[0].decode("utf-8", errors="ignore")
        _attrs, first, cnt, _grp = struct.unpack_from("<IIII", head, b + 36)
        exts = []
        for j in range(first, first + cnt):
            eb = tbl + e_off + j * e_sz
            sectors, ttype, tdata, _tsrc = struct.unpack_from("<QIQI", head, eb)
            exts.append((ttype, sectors, tdata))
        parts[name] = exts
    return parts

def resolve_lp_partition(parts, req):
    base = re.sub(r"\.(img|bin)$", "", req.strip(), flags=re.I)
    lower = {k.lower(): k for k in parts}
    for cand in (base, base + "_a", base + "_b"):
        k = lower.get(cand.lower())
        if k and sum(e[1] for e in parts[k]) > 0:
            return k
    return None

def extract_from_super(job_id, stream, part_req, out_path, size_hint=None, cname="super.img"):
    """Writes the logical partition `part_req` out of a raw or sparse super image.
    Bar 2 = reading the super image up to the last byte the partition needs.
    Bar 3 = bytes of the partition written to disk."""
    job = JOBS[job_id]
    job["cont_name"] = cname
    job["cont_skip"] = False
    stage(job, "cont", 0, f"Reading {cname} header...")
    reader = ExpandedReader(stream, size_hint)
    gen = reader.pieces()
    head = bytearray(HEAD_BYTES)
    pending = []
    for off, data in gen:
        check_cancel(job)
        if off < HEAD_BYTES:
            n = min(len(data), HEAD_BYTES - off)
            head[off:off + n] = data[:n]
            if n < len(data):
                pending.append((off + n, data[n:]))
        else:
            pending.append((off, data))
        if off + len(data) >= HEAD_BYTES:
            break

    parts = parse_lp(bytes(head))
    listing = ", ".join(f"{k} ({sum(e[1] for e in v) * 512 / MB:.0f} MB)" for k, v in parts.items() if sum(e[1] for e in v) > 0)
    job_log(job_id, "META", f"super.img LP partitions: {listing[:600]}")

    pname = resolve_lp_partition(parts, part_req)
    if not pname:
        raise NotInSource(f"'{part_req}' is not a partition inside this super.img.", available=[k for k, v in parts.items() if sum(e[1] for e in v) > 0])

    ext, lo = [], 0
    for ttype, sectors, tdata in parts[pname]:
        ln = sectors * 512
        if ttype == 0:
            ext.append((tdata * 512, ln, lo))
        lo += ln
    total = lo
    ext.sort()
    starts = [e[0] for e in ext]
    max_end = max((s + l) for s, l, _ in ext) if ext else 0
    mb_total = total / MB
    job_log(job_id, "STREAM", f"MATCH: logical partition '{pname}' | {len(ext)} extents | {total:,} bytes ({mb_total:.2f} MB)")
    stage(job, "search", 100, f"Found '{pname}' inside {cname} ({mb_total:.1f} MB)")

    def need(off, ln):
        i = bisect.bisect_right(starts, off + ln - 1) - 1
        return i >= 0 and ext[i][0] + ext[i][1] > off

    wr = [0]

    def write_piece(out, off, data):
        end = off + len(data)
        i = max(0, bisect.bisect_right(starts, off) - 1)
        while i < len(ext) and ext[i][0] < end:
            ps, ln, dst = ext[i]
            a, b = max(ps, off), min(ps + ln, end)
            if a < b:
                out.seek(dst + (a - ps))
                out.write(data[a - off:b - off])
                wr[0] += b - a
            i += 1

    t0 = time.time()
    last = [0.0]

    def report(off, force=False):
        now = time.time()
        if not force and now - last[0] < 0.25:
            return
        last[0] = now
        stage(job, "cont", min(99, off / max(1, max_end) * 100),
              f"Downloading {cname}: {off / MB:.0f} / {max_end / MB:.0f} MB")
        stage(job, "ext", min(99, wr[0] / max(1, total) * 100),
              f"Writing '{pname}': {wr[0] / MB:.0f} / {mb_total:.0f} MB")
        job["hex_offset"] = f"0x{off:08X}"
        job["bytes_streamed_mb"] = f"{off / MB:.1f} MB"
        _speed(job, off, t0)

    def tick(off):
        check_cancel(job)
        report(off)

    reader.need = need
    reader.stop_at = max_end
    reader.tick = tick

    with open(out_path, "wb") as out:
        out.truncate(total)
        write_piece(out, 0, bytes(head))
        for off, data in pending:
            write_piece(out, off, data)
        for off, data in gen:
            check_cancel(job)
            if off >= max_end:
                break
            write_piece(out, off, data)
            job["chunks_verified"] += 1
            report(off + len(data))
        out.truncate(total)

    stage(job, "cont", 100, f"Downloaded {cname} ✓")
    stage(job, "ext", 100, f"Extracted '{pname}' ({mb_total:.1f} MB)")
    return {"expected_size": total, "source": f"super.img → {pname}"}

# ---------------- payload.bin (CrAU) protobuf ---------------- #

def _read_varint(buf: bytes, pos: int):
    res, shift = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, pos
        shift += 7

def _iter_fields(buf: bytes):
    pos, n = 0, len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        field_num, wire_type = tag >> 3, tag & 0x07
        if wire_type == 0:
            val, pos = _read_varint(buf, pos)
            yield field_num, val
        elif wire_type == 1:
            yield field_num, buf[pos:pos + 8]
            pos += 8
        elif wire_type == 2:
            length, pos = _read_varint(buf, pos)
            yield field_num, buf[pos:pos + length]
            pos += length
        elif wire_type == 5:
            yield field_num, buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError("Unsupported wire type")

PAYLOAD_OP_NAMES = {0: "RAW", 1: "BZIP2", 8: "XZ", 14: "ZSTD"}
PAYLOAD_DELTA_OPS = {2, 3, 4, 5, 9, 10, 11, 12, 13}

def extract_from_payload(job_id, stream, part_name, out_path):
    """Extracts one partition from payload.bin (full OTA). Works on seekable and forward-only streams.
    Bar 2 = compressed bytes fetched from payload.bin. Bar 3 = bytes of the partition written."""
    job = JOBS[job_id]
    job["cont_name"] = "payload.bin"
    job["cont_skip"] = False
    stage(job, "cont", 0, "Reading payload.bin manifest...")
    if stream.read(4) != b"CrAU":
        raise Fatal("Invalid payload.bin CrAU magic header.")
    version = struct.unpack(">Q", stream.read(8))[0]
    manifest_size = struct.unpack(">Q", stream.read(8))[0]
    sig_size = struct.unpack(">I", stream.read(4))[0] if version >= 2 else 0
    manifest = stream.read(manifest_size)
    base_data_offset = (24 if version >= 2 else 20) + manifest_size + sig_size

    block_size, parts = 4096, {}
    for fnum, val in _iter_fields(manifest):
        if fnum == 3:
            block_size = val
        elif fnum == 13:
            nm = None
            for pf, pv in _iter_fields(val):
                if pf == 1:
                    nm = pv.decode("utf-8", errors="ignore")
                    break
            if nm:
                parts[nm] = val

    key = next((k for k in parts if k.lower() == part_name.lower()), None)
    if key is None:
        raise NotInSource(f"'{part_name}' not found in payload.bin.", available=list(parts))

    expected_size, expected_hash, ops = None, None, []
    for pf, pv in _iter_fields(parts[key]):
        if pf == 7:
            for ifn, iv in _iter_fields(pv):
                if ifn == 1:
                    expected_size = iv
                elif ifn == 2:
                    expected_hash = iv
        elif pf == 8:
            otype, doff, dlen, dsha, dst = 0, 0, 0, None, []
            for of, ov in _iter_fields(pv):
                if of == 1: otype = ov
                elif of == 2: doff = ov
                elif of == 3: dlen = ov
                elif of == 6:
                    sb, nb = 0, 0
                    for ef, ev in _iter_fields(ov):
                        if ef == 1: sb = ev
                        elif ef == 2: nb = ev
                    dst.append((sb, nb))
                elif of == 8:
                    dsha = ov
            ops.append((otype, doff, dlen, dst, dsha))

    if any(o[0] in PAYLOAD_DELTA_OPS for o in ops):
        raise Fatal("This payload.bin is an incremental/delta OTA; only full OTAs can be extracted.")

    todo = sorted((o for o in ops if o[2] > 0 and o[0] not in (6, 7)), key=lambda o: o[1])
    mb_total = (expected_size or 0) / MB
    total_dlen = max(1, sum(o[2] for o in todo))
    job_log(job_id, "STREAM", f"payload.bin: '{key}' | {len(todo)} data chunks | {mb_total:.2f} MB")
    stage(job, "search", 100, f"Found '{key}' in payload.bin ({mb_total:.1f} MB)")

    zdec = zstd.ZstdDecompressor()
    t0, fetched, written = time.time(), 0, 0
    total_ops = len(todo)
    with open(out_path, "wb") as out:
        if expected_size:
            out.truncate(expected_size)
        for idx, (otype, doff, dlen, dst, dsha) in enumerate(todo, 1):
            check_cancel(job)
            absoff = base_data_offset + doff
            gap = absoff - stream.pos
            if gap < 0:
                raise Fatal("payload.bin operations are not in forward order; cannot stream this ROM.")
            stream.skip(gap)
            blob = stream.read(dlen)
            if len(blob) != dlen:
                raise Exception("payload.bin stream ended early (truncated download).")
            fetched += dlen
            if dsha and hashlib.sha256(blob).digest() != dsha:
                raise Exception(f"Anti-Brick Guard: Chunk {idx}/{total_ops} failed SHA-256 verification!")

            if otype == 0:
                raw = blob
            elif otype == 8 or blob.startswith(b"\xfd7zXZ\x00"):
                raw = lzma.decompress(blob)
            elif otype == 1 or blob.startswith(b"BZh"):
                raw = bz2.decompress(blob)
            elif otype == 14 or blob.startswith(b"\x28\xb5\x2f\xfd"):
                raw = zdec.decompressobj().decompress(blob)
            else:
                raise Fatal(f"Unsupported payload operation type: {otype}")

            pos = 0
            for sb, nb in dst:
                ln = nb * block_size
                out.seek(sb * block_size)
                out.write(raw[pos:pos + ln])
                pos += ln
                written += min(ln, max(0, len(raw) - (pos - ln)))

            job["chunks_verified"] = idx
            job["bytes_streamed_mb"] = f"{fetched / MB:.2f} MB"
            job["hex_offset"] = f"0x{absoff:08X}"
            job["current_scan"] = f"Chunk {idx}/{total_ops} [{PAYLOAD_OP_NAMES.get(otype, 'COMP')}]"
            _speed(job, fetched, t0)
            stage(job, "cont", min(99, fetched / total_dlen * 100),
                  f"Downloading payload.bin data: {fetched / MB:.0f} / {total_dlen / MB:.0f} MB")
            stage(job, "ext", min(99, (written / expected_size * 100) if expected_size else idx / max(1, total_ops) * 100),
                  f"Decompressing & hashing chunk {idx}/{total_ops} ({mb_total:.1f} MB)")
            if idx == 1 or idx == total_ops or idx % max(1, total_ops // 6) == 0:
                job_log(job_id, "CHUNK", f"Chunk {idx}/{total_ops} [{PAYLOAD_OP_NAMES.get(otype, 'COMP')}] @ 0x{absoff:08X} ({dlen:,} B -> {len(raw):,} B) OK")
        if expected_size:
            out.truncate(expected_size)

    stage(job, "cont", 100, "Downloaded payload.bin data ✓")
    stage(job, "ext", 100, f"Extracted '{key}' ({mb_total:.1f} MB)")
    return {"expected_size": expected_size, "expected_sha": expected_hash, "source": f"payload.bin → {key}"}

# ================================================================================ #
# ENGINE:END                                                                        #
# ================================================================================ #

# ---------------- TARGET MATCHING ---------------- #

class Want:
    def __init__(self, target: str):
        self.name = os.path.basename(target.replace("\\", "/")).strip()
        self.low = self.name.lower()
        self.stem = re.sub(r"\.(img|bin)$", "", self.low)
        self.is_super = self.stem == "super"

def norm_name(n: str):
    return re.sub(r"^(\./)+", "", n.replace("\\", "/"))

def classify(low: str, want: Want):
    """exact | exact_zst | super | super_zst | None — `low` is a lower-cased base file name."""
    if low == want.low:
        return "exact"
    if low in (want.low + ".zst", want.stem + ".zst", want.stem + ".img.zst"):
        return "exact_zst"
    if not want.is_super and SUPER_RE.match(low):
        return "super_zst" if low.endswith(".zst") else "super"
    return None

def not_found_error(want, searched):
    where = "; ".join(searched) if searched else "no matching file, payload.bin or super.img was found"
    return NotInSource(f"'{want.name}' was not found. Searched: {where}.")

# ---------------- ARCHIVE WALKERS ---------------- #

def extract_tgz(job_id, session, url, total_size, rom_filename, want, user_meta, out_path):
    """Fastboot .tgz — one forward pass. Direct file, .zst file, or logical partition inside super.img."""
    job = JOBS[job_id]
    resolved, root_seen, searched = None, False, []
    gen = prefetch(net_chunks(session, url, job_id, total_size))
    try:
        with tarfile.open(fileobj=IterFile(gen), mode="r|*") as tar:
            for member in tar:
                check_cancel(job)
                norm = norm_name(member.name)
                if not root_seen and "/" in norm:
                    root_seen = True
                    resolved = reconcile_metadata(user_meta, rom_filename, norm.split("/")[0], {}, job_id)
                if not member.isfile():
                    continue
                base = os.path.basename(norm)
                job["current_scan"] = norm
                job["chunks_verified"] += 1
                kind = classify(base.lower(), want)
                if not kind:
                    continue
                fp = tar.extractfile(member)
                if fp is None:
                    continue
                if not resolved:
                    resolved = reconcile_metadata(user_meta, rom_filename, norm, {}, job_id)
                stream = Stream(fp)

                if kind in ("exact", "exact_zst"):
                    stage(job, "search", 100, f"Located {norm} ({member.size / MB:.2f} MB)")
                    mark_direct(job)
                    job_log(job_id, "STREAM", f"MATCH FOUND: '{norm}' | {member.size:,} bytes")
                    if kind == "exact":
                        copy_to_file(job_id, stream, out_path, member.size, want.name)
                        return {"expected_size": member.size, "source": f"file: {norm}", "resolved_meta": resolved}
                    copy_to_file(job_id, zst_stream(stream), out_path, 0, want.name)
                    return {"source": f"zstd file: {norm}", "resolved_meta": resolved}

                job_log(job_id, "STREAM", f"Opening '{norm}' to look for logical partition '{want.stem}'...")
                try:
                    src = zst_stream(stream) if kind == "super_zst" else stream
                    info = extract_from_super(job_id, src, want.stem, out_path, None if kind == "super_zst" else member.size, cname=base)
                    info["resolved_meta"] = resolved
                    return info
                except NotInSource as e:
                    searched.append(f"{norm} (partitions: {', '.join(e.available[:30])})")
    finally:
        gen.close()
    raise not_found_error(want, searched)

def extract_zip_ranged(job_id, session, url, rom_filename, want, user_meta, out_path):
    """Recovery/custom/port .zip over HTTP Range: jumps straight to the bytes it needs."""
    job = JOBS[job_id]
    searched = []
    is_pd = is_throttled_host(url) and not session.proxies
    with RemoteZip(url, session=session) as zf:
        namelist = zf.namelist()
        internal_meta = inspect_zip_internal_metadata(zf, job_id)
        resolved = reconcile_metadata(user_meta, rom_filename, "", internal_meta, job_id)
        stage(job, "search", 60, f"ZIP index mapped ({len(namelist)} files) — {resolved['device_name']}")
        check_cancel(job)

        exact = super_e = payload_e = None
        for n in namelist:
            if n.endswith("/"):
                continue
            low = os.path.basename(norm_name(n)).lower()
            k = classify(low, want)
            if k in ("exact", "exact_zst") and (exact is None or k == "exact"):
                exact = (n, k)
            elif k in ("super", "super_zst") and super_e is None:
                super_e = (n, k)
            if low == "payload.bin" and payload_e is None:
                payload_e = n

        if exact:
            n, k = exact
            info = zf.getinfo(n)
            stage(job, "search", 100, f"Located {n} ({info.file_size / MB:.2f} MB)")
            mark_direct(job)
            job_log(job_id, "STREAM", f"Direct ZIP Entry: '{n}' | Offset: 0x{info.header_offset:08X} | CRC32: {hex(info.CRC)}")
            with zf.open(n) as fp:
                if k == "exact":
                    copied = copy_to_file(job_id, Stream(fp), out_path, info.file_size, want.name)
                    if is_pd:
                        IP_STATE["direct_pixeldrain_bytes"] += copied
                    return {"expected_size": info.file_size, "expected_crc": info.CRC, "source": f"file: {n}", "resolved_meta": resolved}
                copied = copy_to_file(job_id, zst_stream(Stream(fp)), out_path, 0, want.name)
                if is_pd:
                    IP_STATE["direct_pixeldrain_bytes"] += copied
                return {"source": f"zstd file: {n}", "resolved_meta": resolved}

        if payload_e:
            job_log(job_id, "STREAM", f"Opening payload.bin for '{want.stem}'...")
            try:
                with zf.open(payload_e) as fp:
                    info = extract_from_payload(job_id, Stream(fp, seek_ok=True), want.stem, out_path)
                if is_pd:
                    IP_STATE["direct_pixeldrain_bytes"] += info.get("expected_size") or 0
                info["resolved_meta"] = resolved
                return info
            except NotInSource as e:
                searched.append(f"payload.bin (partitions: {', '.join(e.available[:40])})")

        if super_e:
            n, k = super_e
            zi = zf.getinfo(n)
            job_log(job_id, "STREAM", f"Opening '{n}' ({zi.file_size / MB:.0f} MB) for logical partition '{want.stem}'...")
            try:
                with zf.open(n) as fp:
                    base = Stream(fp, seek_ok=True)
                    info = extract_from_super(job_id, zst_stream(base) if k == "super_zst" else base, want.stem, out_path,
                                              None if k == "super_zst" else zi.file_size, cname=os.path.basename(n))
                if is_pd:
                    IP_STATE["direct_pixeldrain_bytes"] += info.get("expected_size") or 0
                info["resolved_meta"] = resolved
                return info
            except NotInSource as e:
                searched.append(f"{n} (partitions: {', '.join(e.available[:30])})")
    raise not_found_error(want, searched)

def extract_zip_sequential(job_id, session, url, total_size, rom_filename, want, user_meta, out_path):
    """Same logic for servers without Range support (Google Drive): one forward pass, no random access."""
    try:
        from stream_unzip import stream_unzip
    except ImportError:
        raise Fatal("Missing dependency: add 'stream-unzip' to requirements.txt")
    job = JOBS[job_id]
    meta = {"meta": "", "script": ""}
    searched = []

    def resolve():
        return reconcile_metadata(user_meta, rom_filename, "", parse_meta_texts(meta["meta"], meta["script"], job_id), job_id)

    gen = prefetch(net_chunks(session, url, job_id, total_size))
    try:
        try:
            entries = stream_unzip(gen, chunk_size=PIECE)
        except TypeError:
            entries = stream_unzip(gen)
        for name_b, size, chunks in entries:
            check_cancel(job)
            name = name_b.decode("utf-8", errors="ignore") if isinstance(name_b, (bytes, bytearray)) else str(name_b)
            clean = norm_name(name)
            if clean.endswith("/"):
                for _ in chunks:
                    pass
                continue
            low = os.path.basename(clean).lower()
            job["current_scan"] = clean
            job["chunks_verified"] += 1
            stream = Stream(IterFile(chunks))
            kind = classify(low, want)

            if clean == "META-INF/com/android/metadata":
                meta["meta"] = stream.read(65536).decode("utf-8", errors="ignore")
            elif clean == "META-INF/com/google/android/updater-script":
                meta["script"] = stream.read(65536).decode("utf-8", errors="ignore")
            elif kind in ("exact", "exact_zst"):
                stage(job, "search", 100, f"Located {clean}")
                mark_direct(job)
                job_log(job_id, "STREAM", f"MATCH FOUND (sequential): '{clean}' | size: {size}")
                if kind == "exact":
                    copy_to_file(job_id, stream, out_path, size or 0, want.name)
                    return {"expected_size": size or None, "source": f"file: {clean}", "resolved_meta": resolve()}
                copy_to_file(job_id, zst_stream(stream), out_path, 0, want.name)
                return {"source": f"zstd file: {clean}", "resolved_meta": resolve()}
            elif low == "payload.bin":
                job_log(job_id, "STREAM", f"Opening payload.bin (sequential) for '{want.stem}'...")
                try:
                    info = extract_from_payload(job_id, stream, want.stem, out_path)
                    info["resolved_meta"] = resolve()
                    return info
                except NotInSource as e:
                    searched.append(f"payload.bin (partitions: {', '.join(e.available[:40])})")
            elif kind in ("super", "super_zst"):
                job_log(job_id, "STREAM", f"Opening '{clean}' (sequential) for logical partition '{want.stem}'...")
                try:
                    src = zst_stream(stream) if kind == "super_zst" else stream
                    info = extract_from_super(job_id, src, want.stem, out_path, None if kind == "super_zst" else size, cname=os.path.basename(clean))
                    info["resolved_meta"] = resolve()
                    return info
                except NotInSource as e:
                    searched.append(f"{clean} (partitions: {', '.join(e.available[:30])})")

            for _ in chunks:  # every skipped entry must be drained before the next one
                pass
    finally:
        gen.close()
    raise not_found_error(want, searched)

# ---------------- 4-LAYER ANTI-BRICK & HASH VERIFIER ---------------- #

def verify_and_hash_file(
    file_path: str,
    expected_size: int = None,
    expected_sha256_bytes: bytes = None,
    expected_crc32: int = None,
    on_progress=None
):
    if not os.path.exists(file_path):
        raise Exception("Anti-Brick Guard: Output file was not created.")

    actual_size = os.path.getsize(file_path)
    if expected_size is not None and actual_size != expected_size:
        raise Exception(
            f"Anti-Brick Guard: Size mismatch! Wrote {actual_size} bytes, but the source requires {expected_size} bytes."
        )
    if actual_size < 64:
        raise Exception(f"Anti-Brick Guard: File is abnormally small ({actual_size} bytes).")

    sha256_hasher = hashlib.sha256()
    crc_val = 0
    header_sample = b""
    hashed = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            if not header_sample:
                header_sample = chunk[:65536]
            sha256_hasher.update(chunk)
            if expected_crc32 is not None:
                crc_val = zlib.crc32(chunk, crc_val)
            hashed += len(chunk)
            if on_progress:
                on_progress(hashed, actual_size)

    # A raw super.img legitimately starts with 4096 zero bytes, so test a larger window.
    if len(header_sample) >= 16384 and header_sample[:16384] == b"\x00" * 16384:
        raise Exception("Anti-Brick Guard: Extracted file header contains only null (0x00) bytes!")

    if header_sample.lstrip().startswith((b"<!DOCTYPE", b"<html", b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error>")):
        raise Exception("Anti-Brick Guard: Remote server returned an HTML/XML error page instead of binary data!")

    if expected_crc32 is not None and (crc_val & 0xFFFFFFFF) != (expected_crc32 & 0xFFFFFFFF):
        raise Exception(
            f"Anti-Brick Guard: ZIP CRC-32 mismatch! Expected {hex(expected_crc32)}, got {hex(crc_val & 0xFFFFFFFF)}."
        )

    if expected_sha256_bytes is not None and sha256_hasher.digest() != expected_sha256_bytes:
        raise Exception("Anti-Brick Guard: Payload SHA-256 cryptographic hash mismatch!")

    def u32(off):
        return struct.unpack_from("<I", header_sample, off)[0] if len(header_sample) >= off + 4 else None

    def u16(off):
        return struct.unpack_from("<H", header_sample, off)[0] if len(header_sample) >= off + 2 else None

    sig = "Verified Raw Binary"
    if header_sample.startswith(b"\x3a\xff\x26\xed"):
        sig = "Android Sparse Image (0xED26FF3A)"
    elif u32(4096) == LP_GEOMETRY_MAGIC:
        sig = "Raw super.img (LP dynamic-partition metadata)"
    elif u32(1024) == 0xE0F5E1E2:
        sig = "EROFS filesystem image"
    elif u16(1080) == 0xEF53:
        sig = "ext4 filesystem image"
    elif u32(1024) == 0xF2F52010:
        sig = "F2FS filesystem image"
    elif header_sample.startswith(b"ANDROID!"):
        sig = "ANDROID! Boot Image (Magic: 0x414E4452)"
    elif header_sample.startswith(b"VNDRBOOT"):
        sig = "VNDRBOOT Vendor Boot (Magic: 0x564E4452)"
    elif header_sample.startswith(b"AVB0"):
        sig = "AVB0 Verified Boot (Magic: 0x41564230)"
    elif b"LK" in header_sample[:128] or header_sample[:4] in (b"\x88\x16\x88\x58", b"BFBF"):
        sig = "Little Kernel (LK) Bootloader Binary"
    elif header_sample.startswith(b"\xd7\xb7\xab\x1e"):
        sig = "DTBO Device Tree Overlay Table"

    return sha256_hasher.hexdigest(), actual_size, sig

# ---------------- VAULT INDEX HELPER ---------------- #

def read_vault_index():
    """Always fetches a fresh copy (force_download) so a stale local cache can never hide
    or overwrite entries."""
    if hf_api.file_exists(repo_id=DATASET_REPO, filename="vault_index.json", repo_type="dataset"):
        local_idx = hf_hub_download(repo_id=DATASET_REPO, filename="vault_index.json", repo_type="dataset",
                                    token=HF_TOKEN, force_download=True)
        with open(local_idx, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def update_vault_index(work_dir: str, entry: dict):
    index_data = {"roms": {}, "images": []}
    try:
        fresh = read_vault_index()
        if fresh:
            index_data = fresh
    except Exception:
        pass

    rom_key = entry["rom_key"]
    index_data["roms"][rom_key] = {
        "device_name": entry["device_name"],
        "codename": entry["codename"],
        "rom_version": entry["rom_version"],
        "rom_category": entry["rom_category"],
        "rom_format": entry["rom_format"],
        "rom_url": entry["rom_url"],
        "rom_filename": entry["rom_filename"],
        "updated_at": entry["timestamp"]
    }

    index_data["images"] = [
        img for img in index_data["images"]
        if not (img.get("rom_key") == rom_key and img.get("target") == entry["target"])
    ]
    index_data["images"].insert(0, entry)

    local_index_out = os.path.join(work_dir, "vault_index.json")
    with open(local_index_out, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2)

    hf_api.upload_file(
        path_or_fileobj=local_index_out,
        path_in_repo="vault_index.json",
        repo_id=DATASET_REPO,
        repo_type="dataset",
        commit_message=f"Vault Index: {entry['device_name']} [{entry['codename']}] - {entry['target']}"
    )

# ---------------- MAIN EXTRACTION WORKER ---------------- #

def run_extraction_worker(job_id: str, raw_url: str, target: str, user_meta: dict):
    job = JOBS[job_id]
    work_dir = f"/tmp/flux_{job_id}"
    os.makedirs(work_dir, exist_ok=True)
    output_path = os.path.join(work_dir, target)
    session = None

    try:
        ensure_dataset_exists()
        start_time = time.time()
        is_gdrive = "drive.google.com" in raw_url or "drive.usercontent.google.com" in raw_url
        want = Want(target)

        job_add_code(
            job_id,
            "STAGE 1: URL & KHWANG9883 DATABASE INITIALIZATION",
            f"# Loaded {len(KHWANG_XIAOMI_MAP)} codenames from KHwang9883/MobileModels (xiaomi_en.md)\n"
            f"# Post-Download IP Rotator Ready (Rotations so far: #{IP_STATE['rotations_count']})\n"
            f"stream_url, rom_filename, total_size = resolve_source(\"{raw_url[:60]}...\")"
        )

        public_url = raw_url
        if is_gdrive:
            g_id = extract_gdrive_id(raw_url)
            if not g_id:
                raise Exception("Invalid Google Drive link: Could not extract File ID.")
            public_url = f"https://drive.google.com/file/d/{g_id}/view"
            stream_url, rom_filename, total_size, session = resolve_gdrive_stream(g_id, job_id)
        else:
            stage(job, "search", 3, "Finding the real download link...")
            page_session = make_session(raw_url, job_id)
            direct_url = find_download_url(page_session, raw_url, job_id)
            check_cancel(job)
            stream_url, rom_filename, total_size, session = resolve_direct_url(direct_url, job_id, page_session)
        check_cancel(job)

        fmt = sniff_format(session, stream_url, rom_filename)
        job_log(job_id, "STREAM", f"Archive type: {fmt.upper()} | Target: {want.name} (matched case-insensitively)")

        job_add_code(
            job_id,
            "STAGE 2: SMART TARGET RESOLVER",
            f"# 1) file named '{want.name}' (also .zst)\n"
            f"# 2) partition '{want.stem}' inside payload.bin (CrAU manifest)\n"
            f"# 3) logical partition '{want.stem}' inside super.img (raw or Android sparse, LP metadata)\n"
            f"# range-capable server -> HTTP Range jumps | no ranges (Google Drive) -> single forward stream"
        )

        if fmt == "tgz":
            info = extract_tgz(job_id, session, stream_url, total_size, rom_filename, want, user_meta, output_path)
        else:
            info = None
            if not is_gdrive and supports_ranges(session, stream_url):
                job_log(job_id, "STREAM", "Server supports HTTP Range → random-access mode.")
                try:
                    info = extract_zip_ranged(job_id, session, stream_url, rom_filename, want, user_meta, output_path)
                except Fatal:
                    raise
                except Exception as e:
                    job_log(job_id, "INFO", f"Range mode failed ({e}) → switching to sequential streaming.")
                    job["cont_skip"] = False
                    stage(job, "search", 2, "Retrying in sequential mode...")
                    stage(job, "cont", 0, "Waiting for the container file...")
                    stage(job, "ext", 0, "Waiting for the target file...")
            else:
                job_log(job_id, "STREAM", "Google Drive / no usable HTTP Range support → sequential streaming mode.")
            if info is None:
                info = extract_zip_sequential(job_id, session, stream_url, total_size, rom_filename, want, user_meta, output_path)

        resolved_meta = info.get("resolved_meta") or reconcile_metadata(user_meta, rom_filename, "", {}, job_id)
        job_log(job_id, "STREAM", f"Source: {info.get('source', '?')}")

        stage(job, "search", 100)
        stage(job, "cont", 100)
        stage(job, "ext", 100)
        check_cancel(job)

        # ---- Bar 4: verification (0-30%) + vault upload (30-100%) ----
        stage(job, "fin", 0, "Running 4-Layer Anti-Brick & SHA-256 Verification...")

        def vprog(done, total):
            check_cancel(job)
            stage(job, "fin", done / max(1, total) * 30, f"Verifying & hashing: {done / MB:.0f} / {total / MB:.0f} MB")

        file_sha256, file_size, file_sig = verify_and_hash_file(
            output_path,
            expected_size=info.get("expected_size"),
            expected_sha256_bytes=info.get("expected_sha"),
            expected_crc32=info.get("expected_crc"),
            on_progress=vprog,
        )

        job_log(job_id, "VERIFY", f"Binary Magic Signature: {file_sig}")
        job_log(job_id, "VERIFY", f"Full File SHA-256 Digest: {file_sha256}")
        stage(job, "fin", 30, "Verified ✓ — preparing vault upload")

        clean_dev = re.sub(r"[^a-zA-Z0-9._-]", "_", resolved_meta["device_name"])[:45]
        clean_code = re.sub(r"[^a-zA-Z0-9._-]", "_", resolved_meta["codename"])
        clean_ver = re.sub(r"[^a-zA-Z0-9._-]", "_", resolved_meta["rom_version"])[:40]
        url_id = hashlib.md5(raw_url.encode()).hexdigest()[:6]
        rom_key = f"{clean_dev}__{clean_code}__{clean_ver}__{url_id}"

        img_repo_path = f"vault_roms/{rom_key}/extracted_imgs/{target}"
        rom_meta_path = f"vault_roms/{rom_key}/rom_info.json"

        job_add_code(
            job_id,
            "STAGE 4: HUGGING FACE VAULT UPLOAD (KHWANG9883 VERIFIED)",
            f"# Vault Device Name: {resolved_meta['device_name']} (Codename: {resolved_meta['codename']})\n"
            f"# Vault ROM Version: {resolved_meta['rom_version']} [{resolved_meta['rom_category']}]\n"
            f"hf_api.upload_file(\n"
            f"    path_or_fileobj='{output_path}',\n"
            f"    path_in_repo='{img_repo_path}',\n"
            f"    repo_id='{DATASET_REPO}',\n"
            f"    repo_type='dataset'\n"
            f")"
        )

        check_cancel(job)  # last point where Cancel is still honoured; after this the upload commits
        job["fin_busy"] = True
        stage(job, "fin", 35, f"Uploading {target} to Vault ({resolved_meta['device_name']}) — cannot cancel now")
        job_log(job_id, "UPLOAD", f"Uploading '{target}' to Hugging Face Dataset '{DATASET_REPO}/{img_repo_path}'...")

        hf_api.upload_file(
            path_or_fileobj=output_path,
            path_in_repo=img_repo_path,
            repo_id=DATASET_REPO,
            repo_type="dataset",
            commit_message=f"Verified {target} for {resolved_meta['device_name']} ({resolved_meta['codename']}) [{resolved_meta['rom_version']}]"
        )

        download_url = hf_hub_url(repo_id=DATASET_REPO, filename=img_repo_path, repo_type="dataset")
        size_mb_str = f"{file_size / MB:.2f} MB"
        stage(job, "fin", 80, "File uploaded ✓ — writing ROM metadata")

        vault_entry = {
            "rom_key": rom_key,
            "device_name": resolved_meta["device_name"],
            "codename": resolved_meta["codename"],
            "rom_version": resolved_meta["rom_version"],
            "rom_category": resolved_meta["rom_category"],
            "rom_format": resolved_meta["rom_format"],
            "auto_status": resolved_meta["auto_status"],
            "rom_url": public_url,
            "rom_filename": rom_filename,
            "target": target,
            "source": info.get("source", ""),
            "sha256": file_sha256,
            "size": size_mb_str,
            "signature": file_sig,
            "download_url": download_url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
        }

        local_meta_file = os.path.join(work_dir, "rom_info.json")
        with open(local_meta_file, "w", encoding="utf-8") as mf:
            json.dump(vault_entry, mf, indent=2)

        hf_api.upload_file(
            path_or_fileobj=local_meta_file,
            path_in_repo=rom_meta_path,
            repo_id=DATASET_REPO,
            repo_type="dataset",
            commit_message=f"ROM Metadata: {resolved_meta['device_name']} ({resolved_meta['rom_version']})"
        )
        stage(job, "fin", 92, "Updating Vault index")

        update_vault_index(work_dir, vault_entry)

        duration_sec = max(1, int(time.time() - start_time))
        job["fin_busy"] = False
        stage(job, "fin", 100, f"Verified & synced to Vault ({duration_sec}s)")
        job_log(job_id, "SUCCESS", f"Vault Upload Complete in {duration_sec}s! Temporary server storage wiped clean.")

        job["result"] = vault_entry
        job["result"]["duration"] = f"{duration_sec}s"
        job["state"] = "done"

    except Cancelled:
        job_log(job_id, "INFO", "Extraction cancelled by user. Temporary files removed; nothing was added to the Vault.")
        job["error"] = "Cancelled"
        job["state"] = "cancelled"
    except Exception as e:
        if job.get("cancel"):
            job_log(job_id, "INFO", "Extraction cancelled by user. Temporary files removed; nothing was added to the Vault.")
            job["error"] = "Cancelled"
            job["state"] = "cancelled"
        else:
            job_log(job_id, "ERROR", str(e))
            job["error"] = str(e)
            job["state"] = "error"
    finally:
        job["fin_busy"] = False
        if session:
            session.close()
        # Rotate IP ONLY after the download has completely stopped so the next job gets a fresh IP
        rotate_ip_after_job(job_id, raw_url)
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
        if os.path.exists("/tmp/hf_cache"):
            shutil.rmtree("/tmp/hf_cache", ignore_errors=True)

# ---------------- API ENDPOINTS ---------------- #

@app.post("/api/start")
def start_job(req: ExtractRequest):
    if not HF_TOKEN:
        raise HTTPException(status_code=500, detail="Missing HF_TOKEN in Render Environment Variables.")
    if not req.rom_url.strip():
        raise HTTPException(status_code=400, detail="Please paste a valid ROM download link.")

    # basename() blocks path traversal like "../../x"; matching itself is case-insensitive
    target = os.path.basename(req.target.strip().replace("\\", "/"))
    if not target:
        raise HTTPException(status_code=400, detail="Please select or type a target file.")
    if "." not in target:
        target += ".img"

    job_id = uuid.uuid4().hex[:12]
    user_meta = {
        "device_name": req.device_name.strip(),
        "rom_version": req.rom_version.strip(),
        "rom_category": req.rom_category.strip().lower(),
        "rom_format": req.rom_format.strip().lower() if req.rom_category.strip().lower() == "stock" else "custom"
    }

    JOBS[job_id] = {
        "state": "running",
        "cancel": False,
        "target": target,
        # Bar 1: locating the file inside the ROM
        "search_progress": 2,
        "search_label": "Connecting to cloud stream...",
        # Bar 2: downloading the container file (super.img / payload.bin) when the target lives inside one
        "cont_progress": 0,
        "cont_label": "Waiting for the file to be located...",
        "cont_name": "",
        "cont_skip": False,
        # Bar 3: extracting the file you asked for
        "ext_progress": 0,
        "ext_label": "Waiting for the target offset...",
        # Bar 4: 4-layer verification + vault upload
        "fin_progress": 0,
        "fin_label": "Waiting for the extracted file...",
        "fin_busy": False,
        "speed": "Connecting...",
        "bytes_streamed_mb": "0.0 MB",
        "hex_offset": "0x00000000",
        "chunks_verified": 0,
        "current_scan": "—",
        "resolved_meta": None,
        "cmd": "# Initializing HYPER//FLUX v9 + KHwang9883 MobileModels Engine...",
        "cmd_history": [],
        "logs": [],
        "result": None,
        "error": None
    }
    threading.Thread(target=run_extraction_worker, args=(job_id, req.rom_url.strip(), target, user_meta), daemon=True).start()
    return {"job_id": job_id}

@app.get("/api/status/{job_id}")
def get_job_status(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job not found.")
    return JSONResponse(JOBS[job_id], headers=NO_STORE)

@app.post("/api/cancel/{job_id}")
def cancel_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    if job["state"] != "running":
        return {"ok": False, "state": job["state"]}
    if job.get("fin_busy"):
        return {"ok": False, "state": "running", "note": "Vault upload already started; it will finish in a few seconds."}
    job["cancel"] = True
    job_log(job_id, "INFO", "Cancel requested — stopping the stream and wiping temporary files...")
    return {"ok": True, "state": "cancelling"}

@app.get("/api/vault")
def list_vault():
    try:
        ensure_dataset_exists()
        data = read_vault_index()
        if data:
            return JSONResponse({
                "roms": list(data.get("roms", {}).values()),
                "images": data.get("images", []),
                "fetched_at": datetime.now().strftime("%H:%M:%S")
            }, headers=NO_STORE)
        return JSONResponse({"roms": [], "images": [], "fetched_at": datetime.now().strftime("%H:%M:%S")}, headers=NO_STORE)
    except Exception as e:
        return JSONResponse({"roms": [], "images": [], "note": str(e)}, headers=NO_STORE)

# ---------------- FRONTEND UI ---------------- #

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ROM DUMPER</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    h1, h2, .brand-font { font-family: 'Space Grotesk', sans-serif; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    :root { --ease: cubic-bezier(0.22, 1, 0.36, 1); }
    html { scroll-behavior: smooth; }
    body {
      background-color: #05050a;
      overflow-x: hidden;
    }

    /* ---------- AMBIENT BACKDROP ---------- */
    .ambient { position: fixed; inset: 0; z-index: 0; pointer-events: none; overflow: hidden; }
    .orb { position: absolute; border-radius: 50%; background: radial-gradient(circle, var(--c) 0%, transparent 68%); opacity: 0.6; will-change: transform; transform: translateZ(0); animation: drift 24s ease-in-out infinite alternate; }
    .orb.o1 { --c: #7c3aed; width: 560px; height: 560px; top: -190px; right: -170px; }
    .orb.o2 { --c: #f59e0b; width: 520px; height: 520px; top: calc(28% - 70px); left: -230px; animation-duration: 30s; animation-delay: -6s; opacity: 0.42; }
    .orb.o3 { --c: #10b981; width: 600px; height: 600px; bottom: -260px; right: calc(5% - 80px); animation-duration: 27s; animation-delay: -12s; opacity: 0.38; }
    .orb.o4 { --c: #ec4899; width: 420px; height: 420px; bottom: calc(22% - 60px); left: calc(30% - 60px); animation-duration: 34s; animation-delay: -3s; opacity: 0.26; }
    @keyframes drift {
      0%   { transform: translate3d(0, 0, 0) scale(1); }
      50%  { transform: translate3d(60px, -70px, 0) scale(1.18); }
      100% { transform: translate3d(-70px, 50px, 0) scale(0.92); }
    }
    .grid-wrap {
      position: absolute; inset: 0;
      mask-image: radial-gradient(ellipse at 50% 30%, #000 20%, transparent 75%);
      -webkit-mask-image: radial-gradient(ellipse at 50% 30%, #000 20%, transparent 75%);
    }
    .grid-glow {
      position: absolute; inset: -46px; will-change: transform;
      background-image: linear-gradient(rgba(255,255,255,0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.035) 1px, transparent 1px);
      background-size: 46px 46px;
      animation: gridpan 40s linear infinite;
    }
    @keyframes gridpan { to { transform: translate3d(46px, 46px, 0); } }
    .spark { position: absolute; width: 3px; height: 3px; border-radius: 50%; background: rgba(253, 230, 138, 0.8); box-shadow: 0 0 10px rgba(253, 230, 138, 0.9); opacity: 0; animation: floatup linear infinite; }
    @keyframes floatup {
      0% { transform: translateY(0) scale(0.6); opacity: 0; }
      15% { opacity: 0.9; }
      100% { transform: translateY(-110vh) scale(1.2); opacity: 0; }
    }

    /* ---------- GLASS ---------- */
    .glass {
      position: relative;
      background: linear-gradient(145deg, rgba(255,255,255,0.09), rgba(255,255,255,0.02));
      backdrop-filter: blur(16px) saturate(150%);
      -webkit-backdrop-filter: blur(16px) saturate(150%);
      border: 1px solid rgba(255,255,255,0.1);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.16), inset 0 -1px 0 rgba(255,255,255,0.03), 0 26px 60px -22px rgba(0,0,0,0.9);
      overflow: hidden;
      transition: border-color 0.4s var(--ease), box-shadow 0.4s var(--ease), transform 0.4s var(--ease);
    }
    .glass::before {
      content: ""; position: absolute; inset: 0; pointer-events: none; opacity: 0;
      background: radial-gradient(280px circle at var(--mx, 50%) var(--my, 50%), rgba(167,139,250,0.2), transparent 62%);
      transition: opacity 0.35s ease;
    }
    .glass:hover::before { opacity: 1; }
    .glass::after {
      content: ""; position: absolute; top: 0; left: 0; width: 40%; height: 100%; pointer-events: none;
      background: linear-gradient(100deg, transparent, rgba(255,255,255,0.07), transparent);
      will-change: transform; transform: translateX(-150%) skewX(-18deg); animation: sheen 9s ease-in-out infinite;
    }
    @keyframes sheen { 0%, 70% { transform: translateX(-150%) skewX(-18deg); } 100% { transform: translateX(350%) skewX(-18deg); } }
    @media (hover: none) { .glass::before { display: none; } }
    .glass:hover { border-color: rgba(167,139,250,0.28); }

    /* ---------- ENTRANCE / VIEW TRANSITIONS ---------- */
    .rise { animation: rise 0.8s var(--ease) both; animation-delay: calc(var(--i, 0) * 90ms); }
    @keyframes rise { from { opacity: 0; transform: translateY(22px) scale(0.98); } to { opacity: 1; transform: none; } }
    .view-in { animation: viewin 0.55s var(--ease) both; }
    @keyframes viewin { from { opacity: 0; transform: translateY(18px) scale(0.985); } to { opacity: 1; transform: none; } }
    .pop-in { animation: popin 0.7s cubic-bezier(0.34, 1.56, 0.64, 1) both; }
    @keyframes popin { from { opacity: 0; transform: scale(0.88) translateY(20px); } to { opacity: 1; transform: none; } }
    .slide-open { animation: slideopen 0.6s var(--ease) both; transform-origin: top; }
    @keyframes slideopen { from { opacity: 0; transform: scaleY(0.92) translateY(-12px); } to { opacity: 1; transform: none; } }

    /* ---------- INPUTS / CHIPS / BUTTONS ---------- */
    .cyber-input {
      background: rgba(6, 6, 12, 0.7);
      border: 1px solid rgba(139, 92, 246, 0.28);
      transition: border-color 0.25s ease, box-shadow 0.3s ease, transform 0.3s var(--ease), background 0.3s ease;
    }
    .cyber-input:focus { border-color: #a78bfa; box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.18), 0 0 28px -6px rgba(139, 92, 246, 0.55); outline: none; transform: translateY(-1px); background: rgba(10, 10, 20, 0.85); }
    .chip-btn {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      transition: all 0.3s var(--ease);
    }
    .chip-btn:hover { transform: translateY(-2px); background: rgba(255,255,255,0.09); border-color: rgba(167,139,250,0.4); }
    .chip-btn:active { transform: scale(0.95); }
    .chip-btn.active {
      background: linear-gradient(135deg, rgba(139, 92, 246, 0.36), rgba(245, 158, 11, 0.3));
      border-color: #f59e0b; color: #fde68a; box-shadow: 0 0 22px -4px rgba(245, 158, 11, 0.55);
      animation: chippulse 0.5s var(--ease);
    }
    @keyframes chippulse { 0% { transform: scale(0.9); } 60% { transform: scale(1.06); } 100% { transform: scale(1); } }
    .form-locked { pointer-events: none !important; user-select: none !important; opacity: 0.42 !important; filter: grayscale(35%); }
    #lockableControls { transition: opacity 0.5s var(--ease), filter 0.5s var(--ease); }

    .btn { position: relative; overflow: hidden; transition: transform 0.3s var(--ease), filter 0.3s ease, box-shadow 0.3s ease; }
    .btn:hover:not(:disabled) { transform: translateY(-2px); filter: brightness(1.1); }
    .btn:active:not(:disabled) { transform: scale(0.97); }
    .btn:disabled { cursor: not-allowed; }
    .ripple { position: absolute; border-radius: 50%; background: rgba(255,255,255,0.5); transform: scale(0); animation: ripple 0.7s ease-out forwards; pointer-events: none; }
    @keyframes ripple { to { transform: scale(4); opacity: 0; } }
    .btn-main { box-shadow: 0 10px 40px -10px rgba(167, 139, 250, 0.7); background-size: 200% 100%; animation: gradflow 6s ease infinite; }
    @keyframes gradflow { 0%, 100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }
    .btn-cancel { background: linear-gradient(135deg, rgba(244,63,94,0.28), rgba(244,63,94,0.12)); border: 1px solid rgba(244,63,94,0.5); color: #fecdd3; box-shadow: 0 0 26px -8px rgba(244,63,94,0.7); }
    .btn-cancel:disabled { opacity: 0.55; box-shadow: none; }

    /* ---------- 4-STAGE PROGRESS ---------- */
    .stage {
      padding: 14px; border-radius: 20px;
      border: 1px solid rgba(255,255,255,0.07);
      background: rgba(0,0,0,0.3);
      opacity: 0.5; transform: scale(0.985);
      transition: all 0.55s var(--ease);
    }
    .stage[data-state="active"] { opacity: 1; transform: none; border-color: rgba(167,139,250,0.55); box-shadow: 0 0 36px -10px rgba(139,92,246,0.75), inset 0 0 24px -14px rgba(167,139,250,0.6); }
    .stage[data-state="done"] { opacity: 1; transform: none; border-color: rgba(52,211,153,0.5); box-shadow: 0 0 28px -12px rgba(52,211,153,0.6); }
    .stage[data-state="skipped"] { opacity: 0.55; transform: none; border-style: dashed; }
    .stage[data-state="error"] { opacity: 1; border-color: rgba(244,63,94,0.65); box-shadow: 0 0 28px -10px rgba(244,63,94,0.6); }
    .stage[data-state="cancelled"] { opacity: 0.7; border-color: rgba(251,191,36,0.5); }
    .stage .ico { display: inline-flex; width: 34px; height: 34px; align-items: center; justify-content: center; border-radius: 12px; background: rgba(255,255,255,0.06); font-size: 16px; flex-shrink: 0; }
    .stage[data-state="active"] .ico { animation: bob 1.8s ease-in-out infinite; background: rgba(139,92,246,0.22); }
    .stage[data-state="done"] .ico { background: rgba(52,211,153,0.2); }
    @keyframes bob { 0%, 100% { transform: translateY(0) rotate(0); } 50% { transform: translateY(-3px) rotate(-6deg); } }
    .chip-state { font-size: 9px; padding: 2px 8px; border-radius: 999px; background: rgba(255,255,255,0.07); color: #94a3b8; letter-spacing: 0.04em; transition: all 0.4s var(--ease); }
    .stage[data-state="active"] .chip-state { background: rgba(167,139,250,0.22); color: #ddd6fe; }
    .stage[data-state="done"] .chip-state { background: rgba(52,211,153,0.2); color: #6ee7b7; }
    .stage[data-state="error"] .chip-state { background: rgba(244,63,94,0.22); color: #fda4af; }
    .stage[data-state="cancelled"] .chip-state { background: rgba(251,191,36,0.2); color: #fde68a; }

    .bar { height: 11px; border-radius: 999px; background: rgba(0,0,0,0.6); overflow: hidden; border: 1px solid rgba(255,255,255,0.08); padding: 1.5px; }
    .bar-fill { height: 100%; width: 0%; border-radius: 999px; position: relative; overflow: hidden; transition: width 0.6s var(--ease); }
    .c-violet { background: linear-gradient(90deg, #7c3aed, #d946ef); }
    .c-sky { background: linear-gradient(90deg, #0ea5e9, #6366f1); }
    .c-amber { background: linear-gradient(90deg, #f59e0b, #f97316); }
    .c-emerald { background: linear-gradient(90deg, #10b981, #2dd4bf); }
    .bar-fill::after {
      content: ""; position: absolute; inset: 0; opacity: 0;
      background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.55) 50%, transparent 100%);
      transform: translateX(-100%);
    }
    .stage[data-state="active"] .bar-fill::after { opacity: 1; animation: shine 1.5s ease-in-out infinite; }
    @keyframes shine { to { transform: translateX(100%); } }
    .stage[data-state="active"] .bar-fill { box-shadow: 0 0 16px 0 rgba(167,139,250,0.7); }
    .bar.indet .bar-fill { width: 100% !important; background-image: repeating-linear-gradient(45deg, rgba(255,255,255,0.28) 0 10px, transparent 10px 20px); background-color: #10b981; animation: stripes 0.9s linear infinite; background-size: 28px 28px; }
    @keyframes stripes { to { background-position: 28px 0; } }
    .stage-line { width: 2px; height: 10px; margin: 0 auto; background: linear-gradient(to bottom, rgba(167,139,250,0.5), transparent); }

    /* ---------- DOCK ---------- */
    .ios-dock {
      background: rgba(18, 18, 30, 0.6);
      backdrop-filter: blur(30px) saturate(180%);
      -webkit-backdrop-filter: blur(30px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.16);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.18), 0 24px 48px -8px rgba(0, 0, 0, 0.9);
      position: relative;
    }
    .dock-btn { position: relative; z-index: 1; transition: color 0.35s ease, transform 0.35s var(--ease); }
    .dock-btn:active { transform: scale(0.92); }
    .dock-btn.active { color: #fff; font-weight: 700; }
    #dockPill { position: absolute; top: 6px; bottom: 6px; left: 0; will-change: transform; border-radius: 20px; background: linear-gradient(135deg, #8b5cf6, #ec4899); box-shadow: 0 8px 26px -6px rgba(236,72,153,0.7); transition: transform 0.5s var(--ease); z-index: 0; }

    /* ---------- MISC ---------- */
    .skeleton { background: linear-gradient(100deg, rgba(255,255,255,0.04) 30%, rgba(255,255,255,0.12) 50%, rgba(255,255,255,0.04) 70%); background-size: 220% 100%; animation: skel 1.3s linear infinite; border-radius: 16px; }
    @keyframes skel { to { background-position: -220% 0; } }
    .spin { animation: spin 0.8s linear infinite; display: inline-block; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .vault-item { animation: rise 0.6s var(--ease) both; animation-delay: calc(var(--i, 0) * 60ms); transition: transform 0.3s var(--ease), border-color 0.3s ease, background 0.3s ease; }
    .vault-item:hover { transform: translateY(-2px) scale(1.01); border-color: rgba(167,139,250,0.35); background: rgba(255,255,255,0.05); }
    #toasts { position: fixed; top: 14px; left: 50%; transform: translateX(-50%); z-index: 100; display: flex; flex-direction: column; gap: 8px; align-items: center; width: calc(100% - 28px); max-width: 420px; pointer-events: none; }
    .toast { pointer-events: auto; padding: 10px 16px; border-radius: 16px; font-size: 12px; backdrop-filter: blur(22px); -webkit-backdrop-filter: blur(22px); border: 1px solid rgba(255,255,255,0.18); background: rgba(20,20,32,0.78); color: #e2e8f0; box-shadow: 0 16px 40px -10px rgba(0,0,0,0.9); animation: toastin 0.55s cubic-bezier(0.34, 1.56, 0.64, 1) both; }
    .toast.out { animation: toastout 0.4s ease forwards; }
    .toast.ok { border-color: rgba(52,211,153,0.5); }
    .toast.warn { border-color: rgba(251,191,36,0.5); }
    .toast.bad { border-color: rgba(244,63,94,0.5); }
    @keyframes toastin { from { opacity: 0; transform: translateY(-20px) scale(0.9); } to { opacity: 1; transform: none; } }
    @keyframes toastout { to { opacity: 0; transform: translateY(-14px) scale(0.92); } }
    .live-dot { animation: ping 1.6s cubic-bezier(0, 0, 0.2, 1) infinite; }
    @keyframes ping { 75%, 100% { transform: scale(2.2); opacity: 0; } }
    .glow-ring { animation: glowring 2.8s ease-in-out infinite; }
    @keyframes glowring { 0%, 100% { box-shadow: 0 0 0 0 rgba(52,211,153,0.0), 0 20px 50px -15px rgba(0,0,0,0.9); } 50% { box-shadow: 0 0 40px 0 rgba(52,211,153,0.28), 0 20px 50px -15px rgba(0,0,0,0.9); } }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-thumb { background: rgba(167,139,250,0.35); border-radius: 99px; }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; transition-duration: 0.01ms !important; }
      .orb, .spark, .grid-wrap { display: none; }
    }
  </style>
</head>
<body class="min-h-screen text-slate-100 p-4 pb-36 selection:bg-violet-500/30">

  <!-- AMBIENT LAYER -->
  <div class="ambient" aria-hidden="true">
    <div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div><div class="orb o4"></div>
    <div class="grid-wrap"><div class="grid-glow"></div></div>
    <div id="sparks"></div>
  </div>

  <div id="toasts"></div>

  <div class="relative z-10 w-full max-w-lg mx-auto pt-2">
    <!-- Top Header -->
    <div class="glass flex items-center justify-between px-4 py-2.5 rounded-2xl mb-4 rise" style="--i:0">
      <div class="flex items-center gap-2.5">
        <span class="relative flex w-2.5 h-2.5">
          <span class="live-dot absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-75"></span>
          <span class="relative inline-flex rounded-full w-2.5 h-2.5 bg-violet-400"></span>
        </span>
        <span class="brand-font font-bold text-sm tracking-wider bg-gradient-to-r from-violet-300 via-purple-400 to-amber-300 bg-clip-text text-transparent">
          ROM DUMPER
        </span>
      </div>
      <span id="lockStatusBadge" class="mono text-[10px] px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 transition-all duration-500">
        MADE BY YASH 
      </span>
    </div>

    <!-- ================= TAB 1: STUDIO ================= -->
    <div id="tabStudio" class="space-y-4">
      <div class="glass rounded-3xl p-5 space-y-4 rise" style="--i:1">
        <div id="lockableControls" class="space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-xs font-bold text-white uppercase tracking-wider mono">01 // Device & ROM Info (Auto-Verified via KHwang9883 DB)</h2>
            <span class="text-[10px] text-amber-300 mono">✨ Unknown Fallback</span>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-[10px] uppercase mono text-slate-400 block mb-1">1. Device Name</label>
              <input id="devName" type="text" placeholder="Auto-detected from ROM" class="cyber-input w-full px-3.5 py-2.5 rounded-xl text-xs mono text-white placeholder-slate-600" />
            </div>
            <div>
              <label class="text-[10px] uppercase mono text-slate-400 block mb-1">2. ROM Version</label>
              <input id="romVer" type="text" placeholder="e.g. OS2.0 / lineage-19.1" class="cyber-input w-full px-3.5 py-2.5 rounded-xl text-xs mono text-white placeholder-slate-600" />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
                            <label class="text-[10px] uppercase mono text-slate-400 block mb-1">3. ROM Category</label>
              <select id="romCat" onchange="toggleFormatOption(this.value)" class="cyber-input w-full px-3.5 py-2.5 rounded-xl text-xs mono text-white">
                <option value="stock">Stock ROM</option>
                <option value="custom">Custom ROM (Lineage / PixelOS / etc.)</option>
              </select>
            </div>
            <div id="formatBox" style="transition: opacity .35s ease, transform .35s ease">
              <label class="text-[10px] uppercase mono text-slate-400 block mb-1">4. Stock Format</label>
              <select id="romFmt" class="cyber-input w-full px-3.5 py-2.5 rounded-xl text-xs mono text-white">
                <option value="fastboot">Fastboot (.tgz)</option>
                <option value="recovery">Recovery (.zip)</option>
              </select>
            </div>
          </div>

          <hr class="border-white/10" />

          <div>
            <label class="text-[10px] uppercase mono text-amber-300 block mb-1">02 // ROM Download Link (Fastboot, Recovery, Custom, Port, G-Drive)</label>
            <input id="romUrl" type="url" placeholder="Paste a ROM link or any download page (SourceForge, PixelDrain, MediaFire...)" class="cyber-input w-full px-3.5 py-3 rounded-xl text-xs mono text-white placeholder-slate-600" />
          </div>

          <div>
            <div class="flex justify-between items-center mb-1.5">
              <label class="text-[10px] uppercase mono text-violet-300">03 // Target Partition / File</label>
              <span id="selectedLabel" class="mono text-xs font-bold text-amber-300">init_boot.img</span>
            </div>
            <div class="grid grid-cols-3 gap-2 mb-2.5" id="chipGrid">
              <button type="button" onclick="pickPart('init_boot.img', this)" class="chip-btn active py-2 px-2 rounded-xl mono text-[11px] text-slate-300">init_boot.img</button>
              <button type="button" onclick="pickPart('boot.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">boot.img</button>
              <button type="button" onclick="pickPart('lk.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">lk.img</button>
              <button type="button" onclick="pickPart('vendor_boot.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">vendor_boot.img</button>
              <button type="button" onclick="pickPart('dtbo.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">dtbo.img</button>
              <button type="button" onclick="pickPart('recovery.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">recovery.img</button>
              <button type="button" onclick="pickPart('vbmeta.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">vbmeta.img</button>
              <button type="button" onclick="pickPart('preloader_raw.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">preloader</button>
              <button type="button" onclick="pickPart('logo.bin', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">logo.bin</button>
              <button type="button" onclick="pickPart('super.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">super.img</button>
              <button type="button" onclick="pickPart('system.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">system.img</button>
              <button type="button" onclick="pickPart('vendor.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">vendor.img</button>
              <button type="button" onclick="pickPart('vendor_dlkm.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">vendor_dlkm.img</button>
              <button type="button" onclick="pickPart('product.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">product.img</button>
              <button type="button" onclick="pickPart('odm.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">odm.img</button>
            </div>
            <input id="customTarget" type="text" placeholder="Or type any file / partition (modem.img, system_ext.img, mi_ext.img...)" oninput="customInput(this.value)" class="cyber-input w-full px-3.5 py-2 rounded-xl text-xs mono text-white placeholder-slate-600" />
            <p class="text-[10px] text-slate-500 mono mt-1.5">Looks for the file, then payload.bin, then inside super.img. Case-insensitive.</p>
          </div>
        </div>

        <button id="launchBtn" onclick="launchExtraction()" class="btn btn-main rip w-full py-3.5 rounded-2xl font-bold text-sm text-slate-950 bg-gradient-to-r from-violet-400 via-purple-400 to-amber-300">
          🛡️ Auto-Verify ROM & Extract Partition
        </button>

        <div id="errBanner" class="hidden text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-2xl p-3.5 mono leading-relaxed"></div>
      </div>

      <!-- LIVE PROGRESS HUD: 4 separate bars -->
      <div id="liveProgressHud" class="hidden glass rounded-3xl p-5 space-y-3 border border-violet-500/30">
        <div class="flex justify-between items-center border-b border-white/10 pb-2.5">
          <div class="flex items-center gap-2">
            <span class="relative flex w-2 h-2">
              <span class="live-dot absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
              <span class="relative inline-flex rounded-full w-2 h-2 bg-amber-400"></span>
            </span>
            <span class="text-xs font-bold text-white">Live Cloud Security HUD</span>
          </div>
          <span id="hudSpeed" class="mono text-xs font-bold text-amber-300">—</span>
        </div>

        <div id="stageList" class="space-y-1"></div>
        <p id="scanEntryText" class="mono text-[10px] text-slate-400 truncate px-1">Inspecting ROM headers...</p>

        <button id="cancelBtn" onclick="cancelExtraction()" class="btn btn-cancel rip w-full py-2.5 rounded-xl mono text-xs font-bold">
          ✖ Cancel extraction
        </button>

        <button onclick="switchView('terminal')" class="btn rip w-full py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 mono text-[11px] text-amber-300">
          💻 Open Full Telemetry & Live Code Console →
        </button>
      </div>

      <!-- VERIFIED DOWNLOAD RESULT CARD -->
      <div id="doneCard" class="hidden glass glow-ring rounded-3xl p-6 border border-emerald-500/40 space-y-4">
        <div class="flex items-center justify-between">
          <span id="doneAutoBadge" class="px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-400/30 text-emerald-300 mono text-[10px] font-semibold">
            ✓ Auto-Verified from ROM
          </span>
          <span id="doneDuration" class="mono text-xs font-bold text-amber-300">0s</span>
        </div>

        <div>
          <h2 id="doneTitle" class="text-lg font-bold text-white">Partition Ready</h2>
          <p id="doneSub" class="text-xs text-slate-400 mt-0.5"></p>
        </div>

        <div class="bg-black/50 rounded-2xl p-3.5 border border-white/5 space-y-2 mono text-[11px]">
          <div class="flex justify-between"><span class="text-slate-400">KHwang9883 Codename:</span><span id="doneCode" class="text-violet-300 font-bold"></span></div>
          <div class="flex justify-between"><span class="text-slate-400">File & Size:</span><span id="doneFileSize" class="text-amber-300 font-bold"></span></div>
          <div class="flex justify-between gap-3"><span class="text-slate-400 shrink-0">Found in:</span><span id="doneSource" class="text-sky-300 text-right break-all"></span></div>
          <div class="flex justify-between"><span class="text-slate-400">Binary Header:</span><span id="doneSig" class="text-emerald-300"></span></div>
          <div>
            <span class="text-slate-400 block mb-0.5">Verified SHA-256 Checksum:</span>
            <span id="doneHash" class="text-[10px] text-violet-300 break-all block bg-white/5 p-2 rounded-lg"></span>
          </div>
        </div>

        <a id="finalDownloadBtn" href="#" target="_blank" class="btn rip w-full py-3.5 rounded-2xl font-bold text-sm text-slate-950 bg-gradient-to-r from-emerald-400 to-teal-300 flex items-center justify-center gap-2 shadow-lg">
          ⬇ Download Verified File
        </a>
      </div>
    </div>

    <!-- ================= TAB 2: VAULT ================= -->
    <div id="tabVault" class="hidden space-y-4">
      <div class="glass rounded-3xl p-5 space-y-4">
        <div class="flex justify-between items-center">
          <div>
            <h2 class="text-base font-bold text-white">🗄️ Permanent Dataset Vault</h2>
            <p id="vaultSub" class="text-[11px] text-slate-400">Verified via KHwang9883 DB (Unlisted devices marked 'Unknown')</p>
          </div>
          <button id="refreshBtn" onclick="loadVault(true)" class="btn rip mono text-[11px] px-3.5 py-2 rounded-xl bg-white/5 text-amber-300 border border-white/10 flex items-center gap-1.5">
            <span id="refreshIco">⟳</span><span id="refreshTxt">Refresh</span>
          </button>
        </div>

        <div>
          <h3 class="mono text-xs uppercase text-violet-300 mb-2 font-semibold">1. Saved ROMs (Device, Codename & Version)</h3>
          <div id="romVaultList" class="space-y-2 max-h-56 overflow-y-auto pr-1">
            <div class="skeleton h-14"></div>
          </div>
        </div>

        <hr class="border-white/10" />

        <div>
          <h3 class="mono text-xs uppercase text-emerald-300 mb-2 font-semibold">2. Verified Extracted Files (SHA-256 Matched)</h3>
          <div id="imgVaultList" class="space-y-2.5 max-h-72 overflow-y-auto pr-1">
            <div class="skeleton h-20"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ================= TAB 3: TELEMETRY & CONSOLE ================= -->
    <div id="tabTerminal" class="hidden space-y-4">
      <div class="grid grid-cols-2 gap-2.5">
        <div class="glass rounded-2xl p-3.5 rise" style="--i:0">
          <span class="mono text-[10px] uppercase text-slate-400 block">Live Bandwidth</span>
          <span id="conSpeed" class="mono text-sm font-bold text-amber-300 mt-0.5 block">—</span>
        </div>
        <div class="glass rounded-2xl p-3.5 rise" style="--i:1">
          <span class="mono text-[10px] uppercase text-slate-400 block">Streamed / Offset</span>
          <span id="conOffset" class="mono text-sm font-bold text-violet-300 mt-0.5 block">0 MB (0x00)</span>
        </div>
        <div class="glass rounded-2xl p-3.5 rise" style="--i:2">
          <span class="mono text-[10px] uppercase text-slate-400 block">Entries / Chunks Verified</span>
          <span id="conChunks" class="mono text-sm font-bold text-emerald-400 mt-0.5 block">0</span>
        </div>
        <div class="glass rounded-2xl p-3.5 rise" style="--i:3">
          <span class="mono text-[10px] uppercase text-slate-400 block">Current Stream Entry</span>
          <span id="conScan" class="mono text-xs font-semibold text-sky-300 mt-0.5 block truncate">—</span>
        </div>
      </div>

      <div class="glass rounded-3xl p-4 space-y-2 rise" style="--i:4">
        <div class="flex items-center justify-between">
          <span class="mono text-[11px] uppercase text-amber-300 font-bold">✨ KHwang9883 DB Auto-Metadata Inspector</span>
          <span id="metaStatusBadge" class="mono text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">Standby</span>
        </div>
        <div class="grid grid-cols-2 gap-2 mono text-[11px] bg-black/50 p-3 rounded-2xl border border-white/5">
          <div>
            <span class="text-[10px] text-slate-400 block">User Typed:</span>
            <span id="metaUserTyped" class="text-slate-300 truncate block">—</span>
          </div>
          <div>
            <span class="text-[10px] text-slate-400 block">Vault Truth (xiaomi_en.md):</span>
            <span id="metaAutoTruth" class="text-emerald-300 font-bold truncate block">—</span>
          </div>
        </div>
      </div>

      <div class="glass rounded-3xl p-4 space-y-2 rise" style="--i:5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
            <span class="mono text-[11px] font-bold text-violet-300 ml-1">Live Executed Engine Code</span>
          </div>
          <span class="mono text-[10px] px-2 py-0.5 rounded bg-white/5 text-slate-400">Python 3.11 Pipeline</span>
        </div>
        <pre id="cmdViewer" class="mono text-[10.5px] leading-relaxed text-amber-200 bg-black/70 p-3.5 rounded-2xl border border-white/5 overflow-x-auto max-h-56 overflow-y-auto"># Launch an extraction to watch every Python stage execute in real time...</pre>
      </div>

      <div class="glass rounded-3xl p-4 space-y-2 rise" style="--i:6">
        <div class="flex items-center justify-between">
          <span class="mono text-[11px] font-bold text-emerald-300 uppercase">Full Telemetry Terminal Log</span>
          <button onclick="document.getElementById('logBox').innerHTML=''" class="mono text-[10px] text-slate-400 hover:text-white transition">Clear</button>
        </div>
        <div id="logBox" class="mono text-[10.5px] bg-black/75 rounded-2xl p-3.5 h-64 overflow-y-auto space-y-1.5 border border-white/5">
          <div class="text-slate-500">[System] HYPER//FLUX v9 + Post-Download IP Rotator Ready.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- GLASS DOCK + TELEGRAM CIRCLE BUTTON -->
  <div class="fixed bottom-3 inset-x-0 mx-auto z-50 flex flex-col items-center gap-1.5 w-full max-w-md px-4 rise" style="--i:3">
    <div class="flex items-center w-full gap-2.5">
      <div id="dock" class="ios-dock p-1.5 rounded-[26px] flex items-center justify-between flex-1 gap-1">
        <span id="dockPill"></span>
        <button id="btnStudio" onclick="switchView('studio')" class="dock-btn active flex-1 py-2.5 rounded-[20px] text-xs">⚡ Studio</button>
        <button id="btnVault" onclick="switchView('vault')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">🗄️ Vault</button>
        <button id="btnTerminal" onclick="switchView('terminal')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">💻 Console</button>
      </div>

      <a
        href="https://t.me/NotYash01"
        target="_blank"
        rel="noopener noreferrer"
        title="Telegram @NotYash01"
        aria-label="Open Telegram @NotYash01"
        class="ios-dock btn rip w-12 h-12 rounded-full shrink-0 flex items-center justify-center border border-sky-400/35 hover:border-sky-400/80 shadow-[0_0_25px_-5px_rgba(56,189,248,0.55)] active:scale-90 transition-all duration-300 group"
      >
        <svg class="w-5 h-5 text-sky-400 group-hover:text-sky-300 group-hover:scale-110 transition-transform duration-300 -translate-x-0.5" viewBox="0 0 24 24" fill="currentColor">
          <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
        </svg>
      </a>
    </div>
  </div>

  <script>
    let currentPart = "init_boot.img";
    let pollTimer = null;
    let renderedLogs = 0;
    let currentJob = null;
    let cancelling = false;
    let vaultBusy = false;

    const STAGES = [
      { k: "search", ico: "🔎", color: "c-violet" },
      { k: "cont",   ico: "📦", color: "c-sky" },
      { k: "ext",    ico: "🎯", color: "c-amber" },
      { k: "fin",    ico: "🛡️", color: "c-emerald" }
    ];

    /* ---------- helpers ---------- */
    function esc(s) {
      return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function toast(msg, kind) {
      const box = document.getElementById("toasts");
      const t = document.createElement("div");
      t.className = "toast " + (kind || "");
      t.textContent = msg;
      box.appendChild(t);
      setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 450); }, 3200);
    }

    function setText(el, v) {
      v = String(v);
      if (!el._t) { el.textContent = ""; el._t = document.createTextNode(""); el.appendChild(el._t); }
      if (el._t.nodeValue !== v) el._t.nodeValue = v;
    }

    function tween(el, to) {
      if (el._v === to) return;
      const from = el._v || 0;
      el._v = to;
      if (el._raf) cancelAnimationFrame(el._raf);
      const t0 = performance.now(), d = 450;
      function f(t) {
        const p = Math.min(1, (t - t0) / d);
        setText(el, Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))) + "%");
        if (p < 1) el._raf = requestAnimationFrame(f);
      }
      el._raf = requestAnimationFrame(f);
    }

    let moveRaf = 0;
    document.addEventListener("pointermove", (e) => {
      if (e.pointerType === "touch" || moveRaf) return;
      const x = e.clientX, y = e.clientY, tgt = e.target;
      moveRaf = requestAnimationFrame(() => {
        moveRaf = 0;
        const g = tgt.closest ? tgt.closest(".glass") : null;
        if (!g) return;
        const r = g.getBoundingClientRect();
        g.style.setProperty("--mx", (x - r.left) + "px");
        g.style.setProperty("--my", (y - r.top) + "px");
      });
    });

    document.addEventListener("click", (e) => {
      const b = e.target.closest ? e.target.closest(".rip") : null;
      if (!b || b.disabled) return;
      const r = b.getBoundingClientRect();
      const s = document.createElement("span");
      const size = Math.max(r.width, r.height);
      s.className = "ripple";
      s.style.width = s.style.height = size + "px";
      s.style.left = (e.clientX - r.left - size / 2) + "px";
      s.style.top = (e.clientY - r.top - size / 2) + "px";
      b.appendChild(s);
      setTimeout(() => s.remove(), 750);
    });

    function buildSparks() {
      const box = document.getElementById("sparks");
      for (let i = 0; i < 16; i++) {
        const s = document.createElement("span");
        s.className = "spark";
        s.style.left = (Math.random() * 100) + "%";
        s.style.bottom = (-Math.random() * 20) + "%";
        s.style.animationDuration = (14 + Math.random() * 18) + "s";
        s.style.animationDelay = (-Math.random() * 25) + "s";
        box.appendChild(s);
      }
    }

    /* ---------- stages ---------- */
    function renderStages() {
      const list = document.getElementById("stageList");
      list.innerHTML = STAGES.map((s, i) => `
        <div class="stage" id="st-${s.k}" data-state="waiting">
          <div class="flex items-center gap-3 mb-2.5">
            <span class="ico">${s.ico}</span>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="text-xs font-bold text-white truncate" id="st-${s.k}-title"></span>
                <span class="chip-state mono" id="st-${s.k}-chip">WAITING</span>
              </div>
              <div class="mono text-[10px] text-slate-400 truncate mt-0.5" id="st-${s.k}-sub">—</div>
            </div>
            <span class="mono text-sm font-bold text-white" id="st-${s.k}-pct">0%</span>
          </div>
          <div class="bar" id="st-${s.k}-barwrap"><div class="bar-fill ${s.color}" id="st-${s.k}-bar"></div></div>
        </div>
        ${i < STAGES.length - 1 ? '<div class="stage-line"></div>' : ''}
      `).join("");
      setStageTitles("", "");
    }

    function setStageTitles(container, target) {
      const t = {
        search: "1 · Locating the file",
        cont: container ? "2 · Downloading " + container : "2 · Downloading the container file",
        ext: target ? "3 · Extracting " + target : "3 · Extracting your file",
        fin: "4 · Verify & upload to Vault"
      };
      STAGES.forEach(s => {
        const el = document.getElementById("st-" + s.k + "-title");
        if (el && el.textContent !== t[s.k]) el.textContent = t[s.k];
      });
    }

    const CHIP = { waiting: "WAITING", active: "WORKING", done: "DONE ✓", skipped: "SKIPPED", error: "FAILED", cancelled: "STOPPED" };

    function paintStage(k, pct, label, state, indet) {
      const card = document.getElementById("st-" + k);
      if (!card) return;
      if (card.dataset.state !== state) {
        card.dataset.state = state;
        setText(document.getElementById("st-" + k + "-chip"), CHIP[state]);
      }
      const bar = document.getElementById("st-" + k + "-bar");
      bar.style.width = pct + "%";
      document.getElementById("st-" + k + "-barwrap").classList.toggle("indet", !!indet);
      tween(document.getElementById("st-" + k + "-pct"), pct);
      setText(document.getElementById("st-" + k + "-sub"), label);
    }

    function applyStages(job) {
      setStageTitles(job.cont_name, job.target);
      let prevDone = true;
      STAGES.forEach(s => {
        const pct = job[s.k + "_progress"] || 0;
        const label = job[s.k + "_label"] || "";
        let state = "waiting";
        const skipped = s.k === "cont" && job.cont_skip;
        if (skipped) state = "skipped";
        else if (pct >= 100) state = "done";
        else if (pct > 0 || prevDone || s.k === "search") state = "active";
        if (job.state === "error" && state === "active") state = "error";
        if (job.state === "cancelled" && state === "active") state = "cancelled";
        if (job.state !== "running" && job.state !== "done" && state === "waiting") state = "waiting";
        paintStage(s.k, skipped ? 100 : pct, label, state, s.k === "fin" && job.fin_busy && job.state === "running");
        prevDone = skipped || pct >= 100;
      });
    }

    /* ---------- form / views ---------- */
    function setFormLocked(locked) {
      const wrap = document.getElementById("lockableControls");
      const badge = document.getElementById("lockStatusBadge");
      const inputs = wrap.querySelectorAll("input, select, button");
      inputs.forEach(el => el.disabled = locked);

      if (locked) {
        wrap.classList.add("form-locked");
        badge.textContent = "🔒 Locked (Extracting)";
        badge.className = "mono text-[10px] px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 transition-all duration-500";
      } else {
        wrap.classList.remove("form-locked");
        badge.textContent = "MADE BY YASH";
        badge.className = "mono text-[10px] px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 transition-all duration-500";
      }
    }

    function movePill(view) {
      const cap = view.charAt(0).toUpperCase() + view.slice(1);
      const btn = document.getElementById("btn" + cap);
      const pill = document.getElementById("dockPill");
      pill.style.width = btn.offsetWidth + "px";
      pill.style.transform = "translateX(" + btn.offsetLeft + "px)";
    }

    function switchView(view) {
      ["Studio", "Vault", "Terminal"].forEach(v => {
        document.getElementById("tab" + v).classList.add("hidden");
        const b = document.getElementById("btn" + v);
        b.classList.remove("active"); b.classList.add("text-slate-300");
      });
      const cap = view.charAt(0).toUpperCase() + view.slice(1);
      const tab = document.getElementById("tab" + cap);
      tab.classList.remove("hidden");
      tab.classList.remove("view-in");
      void tab.offsetWidth;
      tab.classList.add("view-in");
      const activeBtn = document.getElementById("btn" + cap);
      activeBtn.classList.add("active"); activeBtn.classList.remove("text-slate-300");
      movePill(view);
      window.scrollTo({ top: 0, behavior: "smooth" });
      if (view === "vault") loadVault(false);
    }

    function toggleFormatOption(val) {
      const box = document.getElementById("formatBox");
      if (val === "custom") {
        box.style.opacity = "0"; box.style.transform = "scale(0.95)";
        setTimeout(() => { if (document.getElementById("romCat").value === "custom") box.style.display = "none"; }, 320);
      } else {
        box.style.display = "block";
        void box.offsetWidth;
        box.style.opacity = "1"; box.style.transform = "none";
      }
    }

    function pickPart(part, el) {
      currentPart = part;
      document.getElementById("selectedLabel").textContent = part;
      document.getElementById("customTarget").value = "";
      document.querySelectorAll("#chipGrid .chip-btn").forEach(b => b.classList.remove("active"));
      el.classList.add("active");
    }

    function customInput(val) {
      if (val.trim()) {
        currentPart = val.trim();
        document.getElementById("selectedLabel").textContent = currentPart;
        document.querySelectorAll("#chipGrid .chip-btn").forEach(b => b.classList.remove("active"));
      }
    }

    function resetLaunchUI() {
      const btn = document.getElementById("launchBtn");
      setFormLocked(false);
      btn.disabled = false;
      btn.innerHTML = "🛡️ Auto-Verify ROM & Extract Partition";
      const c = document.getElementById("cancelBtn");
      c.disabled = false;
      c.innerHTML = "✖ Cancel extraction";
      cancelling = false;
    }

    function stopPolling() {
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    /* ---------- launch / cancel ---------- */
    async function launchExtraction() {
      const devName = document.getElementById("devName").value.trim();
      const romVer = document.getElementById("romVer").value.trim();
      const romCat = document.getElementById("romCat").value;
      const romFmt = document.getElementById("romFmt").value;
      const romUrl = document.getElementById("romUrl").value.trim();
      const errBanner = document.getElementById("errBanner");
      const btn = document.getElementById("launchBtn");

      errBanner.classList.add("hidden");
      if (!romUrl) {
        errBanner.textContent = "Please paste a valid ROM download link.";
        errBanner.classList.remove("hidden");
        errBanner.classList.add("slide-open");
        toast("Paste a ROM link first", "warn");
        return;
      }

      setFormLocked(true);
      btn.disabled = true;
      btn.innerHTML = "<span class='spin'>⟳</span> Working — see the live bars below";

      document.getElementById("doneCard").classList.add("hidden");
      const hud = document.getElementById("liveProgressHud");
      hud.classList.remove("hidden");
      hud.classList.remove("slide-open");
      void hud.offsetWidth;
      hud.classList.add("slide-open");
      renderStages();
      document.getElementById("logBox").innerHTML = "";
      renderedLogs = 0;
      cancelling = false;

      try {
        const res = await fetch("/api/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            rom_url: romUrl, target: currentPart,
            device_name: devName, rom_version: romVer,
            rom_category: romCat, rom_format: romFmt
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to start extraction");

        currentJob = data.job_id;
        stopPolling();
        pollTimer = setInterval(() => pollJobStatus(data.job_id), 400);
        pollJobStatus(data.job_id);
      } catch (e) {
        errBanner.textContent = e.message;
        errBanner.classList.remove("hidden");
        errBanner.classList.add("slide-open");
        toast(e.message, "bad");
        hud.classList.add("hidden");
        resetLaunchUI();
      }
    }

    async function cancelExtraction() {
      if (!currentJob || cancelling) return;
      cancelling = true;
      const b = document.getElementById("cancelBtn");
      b.disabled = true;
      b.innerHTML = "<span class='spin'>⟳</span> Cancelling…";
      try {
        const res = await fetch("/api/cancel/" + currentJob, { method: "POST" });
        const data = await res.json();
        if (data && data.ok === false && data.note) {
          toast(data.note, "warn");
          cancelling = false;
          b.innerHTML = "Finalizing — cannot cancel now";
        }
      } catch (e) {
        cancelling = false;
        b.disabled = false;
        b.innerHTML = "✖ Cancel extraction";
        toast("Could not reach the server to cancel", "bad");
      }
    }

    /* ---------- polling ---------- */
    let pollBusy = false;
    async function pollJobStatus(jobId) {
      if (pollBusy) return;
      pollBusy = true;
      const errBanner = document.getElementById("errBanner");
      try {
        const res = await fetch("/api/status/" + jobId, { cache: "no-store" });
        if (!res.ok) return;
        const job = await res.json();

        applyStages(job);
        setText(document.getElementById("scanEntryText"), job.current_scan !== "—" ? "Scanning: " + job.current_scan : "Streaming in cloud RAM (0 MB client data used)");
        setText(document.getElementById("hudSpeed"), job.speed);

        setText(document.getElementById("conSpeed"), job.speed);
        setText(document.getElementById("conOffset"), job.bytes_streamed_mb + " (" + job.hex_offset + ")");
        setText(document.getElementById("conChunks"), job.chunks_verified);
        setText(document.getElementById("conScan"), job.current_scan);
        setText(document.getElementById("cmdViewer"), job.cmd);

        const cb = document.getElementById("cancelBtn");
        if (job.state === "running" && !cancelling) {
          if (job.fin_busy) { cb.disabled = true; cb.innerHTML = "Finalizing upload — cannot cancel now"; }
          else { cb.disabled = false; cb.innerHTML = "✖ Cancel extraction"; }
        }

        if (job.resolved_meta) {
          const rm = job.resolved_meta;
          document.getElementById("metaUserTyped").textContent = rm.user_input_summary;
          document.getElementById("metaAutoTruth").textContent = rm.device_name + " [" + rm.codename + "] • " + rm.rom_version;
          document.getElementById("metaStatusBadge").textContent = rm.device_name === "Unknown" ? "Marked Unknown ⚠️" : "KHwang9883 Match ✓";
        }

        const logBox = document.getElementById("logBox");
        while (renderedLogs < job.logs.length) {
          const item = job.logs[renderedLogs++];
          const d = document.createElement("div");
          const colorMap = {
            ERROR: "text-rose-400 font-bold",
            SUCCESS: "text-emerald-400 font-bold",
            META: "text-amber-300 font-semibold",
            VERIFY: "text-violet-300 font-semibold",
            CHUNK: "text-sky-300",
            HTTP: "text-cyan-300",
            UPLOAD: "text-emerald-300"
          };
          d.className = (colorMap[item.level] || "text-slate-300") + " view-in";
          d.textContent = "[" + item.ts + "] [" + item.level + "] " + item.message;
          logBox.appendChild(d);
          logBox.scrollTop = logBox.scrollHeight;
        }

        if (job.state === "done" && job.result) {
          stopPolling();
          resetLaunchUI();

          const r = job.result;
          document.getElementById("devName").value = r.device_name;
          document.getElementById("romVer").value = r.rom_version;

          const card = document.getElementById("doneCard");
          card.classList.remove("hidden");
          card.classList.remove("pop-in");
          void card.offsetWidth;
          card.classList.add("pop-in");
          document.getElementById("doneAutoBadge").textContent = "✨ " + r.auto_status;
          document.getElementById("doneDuration").textContent = r.duration;
          document.getElementById("doneTitle").textContent = r.device_name + " — " + r.target;
          document.getElementById("doneSub").textContent = r.rom_version + " • " + r.rom_category + " (" + r.rom_format + ")";
          document.getElementById("doneCode").textContent = r.codename;
          document.getElementById("doneFileSize").textContent = r.target + " (" + r.size + ")";
          document.getElementById("doneSource").textContent = r.source || "—";
          document.getElementById("doneSig").textContent = r.signature;
          document.getElementById("doneHash").textContent = r.sha256;
          document.getElementById("finalDownloadBtn").href = r.download_url;
          toast("Verified & saved to the Vault ✓", "ok");
          setTimeout(() => card.scrollIntoView({ behavior: "smooth", block: "center" }), 250);
        } else if (job.state === "cancelled") {
          stopPolling();
          resetLaunchUI();
          errBanner.textContent = "Cancelled. Temporary files were removed and nothing was added to the Vault.";
          errBanner.classList.remove("hidden");
          errBanner.classList.remove("slide-open");
          void errBanner.offsetWidth;
          errBanner.classList.add("slide-open");
          toast("Extraction cancelled", "warn");
        } else if (job.state === "error") {
          stopPolling();
          resetLaunchUI();
          errBanner.textContent = job.error || "Extraction failed.";
          errBanner.classList.remove("hidden");
          errBanner.classList.remove("slide-open");
          void errBanner.offsetWidth;
          errBanner.classList.add("slide-open");
          toast("Extraction failed", "bad");
        }
      } catch (ignore) {} finally { pollBusy = false; }
    }

    /* ---------- vault ---------- */
    async function loadVault(manual) {
      if (vaultBusy) return;
      vaultBusy = true;
      const ico = document.getElementById("refreshIco");
      const txt = document.getElementById("refreshTxt");
      const btn = document.getElementById("refreshBtn");
      const romBox = document.getElementById("romVaultList");
      const imgBox = document.getElementById("imgVaultList");
      btn.disabled = true;
      ico.classList.add("spin");
      txt.textContent = "Syncing…";
      if (manual) {
        romBox.innerHTML = '<div class="skeleton h-14"></div>';
        imgBox.innerHTML = '<div class="skeleton h-20"></div><div class="skeleton h-20"></div>';
      }
      try {
        const res = await fetch("/api/vault?t=" + Date.now(), { cache: "no-store" });
        const data = await res.json();

        if (!data.roms || data.roms.length === 0) {
          romBox.innerHTML = '<div class="text-xs text-slate-500 mono py-3 text-center">No ROMs saved in Vault yet.</div>';
        } else {
          romBox.innerHTML = data.roms.map((r, i) => `
            <div class="vault-item flex items-center justify-between p-3 rounded-2xl bg-black/40 border border-white/5" style="--i:${i}">
              <div class="pr-2 overflow-hidden">
                <div class="text-xs font-bold text-white">${esc(r.device_name)} <span class="mono text-violet-300">[${esc(r.codename)}]</span></div>
                <div class="mono text-[10px] text-amber-300">${esc(r.rom_version)} • ${esc(r.rom_category)} (${esc(r.rom_format)})</div>
              </div>
              <a href="${esc(r.rom_url)}" target="_blank" class="btn shrink-0 px-3 py-1.5 rounded-xl bg-violet-500/20 text-violet-300 border border-violet-400/30 mono text-[10px] font-semibold">
                ⬇ Full ROM
              </a>
            </div>
          `).join("");
        }

        if (!data.images || data.images.length === 0) {
          imgBox.innerHTML = '<div class="text-xs text-slate-500 mono py-4 text-center">No extracted files in Vault yet.</div>';
        } else {
          imgBox.innerHTML = data.images.map((img, i) => `
            <div class="vault-item p-3.5 rounded-2xl bg-black/45 border border-white/5 space-y-2" style="--i:${i}">
              <div class="flex items-center justify-between gap-2">
                <div class="min-w-0">
                  <span class="mono text-xs font-bold text-amber-300">${esc(img.target)}</span>
                  <span class="mono text-[10px] text-slate-400 ml-1.5">(${esc(img.size)})</span>
                  <div class="text-xs font-semibold text-white mt-0.5">${esc(img.device_name)} <span class="mono text-violet-300">[${esc(img.codename)}]</span></div>
                  <div class="mono text-[10px] text-slate-400">${esc(img.rom_version)} • ${esc(img.rom_category)} (${esc(img.rom_format)})</div>
                  <div class="mono text-[10px] text-sky-300 truncate">${esc(img.source || "")}</div>
                </div>
                <a href="${esc(img.download_url)}" target="_blank" class="btn shrink-0 px-3.5 py-2 rounded-xl bg-emerald-500/20 text-emerald-300 border border-emerald-400/30 mono text-[11px] font-bold">
                  ⬇ Get
                </a>
              </div>
              <div class="mono text-[9px] text-slate-400 bg-white/5 px-2.5 py-1 rounded-lg truncate">
                SHA256: <span class="text-emerald-300">${esc(img.sha256)}</span>
              </div>
            </div>
          `).join("");
        }

        document.getElementById("vaultSub").textContent = "Synced " + (data.fetched_at || "just now") + " • " + (data.roms || []).length + " ROMs • " + (data.images || []).length + " files";
        if (data.note) toast("Vault note: " + data.note, "warn");
        else if (manual) toast("Vault refreshed ✓", "ok");
      } catch (e) {
        romBox.innerHTML = '<div class="text-xs text-rose-300 mono py-3 text-center">Could not load the Vault. Tap Refresh to retry.</div>';
        imgBox.innerHTML = "";
        toast("Vault refresh failed", "bad");
      } finally {
        vaultBusy = false;
        btn.disabled = false;
        ico.classList.remove("spin");
        txt.textContent = "Refresh";
      }
    }

    /* ---------- boot ---------- */
    buildSparks();
    renderStages();
    window.addEventListener("load", () => movePill("studio"));
    window.addEventListener("resize", () => {
      const active = ["studio", "vault", "terminal"].find(v => document.getElementById("btn" + v.charAt(0).toUpperCase() + v.slice(1)).classList.contains("active"));
      if (active) movePill(active);
    });
    setTimeout(() => movePill("studio"), 120);
  </script>
</body>
</html>
"""

from dna_manager import setup_dna_manager
HTML_PAGE = setup_dna_manager(app, HTML_PAGE, JOBS, hf_api, DATASET_REPO, HF_TOKEN)

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return HTML_PAGE



@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return HTML_PAGE
