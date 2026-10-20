import os
import re
import bz2
import lzma
import time
import uuid
import struct
import shutil
import tarfile
import hashlib
import threading
import requests
import zstandard as zstd
from datetime import datetime
from urllib.parse import urlparse, unquote
from remotezip import RemoteZip
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import HfApi, hf_hub_url

app = FastAPI(title="HYPER//FLUX ROM Engine")

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

class ExtractRequest(BaseModel):
    rom_url: str
    target: str

def ensure_dataset_exists():
    if not HF_TOKEN or not DATASET_REPO:
        return
    try:
        hf_api.create_repo(repo_id=DATASET_REPO, repo_type="dataset", private=False, exist_ok=True)
    except Exception as e:
        print(f"Dataset auto-init note: {e}")

@app.on_event("startup")
def on_startup():
    threading.Thread(target=ensure_dataset_exists, daemon=True).start()

def job_log(job_id: str, level: str, message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    JOBS[job_id]["logs"].append({"ts": ts, "level": level, "message": message})

class LiveStreamTracker:
    def __init__(self, raw_stream, total_size: int, job_id: str):
        self.raw = raw_stream
        self.total_size = total_size
        self.job_id = job_id
        self.bytes_read = 0
        self.start_time = time.time()
        self.last_update = 0.0

    def read(self, size=-1):
        chunk = self.raw.read(size)
        if chunk:
            self.bytes_read += len(chunk)
            now = time.time()
            if now - self.last_update >= 0.35:
                elapsed = max(0.05, now - self.start_time)
                mbps = (self.bytes_read * 8) / (elapsed * 1_000_000)
                mb_done = self.bytes_read / (1024 * 1024)
                if self.total_size > 0:
                    mb_total = self.total_size / (1024 * 1024)
                    pct = min(99, int((self.bytes_read / self.total_size) * 100))
                    JOBS[self.job_id]["rom_progress"] = pct
                    JOBS[self.job_id]["rom_label"] = f"Cloud Scanning ROM: {mb_done:.0f} MB / {mb_total:.0f} MB"
                else:
                    JOBS[self.job_id]["rom_progress"] = min(95, int(mb_done / 40))
                    JOBS[self.job_id]["rom_label"] = f"Cloud Scanning ROM: {mb_done:.0f} MB streamed"
                JOBS[self.job_id]["speed"] = f"{mbps:.0f} Mbps"
                self.last_update = now
        return chunk

    def close(self):
        if hasattr(self.raw, "close"):
            self.raw.close()

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

def resolve_direct_url(url: str, job_id: str):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    
    parsed = urlparse(url)
    if parsed.netloc in ("bigota.d.miui.com", "hugeota.d.miui.com"):
        fast_mirror = f"https://bkt-sgp-miui-ota-update-alisgp.oss-ap-southeast-1.aliyuncs.com{parsed.path}"
        try:
            r = session.head(fast_mirror, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                job_log(job_id, "STREAM", "Switched to High-Speed Singapore CDN mirror!")
                url = fast_mirror
        except Exception:
            pass

    resp = session.get(url, stream=True, allow_redirects=True, timeout=30)
    if resp.status_code >= 400:
        resp.close()
        raise Exception(f"ROM Server returned HTTP {resp.status_code}.")

    final_url = resp.url
    total_size = int(resp.headers.get("Content-Length", 0) or 0)
    filename = parse_filename_from_cd(resp.headers.get("Content-Disposition", ""))
    resp.close()

    if not filename:
        filename = unquote(os.path.basename(urlparse(final_url).path))
    if not filename:
        filename = unquote(os.path.basename(urlparse(url).path))
    return final_url, filename, total_size, session

def resolve_gdrive_stream(file_id: str):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    direct_url = f"https://drive.usercontent.google.com/download?id={file_id}&export=download&confirm=t"
    resp = session.get(direct_url, stream=True, timeout=30)
    if "text/html" in resp.headers.get("Content-Type", ""):
        html = resp.text
        resp.close()
        uuid_match = re.search(r'name="uuid"\s+value="([^"]+)"', html)
        if uuid_match:
            direct_url = f"https://drive.usercontent.google.com/download?id={file_id}&export=download&confirm=t&uuid={uuid_match.group(1)}"
            resp = session.get(direct_url, stream=True, timeout=30)
    if resp.status_code != 200:
        resp.close()
        raise Exception("Unable to access Google Drive file. Check sharing permissions.")
    filename = parse_filename_from_cd(resp.headers.get("Content-Disposition", ""))
    total_size = int(resp.headers.get("Content-Length", 0) or 0)
    resp.close()
    if not filename:
        filename = "rom_archive.zip"
    return direct_url, filename, total_size, session

def verify_file_integrity(file_path: str):
    if not os.path.exists(file_path):
        raise Exception("Extraction failed: File was not created.")
    size = os.path.getsize(file_path)
    if size < 128:
        raise Exception(f"Extracted file is abnormally small ({size} bytes).")

# Protobuf parsers for payload.bin
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
            raise ValueError(f"Unsupported wire type: {wire_type}")

def run_extraction_worker(job_id: str, raw_url: str, target: str):
    job = JOBS[job_id]
    work_dir = f"/tmp/flux_{job_id}"
    os.makedirs(work_dir, exist_ok=True)
    output_path = os.path.join(work_dir, target)
    session = None

    try:
        ensure_dataset_exists()
        parsed = urlparse(raw_url)
        is_gdrive = "drive.google.com" in parsed.netloc or "drive.usercontent.google.com" in parsed.netloc

        if is_gdrive:
            gdrive_id = extract_gdrive_id(raw_url)
            stream_url, rom_filename, total_size, session = resolve_gdrive_stream(gdrive_id)
            cache_folder = f"gdrive_{gdrive_id}"
            source_label = "Google Drive"
        else:
            stream_url, rom_filename, total_size, session = resolve_direct_url(raw_url, job_id)
            cache_folder = re.sub(r"[^a-zA-Z0-9._-]", "_", rom_filename)
            source_label = "Cloud Mirror"

        repo_path = f"{cache_folder}/{target}"
        job["source"] = source_label

        # 0s Cache Check
        try:
            if hf_api.file_exists(repo_id=DATASET_REPO, filename=repo_path, repo_type="dataset"):
                download_url = hf_hub_url(repo_id=DATASET_REPO, filename=repo_path, repo_type="dataset")
                job["rom_progress"] = 100
                job["rom_label"] = "Vault Hit (0 MB downloaded)"
                job["ext_progress"] = 100
                job["ext_label"] = f"Ready: {target} (0s Instant Cache)"
                job["speed"] = "INSTANT"
                job_log(job_id, "SUCCESS", "0s CACHE HIT! Serving from Dataset Vault.")
                job["result"] = {
                    "cached": True, "status": "Retrieved from Vault",
                    "banner": "Instant Match! File found in Dataset Vault (0s)",
                    "duration": "0s", "target": target, "source": source_label, "download_url": download_url
                }
                job["state"] = "done"
                return
        except Exception:
            pass

        start_time = time.time()
        lower_name = rom_filename.lower()

        # 1. FASTBOOT (.TGZ) UNIVERSAL DEEP SCAN (Finds lk.img, boot.img, flash scripts, etc. anywhere in archive)
        if lower_name.endswith((".tgz", ".tar.gz")):
            job["cmd"] = f"# Universal Deep Scan of Fastboot Archive for '{target}'\nwith tarfile.open(fileobj=tracker, mode='r|*') as tar:\n    for member in tar:\n        if member.name.endswith('/{target}') or os.path.basename(member.name) == '{target}':\n        extract_file(member)"
            job_log(job_id, "STREAM", f"Scanning entire Fastboot archive structure for '{target}'...")

            found = False
            with session.get(stream_url, stream=True, timeout=60) as resp:
                resp.raise_for_status()
                tracker = LiveStreamTracker(resp.raw, total_size, job_id)
                with tarfile.open(fileobj=tracker, mode="r|*") as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        norm = member.name.replace("\\", "/").lstrip("./")
                        short = os.path.basename(norm)
                        job["current_scan"] = short

                        # Matches target whether it's in /images/, root, or any subfolder (e.g. lk.img, boot.img)
                        if norm.endswith(f"/{target}") or norm == target or short == target:
                            job_log(job_id, "STREAM", f"Found match: '{norm}'! Extracting...")
                            job["rom_progress"] = 100
                            job["rom_label"] = f"Located {target} in archive! Halting rest of ROM stream."
                            
                            src = tar.extractfile(member)
                            if src is None:
                                raise Exception(f"Unable to read {target}.")
                            
                            with open(output_path, "wb") as dst:
                                shutil.copyfileobj(src, dst, length=1024 * 1024)
                            found = True
                            break

            if not found:
                raise Exception(f"'{target}' was not found anywhere inside this Fastboot archive.")
            verify_file_integrity(output_path)

        # 2. RECOVERY ROM (.ZIP) & CUSTOM ROM PAYLOAD.BIN SUPPORT
        elif lower_name.endswith(".zip"):
            job["rom_progress"] = 40
            job["rom_label"] = "Mapping ZIP Archive via HTTP Range..."
            job_log(job_id, "STREAM", "Reading ZIP directory index via HTTP Range...")

            with RemoteZip(stream_url, session=session) as zf:
                namelist = zf.namelist()
                job["rom_progress"] = 100

                matching_entry = None
                for name in namelist:
                    clean = name.replace("\\", "/").lstrip("./")
                    if clean == target or clean.endswith(f"/{target}") or os.path.basename(clean) == target:
                        matching_entry = name
                        break

                if matching_entry:
                    job_log(job_id, "STREAM", f"Found direct file '{matching_entry}' in ZIP. Streaming...")
                    with zf.open(matching_entry) as src, open(output_path, "wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    verify_file_integrity(output_path)

                elif "payload.bin" in namelist:
                    part_name = target.replace(".img", "")
                    job_log(job_id, "STREAM", f"Parsing payload.bin manifest for partition '{part_name}'...")
                    
                    with zf.open("payload.bin") as payload_stream:
                        magic = payload_stream.read(4)
                        if magic != b"CrAU":
                            raise Exception("Invalid payload.bin header.")
                        version = struct.unpack(">Q", payload_stream.read(8))[0]
                        manifest_size = struct.unpack(">Q", payload_stream.read(8))[0]
                        meta_sig_size = struct.unpack(">I", payload_stream.read(4))[0] if version >= 2 else 0
                        manifest_bytes = payload_stream.read(manifest_size)
                        base_data_offset = (24 if version >= 2 else 20) + manifest_size + meta_sig_size

                        block_size = 4096
                        target_part_bytes = None
                        for f_num, val in _iter_fields(manifest_bytes):
                            if f_num == 3:
                                block_size = val
                            elif f_num == 13:
                                p_name = None
                                for pf_num, p_val in _iter_fields(val):
                                    if pf_num == 1:
                                        p_name = p_val.decode("utf-8", errors="ignore")
                                        break
                                if p_name == part_name:
                                    target_part_bytes = val
                                    break

                        if target_part_bytes is None:
                            raise Exception(f"Partition '{part_name}' not found in payload.bin.")

                        expected_size = None
                        operations = []
                        for pf_num, p_val in _iter_fields(target_part_bytes):
                            if pf_num == 7:
                                for if_num, i_val in _iter_fields(p_val):
                                    if if_num == 1:
                                        expected_size = i_val
                            elif pf_num == 8:
                                op_type, data_offset, data_length = 0, 0, 0
                                dst_extents = []
                                for of_num, o_val in _iter_fields(p_val):
                                    if of_num == 1: op_type = o_val
                                    elif of_num == 2: data_offset = o_val
                                    elif of_num == 3: data_length = o_val
                                    elif of_num == 6:
                                        sb, nb = 0, 0
                                        for ef_num, e_val in _iter_fields(o_val):
                                            if ef_num == 1: sb = e_val
                                            elif ef_num == 2: nb = e_val
                                        dst_extents.append((sb, nb))
                                operations.append((op_type, data_offset, data_length, dst_extents))

                        zstd_dctx = zstd.ZstdDecompressor()
                        with open(output_path, "wb") as out_f:
                            if expected_size:
                                out_f.truncate(expected_size)
                            for op_type, data_offset, data_length, dst_extents in operations:
                                if data_length == 0 or op_type in (6, 7):
                                    continue
                                payload_stream.seek(base_data_offset + data_offset)
                                compressed = payload_stream.read(data_length)
                                if op_type == 0: raw_data = compressed
                                elif op_type == 8 or compressed.startswith(b"\xfd7zXZ\x00"): raw_data = lzma.decompress(compressed)
                                elif op_type == 1 or compressed.startswith(b"BZh"): raw_data = bz2.decompress(compressed)
                                elif op_type == 14 or compressed.startswith(b"\x28\xb5\x2f\xfd"): raw_data = zstd_dctx.decompress(compressed)
                                else: raw_data = compressed

                                in_pos = 0
                                for start_block, num_blocks in dst_extents:
                                    byte_len = num_blocks * block_size
                                    out_f.seek(start_block * block_size)
                                    out_f.write(raw_data[in_pos:in_pos + byte_len])
                                    in_pos += byte_len
                            if expected_size:
                                out_f.truncate(expected_size)
                    verify_file_integrity(output_path)
                else:
                    raise Exception(f"'{target}' not found in this Recovery/Custom ROM.")
        else:
            raise Exception("Unsupported file format. Must be .zip or .tgz/.tar.gz.")

        # Upload to Dataset Vault
        job["ext_progress"] = 95
        job["ext_label"] = f"Uploading {target} to Dataset Vault..."
        hf_api.upload_file(path_or_fileobj=output_path, path_in_repo=repo_path, repo_id=DATASET_REPO, repo_type="dataset", commit_message=f"Added {target}")

        duration_sec = max(1, int(time.time() - start_time))
        download_url = hf_hub_url(repo_id=DATASET_REPO, filename=repo_path, repo_type="dataset")

        job["ext_progress"] = 100
        job["ext_label"] = f"Complete in {duration_sec}s"
        job_log(job_id, "SUCCESS", "Extracted & stored in Vault successfully!")
        job["result"] = {
            "cached": False, "status": "Extracted & Verified",
            "banner": f"Successfully extracted {target} & saved to Dataset",
            "duration": f"{duration_sec}s", "target": target, "source": source_label, "download_url": download_url
        }
        job["state"] = "done"

    except Exception as e:
        job_log(job_id, "ERROR", str(e))
        job["error"] = str(e)
        job["state"] = "error"
    finally:
        if session: session.close()
        if os.path.exists(work_dir): shutil.rmtree(work_dir, ignore_errors=True)

@app.post("/api/start")
def start_job(req: ExtractRequest):
    if not HF_TOKEN: raise HTTPException(status_code=500, detail="Missing HF_TOKEN.")
    raw_url, target = req.rom_url.strip(), req.target.strip()
    if not target: raise HTTPException(status_code=400, detail="Target cannot be empty.")
    if not target.endswith(".img") and not "." in target: target += ".img"

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "state": "running", "target": target, "rom_progress": 2, "rom_label": "Initializing Cloud Worker...",
        "ext_progress": 0, "ext_label": "Scanning archive...", "speed": "—", "current_scan": "—",
        "cmd": "# Initializing deep scan...", "logs": [], "result": None, "error": None
    }
    threading.Thread(target=run_extraction_worker, args=(job_id, raw_url, target), daemon=True).start()
    return {"job_id": job_id}

@app.get("/api/status/{job_id}")
def get_job_status(job_id: str):
    if job_id not in JOBS: raise HTTPException(status_code=404, detail="Job not found.")
    return JOBS[job_id]

@app.get("/api/vault")
def list_vault_files():
    try:
        ensure_dataset_exists()
        files = hf_api.list_repo_files(repo_id=DATASET_REPO, repo_type="dataset")
        items = []
        for f in reversed(files):
            if "/" in f:
                rom_folder, part = f.split("/", 1)
                items.append({"rom": rom_folder, "partition": part, "url": hf_hub_url(repo_id=DATASET_REPO, filename=f, repo_type="dataset")})
        return {"dataset": DATASET_REPO, "items": items[:60]}
    except Exception as e:
        return {"dataset": DATASET_REPO, "items": [], "note": str(e)}

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>HYPER//FLUX — Universal ROM & Custom Partition Studio</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    h1, h2, .brand-font { font-family: 'Space Grotesk', sans-serif; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    body {
      background-color: #07070b;
      background-image: radial-gradient(circle at 85% 10%, rgba(245, 158, 11, 0.14) 0%, transparent 40%),
                        radial-gradient(circle at 10% 30%, rgba(139, 92, 246, 0.16) 0%, transparent 45%),
                        radial-gradient(circle at 50% 95%, rgba(16, 185, 129, 0.12) 0%, transparent 40%);
      background-attachment: fixed;
    }
    .bento-card {
      background: rgba(17, 17, 26, 0.75);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 20px 50px -15px rgba(0, 0, 0, 0.85);
    }
    .cyber-input {
      background: rgba(9, 9, 15, 0.85);
      border: 1px solid rgba(245, 158, 11, 0.25);
      transition: all 0.2s ease;
    }
    .cyber-input:focus { border-color: #f59e0b; box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.15); outline: none; }
    .chip-btn {
      background: rgba(24, 24, 36, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.07);
      transition: all 0.18s ease;
    }
    .chip-btn.active {
      background: linear-gradient(135deg, rgba(245, 158, 11, 0.25), rgba(139, 92, 246, 0.28));
      border-color: #f59e0b; color: #fde68a; box-shadow: 0 0 18px -4px rgba(245, 158, 11, 0.45);
    }
    .ios-dock {
      background: rgba(18, 18, 28, 0.8);
      backdrop-filter: blur(28px);
      -webkit-backdrop-filter: blur(28px);
      border: 1px solid rgba(255, 255, 255, 0.15);
      box-shadow: 0 24px 48px -8px rgba(0, 0, 0, 0.9);
    }
    .dock-btn { transition: all 0.2s cubic-bezier(0.22, 1, 0.36, 1); }
    .dock-btn.active {
      background: linear-gradient(135deg, #f59e0b, #ea580c); color: #09090f; font-weight: 700; transform: translateY(-2px);
    }
  </style>
</head>
<body class="min-h-screen text-slate-100 p-4 pb-36 selection:bg-amber-500/30">

  <div class="w-full max-w-lg mx-auto pt-2">
    <div class="flex items-center justify-between px-4 py-2.5 rounded-2xl bento-card mb-4">
      <div class="flex items-center gap-2.5">
        <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse"></span>
        <span class="brand-font font-bold text-sm tracking-wider bg-gradient-to-r from-amber-300 via-orange-400 to-violet-400 bg-clip-text text-transparent">
          HYPER//FLUX STUDIO
        </span>
      </div>
      <span class="mono text-[10px] px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
        Universal & Custom ROMs
      </span>
    </div>

    <div class="bento-card rounded-3xl p-5 mb-4">
      <h1 class="text-xl font-bold text-white tracking-tight">Universal Partition & File Extractor</h1>
      <p class="text-xs text-slate-400 mt-1 leading-relaxed">
        Supports Fastboot (.tgz), Recovery (.zip), and Custom ROMs (AOSP/payload.bin). Deep-scans archives for <b class="text-amber-300">lk.img, boot.img, modem, and any file</b>.
      </p>
    </div>

    <!-- STUDIO TAB -->
    <div id="tabStudio" class="space-y-4">
      <div class="bento-card rounded-3xl p-5">
        <span class="mono text-[11px] uppercase tracking-wider text-amber-300/90 font-semibold block mb-2">01 // ROM Link (Fastboot, Custom ROM, G-Drive)</span>
        <input id="romUrl" type="url" placeholder="Paste .zip, .tgz, or Google Drive link..." class="cyber-input w-full px-4 py-3.5 rounded-2xl text-xs mono text-white placeholder-slate-500 mb-4" />

        <div class="flex items-center justify-between mb-2">
          <span class="mono text-[11px] uppercase tracking-wider text-amber-300/90 font-semibold">02 // Select or Type Target File</span>
          <span id="selectedLabel" class="mono text-xs text-violet-300 font-semibold">init_boot.img</span>
        </div>

        <div class="grid grid-cols-3 gap-2 mb-3" id="chipGrid">
          <button type="button" onclick="pickPart('init_boot.img', this)" class="chip-btn active py-2 px-2 rounded-xl mono text-[11px] text-slate-300">init_boot.img</button>
          <button type="button" onclick="pickPart('boot.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">boot.img</button>
          <button type="button" onclick="pickPart('lk.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">lk.img</button>
          <button type="button" onclick="pickPart('vendor_boot.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">vendor_boot.img</button>
          <button type="button" onclick="pickPart('dtbo.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">dtbo.img</button>
          <button type="button" onclick="pickPart('recovery.img', this)" class="chip-btn py-2 px-2 rounded-xl mono text-[11px] text-slate-300">recovery.img</button>
        </div>

        <input id="customTarget" type="text" oninput="customPartInput(this.value)" placeholder="Or type any custom filename (e.g. modem.img, sec.dat)..." class="cyber-input w-full px-4 py-2.5 rounded-xl text-xs mono text-white placeholder-slate-500 mb-4" />

        <button id="launchBtn" onclick="launchExtraction()" class="w-full py-3.5 rounded-2xl font-bold text-sm text-slate-950 bg-gradient-to-r from-amber-400 via-orange-400 to-amber-500 hover:brightness-110 transition shadow-lg shadow-amber-500/20">
          ⚡ Deep-Scan & Extract File
        </button>

        <div id="errBanner" class="hidden mt-4 text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-2xl p-3.5 mono"></div>
      </div>

      <!-- LIVE PROGRESS HUD -->
      <div id="liveProgressHud" class="hidden bento-card rounded-3xl p-5 space-y-4 border border-amber-500/30">
        <div class="flex items-center justify-between border-b border-white/10 pb-3">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
            <span class="text-xs font-bold uppercase tracking-wider text-white">Cloud Deep-Scan HUD</span>
          </div>
          <span id="hudSpeed" class="mono text-xs font-semibold px-2.5 py-0.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-400/30">—</span>
        </div>

        <div>
          <div class="flex justify-between text-[11px] mb-1.5">
            <span id="romStageText" class="text-slate-300 font-medium">Stage 1: Streaming Archive</span>
            <span id="romPercentText" class="mono text-amber-300 font-bold">0%</span>
          </div>
          <div class="w-full h-2.5 bg-black/60 rounded-full overflow-hidden p-0.5 border border-white/10">
            <div id="romBar" style="width: 0%" class="h-full rounded-full bg-gradient-to-r from-amber-500 to-orange-400 transition-all duration-300"></div>
          </div>
          <p id="scanFileText" class="mono text-[10px] text-slate-400 mt-1 truncate">Scanning files...</p>
        </div>

        <div>
          <div class="flex justify-between text-[11px] mb-1.5">
            <span id="extStageText" class="text-slate-300 font-medium">Stage 2: Extracting & Vault Sync</span>
            <span id="extPercentText" class="mono text-emerald-400 font-bold">0%</span>
          </div>
          <div class="w-full h-2.5 bg-black/60 rounded-full overflow-hidden p-0.5 border border-white/10">
            <div id="extBar" style="width: 0%" class="h-full rounded-full bg-gradient-to-r from-violet-500 via-sky-400 to-emerald-400 transition-all duration-300"></div>
          </div>
        </div>
      </div>

      <!-- DONE CARD -->
      <div id="doneCard" class="hidden bento-card rounded-3xl p-6 border border-emerald-500/30">
        <h2 class="text-lg font-bold text-white">File Extracted Successfully!</h2>
        <p class="text-xs text-slate-400 mt-0.5">Stored permanently in your Instant Dataset Vault.</p>
        <a id="finalDownloadBtn" href="#" target="_blank" class="mt-4 w-full py-3.5 rounded-2xl font-bold text-sm text-slate-950 bg-gradient-to-r from-emerald-400 to-teal-300 flex items-center justify-center gap-2 shadow-lg">
          ⬇ Download Extracted File
        </a>
      </div>
    </div>

    <!-- VAULT TAB -->
    <div id="tabVault" class="hidden space-y-4">
      <div class="bento-card rounded-3xl p-5">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-base font-bold text-white">Instant Dataset Vault (0s)</h2>
          <button onclick="loadVault()" class="mono text-[11px] px-3 py-1.5 rounded-xl bg-white/5 text-amber-300">Refresh</button>
        </div>
        <div id="vaultList" class="space-y-2 max-h-80 overflow-y-auto pr-1">
          <div class="text-xs text-slate-500 mono py-6 text-center">Loading vault...</div>
        </div>
      </div>
    </div>

    <!-- CONSOLE TAB -->
    <div id="tabTerminal" class="hidden space-y-4">
      <div class="bento-card rounded-3xl p-5">
        <span class="mono text-[11px] text-amber-300 font-semibold block mb-2">Live Cloud Terminal Log</span>
        <div id="logBox" class="mono text-[11px] bg-black/75 rounded-2xl p-3.5 h-64 overflow-y-auto space-y-1.5 border border-white/5">
          <div class="text-slate-500">[System] Ready for deep scan.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- IPHONE GLASS DOCK -->
  <div class="fixed bottom-3 left-1/2 -translate-x-1/2 z-50 flex flex-col items-center gap-1.5 w-full max-w-sm px-4">
    <div class="ios-dock p-1.5 rounded-[26px] flex items-center justify-between w-full gap-1">
      <button id="btnStudio" onclick="switchView('studio')" class="dock-btn active flex-1 py-2.5 rounded-[20px] text-xs">⚡ Studio</button>
      <button id="btnVault" onclick="switchView('vault')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">🗄️ Vault</button>
      <button id="btnTerminal" onclick="switchView('terminal')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">💻 Console</button>
    </div>
    <div class="text-[11px] font-medium text-slate-400 tracking-wide flex items-center gap-1">
      <span>Made by</span>
      <span class="font-bold bg-gradient-to-r from-amber-400 to-orange-300 bg-clip-text text-transparent">Yash</span>
    </div>
  </div>

  <script>
    let currentPart = "init_boot.img";
    let pollTimer = null;
    let renderedLogs = 0;

    function switchView(view) {
      ["Studio", "Vault", "Terminal"].forEach(v => {
        document.getElementById("tab" + v).classList.add("hidden");
        const b = document.getElementById("btn" + v);
        b.classList.remove("active"); b.classList.add("text-slate-300");
      });
      const cap = view.charAt(0).toUpperCase() + view.slice(1);
      document.getElementById("tab" + cap).classList.remove("hidden");
      const activeBtn = document.getElementById("btn" + cap);
      activeBtn.classList.add("active"); activeBtn.classList.remove("text-slate-300");
      if (view === "vault") loadVault();
    }

    function pickPart(part, el) {
      currentPart = part;
      document.getElementById("selectedLabel").textContent = part;
      document.getElementById("customTarget").value = "";
      document.querySelectorAll("#chipGrid .chip-btn").forEach(b => b.classList.remove("active"));
      el.classList.add("active");
    }

    function customPartInput(val) {
      if (val.trim()) {
        currentPart = val.trim();
        document.getElementById("selectedLabel").textContent = currentPart;
        document.querySelectorAll("#chipGrid .chip-btn").forEach(b => b.classList.remove("active"));
      }
    }

    async function launchExtraction() {
      const romUrl = document.getElementById("romUrl").value.trim();
      const errBanner = document.getElementById("errBanner");
      const btn = document.getElementById("launchBtn");
      errBanner.classList.add("hidden");
      if (!romUrl) { errBanner.textContent = "Please paste a ROM link."; errBanner.classList.remove("hidden"); return; }

      btn.disabled = true; btn.innerHTML = "⏳ Deep-Scanning Archive...";
      document.getElementById("doneCard").classList.add("hidden");
      document.getElementById("liveProgressHud").classList.remove("hidden");
      document.getElementById("logBox").innerHTML = ""; renderedLogs = 0;

      try {
        const res = await fetch("/api/start", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rom_url: romUrl, target: currentPart })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail);
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(() => pollJobStatus(data.job_id), 650);
      } catch (e) {
        errBanner.textContent = e.message; errBanner.classList.remove("hidden");
        btn.disabled = false; btn.innerHTML = "⚡ Deep-Scan & Extract File";
      }
    }

    async function pollJobStatus(jobId) {
      try {
        const res = await fetch(`/api/status/${jobId}`);
        if (!res.ok) return;
        const job = await res.json();

        document.getElementById("romBar").style.width = `${job.rom_progress}%`;
        document.getElementById("romPercentText").textContent = `${job.rom_progress}%`;
        document.getElementById("romStageText").textContent = job.rom_label;
        document.getElementById("scanFileText").textContent = `Scanning: ${job.current_scan}`;
        document.getElementById("extBar").style.width = `${job.ext_progress}%`;
        document.getElementById("extPercentText").textContent = `${job.ext_progress}%`;
        document.getElementById("extStageText").textContent = job.ext_label;
        document.getElementById("hudSpeed").textContent = job.speed;

        const logBox = document.getElementById("logBox");
        while (renderedLogs < job.logs.length) {
          const item = job.logs[renderedLogs++];
          const d = document.createElement("div");
          d.className = item.level === "ERROR" ? "text-rose-400 font-semibold" : item.level === "SUCCESS" ? "text-emerald-400 font-semibold" : "text-slate-300";
          d.textContent = `[${item.ts}] [${item.level}] ${item.message}`;
          logBox.appendChild(d); logBox.scrollTop = logBox.scrollHeight;
        }

        if (job.state === "done" && job.result) {
          clearInterval(pollTimer);
          document.getElementById("launchBtn").disabled = false;
          document.getElementById("launchBtn").innerHTML = "⚡ Deep-Scan & Extract File";
          document.getElementById("doneCard").classList.remove("hidden");
          document.getElementById("finalDownloadBtn").href = job.result.download_url;
        } else if (job.state === "error") {
          clearInterval(pollTimer);
          document.getElementById("launchBtn").disabled = false;
          document.getElementById("launchBtn").innerHTML = "⚡ Deep-Scan & Extract File";
          errBanner.textContent = job.error; errBanner.classList.remove("hidden");
        }
      } catch(ignore) {}
    }

    async function loadVault() {
      const box = document.getElementById("vaultList");
      try {
        const res = await fetch("/api/vault");
        const data = await res.json();
        if (!data.items || data.items.length === 0) {
          box.innerHTML = `<div class="text-xs text-slate-500 mono py-6 text-center">No files in vault yet.</div>`;
          return;
        }
        box.innerHTML = data.items.map(item => `
          <div class="flex items-center justify-between p-3 rounded-2xl bg-black/50 border border-white/5">
            <div class="pr-3 overflow-hidden">
              <div class="mono text-xs font-bold text-amber-300">${item.partition}</div>
              <div class="mono text-[10px] text-slate-400 truncate">${item.rom}</div>
            </div>
            <a href="${item.url}" target="_blank" class="shrink-0 px-3 py-1.5 rounded-xl bg-emerald-500/20 text-emerald-300 mono text-[11px] font-semibold hover:bg-emerald-500/30">⬇ 0s Get</a>
          </div>
        `).join("");
      } catch (e) {
        box.innerHTML = `<div class="text-xs text-rose-400 mono py-4 text-center">Failed to load vault.</div>`;
      }
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return HTML_PAGE
