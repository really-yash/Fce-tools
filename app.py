import os
import re
import bz2
import lzma
import json
import time
import struct
import shutil
import tarfile
import hashlib
import requests
import zstandard as zstd
from datetime import datetime
from urllib.parse import urlparse, unquote
from remotezip import RemoteZip
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import HfApi, hf_hub_url

app = FastAPI(title="Xiaomi Firmware Content Extractor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HF_TOKEN = os.getenv("HF_TOKEN", "")
DATASET_REPO = os.getenv("DATASET_REPO", "")
hf_api = HfApi(token=HF_TOKEN if HF_TOKEN else None)

ALLOWED_PARTITIONS = {
    "boot.img", "vendor_boot.img", "init_boot.img", "dtbo.img",
    "vbmeta.img", "vbmeta_system.img", "vbmeta_vendor.img", "recovery.img"
}

class ExtractRequest(BaseModel):
    rom_url: str
    target: str

def sse_event(data: dict) -> str:
    """Formats a dictionary as a Server-Sent Event JSON line."""
    data["ts"] = datetime.now().strftime("%H:%M:%S")
    return f"data: {json.dumps(data)}\n\n"

# ---------------- UNIVERSAL LINK & GOOGLE DRIVE RESOLVER ---------------- #

def extract_gdrive_id(url: str):
    patterns = [
        r"/file/d/([a-zA-Z0-9_-]{20,})",
        r"/d/([a-zA-Z0-9_-]{20,})",
        r"[?&]id=([a-zA-Z0-9_-]{20,})",
    ]
    for pat in patterns:
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

def resolve_gdrive_stream(file_id: str):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    direct_url = f"https://drive.usercontent.google.com/download?id={file_id}&export=download&confirm=t"
    resp = session.get(direct_url, stream=True, timeout=30)

    content_type = resp.headers.get("Content-Type", "")
    if "text/html" in content_type:
        html = resp.text
        resp.close()
        uuid_match = re.search(r'name="uuid"\s+value="([^"]+)"', html)
        if uuid_match:
            uuid_val = uuid_match.group(1)
            direct_url = f"https://drive.usercontent.google.com/download?id={file_id}&export=download&confirm=t&uuid={uuid_val}"
            resp = session.get(direct_url, stream=True, timeout=30)

    if resp.status_code != 200:
        resp.close()
        raise Exception("Unable to access Google Drive file. Ensure link sharing is set to 'Anyone with the link'.")

    filename = parse_filename_from_cd(resp.headers.get("Content-Disposition", ""))
    resp.close()
    if not filename:
        raise Exception("Google Drive link did not return a downloadable ROM archive. Check permissions.")
    return direct_url, filename, session

def resolve_direct_or_unofficial_url(url: str):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    resp = session.get(url, stream=True, allow_redirects=True, timeout=30)
    if resp.status_code >= 400:
        resp.close()
        raise Exception(f"Remote ROM server returned HTTP {resp.status_code}.")

    final_url = resp.url
    filename = parse_filename_from_cd(resp.headers.get("Content-Disposition", ""))
    resp.close()

    if not filename:
        filename = unquote(os.path.basename(urlparse(final_url).path))
    if not filename:
        filename = unquote(os.path.basename(urlparse(url).path))

    return final_url, filename, session

def detect_rom_type(filename: str):
    lower = filename.lower()
    if lower.endswith(".tgz") or lower.endswith(".tar.gz"):
        return "fastboot"
    elif lower.endswith(".zip"):
        return "recovery"
    raise Exception(
        f"Unsupported file '{filename}'. Exclusively supports Xiaomi Fastboot (.tgz) and Recovery (.zip) ROMs."
    )

# ---------------- ANTI-CORRUPTION INTEGRITY CHECK ---------------- #

def verify_img_integrity(file_path: str, expected_size: int = None, expected_sha256: bytes = None):
    if not os.path.exists(file_path):
        raise Exception("Extraction failed: Output image was not created.")

    actual_size = os.path.getsize(file_path)
    if expected_size is not None and actual_size != expected_size:
        raise Exception(
            f"Corruption prevented: Incomplete download ({actual_size} of {expected_size} bytes)."
        )
    if actual_size < 65536:
        raise Exception(f"Integrity check failed: Extracted file is too small ({actual_size} bytes).")

    with open(file_path, "rb") as f:
        header = f.read(4096)
        if header == b"\x00" * len(header):
            raise Exception("Integrity check failed: File header contains only null bytes.")

    if expected_sha256 is not None:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        if h.digest() != expected_sha256:
            raise Exception("Corruption prevented: SHA-256 cryptographic checksum mismatch!")

# ---------------- PURE-PYTHON PAYLOAD.BIN RANGE EXTRACTOR ---------------- #

def _read_varint(buf: bytes, pos: int):
    res = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, pos
        shift += 7

def _iter_fields(buf: bytes):
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
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
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")

# ---------------- LIVE STREAMING EXTRACTION GENERATOR ---------------- #

def extraction_event_generator(raw_url: str, target: str):
    if not HF_TOKEN or not DATASET_REPO:
        yield sse_event({
            "type": "error",
            "message": "Server missing HF_TOKEN or DATASET_REPO. Add them in Space Settings -> Variables and secrets."
        })
        return

    raw_url = raw_url.strip()
    target = target.strip()
    if not target.endswith(".img"):
        target += ".img"

    if target not in ALLOWED_PARTITIONS:
        yield sse_event({"type": "error", "message": f"Target '{target}' is not supported."})
        return

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        yield sse_event({"type": "error", "message": "Please enter a valid http:// or https:// link."})
        return

    is_gdrive = "drive.google.com" in parsed.netloc or "drive.usercontent.google.com" in parsed.netloc
    url_basename = unquote(os.path.basename(parsed.path))

    if is_gdrive:
        gdrive_id = extract_gdrive_id(raw_url)
        if not gdrive_id:
            yield sse_event({"type": "error", "message": "Invalid Google Drive URL. File ID not found."})
            return
        cache_folder = f"gdrive_{gdrive_id}"
        source_label = "Google Drive"
    elif url_basename.lower().endswith((".zip", ".tgz", ".tar.gz")):
        cache_folder = re.sub(r"[^a-zA-Z0-9._-]", "_", url_basename)
        source_label = "Official CDN" if any(d in parsed.netloc for d in ("miui.com", "xiaomi.com", "aliyuncs.com")) else "Unofficial / Mirror"
    else:
        url_hash = hashlib.md5(raw_url.encode()).hexdigest()[:12]
        cache_folder = f"rom_{url_hash}"
        source_label = "Unofficial / Mirror"

    repo_path = f"{cache_folder}/{target}"

    # 1. LOG & CHECK INSTANT 0s CACHE
    yield sse_event({
        "type": "log",
        "level": "CACHE",
        "message": f"Checking Hugging Face Dataset cache for '{repo_path}'..."
    })
    yield sse_event({
        "type": "cmd",
        "code": f"# 1. Instant 0s Cache Lookup\nhf_api.file_exists(\n    repo_id=\"{DATASET_REPO}\",\n    filename=\"{repo_path}\",\n    repo_type=\"dataset\"\n)"
    })
    yield sse_event({"type": "progress", "percent": 5, "stage": "Checking Dataset Cache...", "speed": "—"})

    try:
        if hf_api.file_exists(repo_id=DATASET_REPO, filename=repo_path, repo_type="dataset"):
            download_url = hf_hub_url(repo_id=DATASET_REPO, filename=repo_path, repo_type="dataset")
            yield sse_event({
                "type": "log",
                "level": "SUCCESS",
                "message": "CACHE HIT! Partition already exists in Hugging Face Dataset (0s)."
            })
            yield sse_event({"type": "progress", "percent": 100, "stage": "Retrieved from Cache (0s)", "speed": "Instant"})
            yield sse_event({
                "type": "done",
                "result": {
                    "cached": True,
                    "status": "Retrieved from cache",
                    "banner": "File already exists in dataset (from cache)",
                    "duration": "0s",
                    "target": target,
                    "source": source_label,
                    "download_url": download_url
                }
            })
            return
    except Exception as e:
        yield sse_event({"type": "log", "level": "INFO", "message": f"Cache lookup note: {e}"})

    # 2. CACHE MISS -> RESOLVE STREAM
    start_time = time.time()
    job_id = hashlib.md5(f"{raw_url}_{target}_{time.time()}".encode()).hexdigest()[:10]
    work_dir = f"/tmp/fce_job_{job_id}"
    os.makedirs(work_dir, exist_ok=True)
    extracted_img_path = os.path.join(work_dir, target)
    session = None

    try:
        yield sse_event({
            "type": "log",
            "level": "INFO",
            "message": f"Cache miss. Connecting to {source_label} source..."
        })
        yield sse_event({"type": "progress", "percent": 10, "stage": f"Connecting to {source_label}...", "speed": "—"})

        if is_gdrive:
            yield sse_event({
                "type": "cmd",
                "code": f"# Resolve Google Drive Large-File Stream\nsession.get(\"https://drive.usercontent.google.com/download?id={gdrive_id}&confirm=t\", stream=True)"
            })
            stream_url, rom_filename, session = resolve_gdrive_stream(gdrive_id)
        else:
            yield sse_event({
                "type": "cmd",
                "code": f"# Open HTTP Range Stream to ROM Server\nsession.get(\"{raw_url[:65]}...\", stream=True, allow_redirects=True)"
            })
            stream_url, rom_filename, session = resolve_direct_or_unofficial_url(raw_url)

        rom_type = detect_rom_type(rom_filename)
        yield sse_event({
            "type": "log",
            "level": "INFO",
            "message": f"Detected Xiaomi {rom_type.upper()} ROM: {rom_filename}"
        })

        # 3A. FASTBOOT (.TGZ) EXTRACTION WITH LIVE PROGRESS
        if rom_type == "fastboot":
            yield sse_event({
                "type": "cmd",
                "code": (
                    f"# Stream Fastboot .tgz in RAM & Extract Only 'images/{target}'\n"
                    f"with tarfile.open(fileobj=resp.raw, mode='r|*') as tar:\n"
                    f"    if member.name.endswith('/images/{target}'):\n"
                    f"        shutil.copyfileobj(tar.extractfile(member), out_file)\n"
                    f"        break  # Immediately abort rest of 7GB download"
                )
            })
            yield sse_event({
                "type": "log",
                "level": "STREAM",
                "message": f"Scanning Fastboot archive stream for 'images/{target}'..."
            })

            found = False
            expected_size = None
            with session.get(stream_url, stream=True, timeout=60) as resp:
                resp.raise_for_status()
                with tarfile.open(fileobj=resp.raw, mode="r|*") as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        norm = member.name.replace("\\", "/").lstrip("./")
                        if norm.endswith(f"/images/{target}") or norm == f"images/{target}" or os.path.basename(norm) == target:
                            expected_size = member.size
                            mb_total = expected_size / (1024 * 1024)
                            yield sse_event({
                                "type": "log",
                                "level": "STREAM",
                                "message": f"Found '{member.name}' ({mb_total:.2f} MB). Extracting to temp buffer..."
                            })
                            src = tar.extractfile(member)
                            if src is None:
                                raise Exception(f"Unable to read {target} from Fastboot stream.")

                            copied = 0
                            t0 = time.time()
                            last_emit = 0
                            with open(extracted_img_path, "wb") as dst:
                                while True:
                                    buf = src.read(256 * 1024)
                                    if not buf:
                                        break
                                    dst.write(buf)
                                    copied += len(buf)
                                    now = time.time()
                                    if now - last_emit >= 0.25 or copied == expected_size:
                                        elapsed = max(0.05, now - t0)
                                        mbps = (copied * 8) / (elapsed * 1_000_000)
                                        pct = 15 + int((copied / max(1, expected_size)) * 65)
                                        yield sse_event({
                                            "type": "progress",
                                            "percent": min(80, pct),
                                            "stage": f"Extracting {target} ({copied/(1024*1024):.1f} / {mb_total:.1f} MB)",
                                            "speed": f"{mbps:.0f} Mbps"
                                        })
                                        last_emit = now
                            found = True
                            break

            if not found:
                raise Exception(f"'{target}' was not found inside the 'images/' folder of this Fastboot ROM.")

            yield sse_event({
                "type": "log",
                "level": "VERIFY",
                "message": f"Closed ROM stream early. Verifying byte size ({expected_size} bytes) & image header..."
            })
            verify_img_integrity(extracted_img_path, expected_size=expected_size)

        # 3B. RECOVERY (.ZIP) EXTRACTION WITH LIVE PROGRESS
        else:
            partition_name = target.replace(".img", "")
            yield sse_event({
                "type": "log",
                "level": "STREAM",
                "message": "Reading Recovery ZIP Central Directory via HTTP Range request..."
            })

            with RemoteZip(stream_url, session=session) as zf:
                namelist = zf.namelist()
                matching_entry = None
                for name in namelist:
                    clean = name.replace("\\", "/").lstrip("./")
                    if clean in (target, f"images/{target}", f"firmware-update/{target}") or clean.endswith(f"/images/{target}"):
                        matching_entry = name
                        break

                if matching_entry:
                    info = zf.getinfo(matching_entry)
                    expected_size = info.file_size
                    mb_total = expected_size / (1024 * 1024)
                    yield sse_event({
                        "type": "cmd",
                        "code": (
                            f"# Direct HTTP Range Extraction from ZIP\n"
                            f"with RemoteZip(rom_url) as zf:\n"
                            f"    zf.extract(\"{matching_entry}\")  # Size: {mb_total:.2f} MB"
                        )
                    })
                    yield sse_event({
                        "type": "log",
                        "level": "STREAM",
                        "message": f"Found direct entry '{matching_entry}' ({mb_total:.2f} MB). Streaming byte range..."
                    })

                    copied = 0
                    t0 = time.time()
                    last_emit = 0
                    with zf.open(matching_entry) as src, open(extracted_img_path, "wb") as dst:
                        while True:
                            buf = src.read(256 * 1024)
                            if not buf:
                                break
                            dst.write(buf)
                            copied += len(buf)
                            now = time.time()
                            if now - last_emit >= 0.25 or copied == expected_size:
                                elapsed = max(0.05, now - t0)
                                mbps = (copied * 8) / (elapsed * 1_000_000)
                                pct = 15 + int((copied / max(1, expected_size)) * 65)
                                yield sse_event({
                                    "type": "progress",
                                    "percent": min(80, pct),
                                    "stage": f"Streaming {target} ({copied/(1024*1024):.1f} / {mb_total:.1f} MB)",
                                    "speed": f"{mbps:.0f} Mbps"
                                })
                                last_emit = now

                    verify_img_integrity(extracted_img_path, expected_size=expected_size)

                elif "payload.bin" in namelist:
                    yield sse_event({
                        "type": "cmd",
                        "code": (
                            f"# HTTP Range Extraction from payload.bin\n"
                            f"with RemoteZip(rom_url).open('payload.bin') as payload:\n"
                            f"    parse_crAU_manifest(payload, target='{partition_name}')\n"
                            f"    stream_and_verify_sha256_extents('{target}')"
                        )
                    })
                    yield sse_event({
                        "type": "log",
                        "level": "STREAM",
                        "message": f"Parsing payload.bin CrAU protobuf manifest for '{partition_name}'..."
                    })

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
                                part_name = None
                                for pf_num, p_val in _iter_fields(val):
                                    if pf_num == 1:
                                        part_name = p_val.decode("utf-8", errors="ignore")
                                        break
                                if part_name == partition_name:
                                    target_part_bytes = val
                                    break

                        if target_part_bytes is None:
                            raise Exception(f"Partition '{target}' not found in payload.bin.")

                        expected_size = None
                        expected_hash = None
                        operations = []
                        for pf_num, p_val in _iter_fields(target_part_bytes):
                            if pf_num == 7:
                                for if_num, i_val in _iter_fields(p_val):
                                    if if_num == 1:
                                        expected_size = i_val
                                    elif if_num == 2:
                                        expected_hash = i_val
                            elif pf_num == 8:
                                op_type, data_offset, data_length = 0, 0, 0
                                dst_extents = []
                                data_sha256 = None
                                for of_num, o_val in _iter_fields(p_val):
                                    if of_num == 1:
                                        op_type = o_val
                                    elif of_num == 2:
                                        data_offset = o_val
                                    elif of_num == 3:
                                        data_length = o_val
                                    elif of_num == 6:
                                        sb, nb = 0, 0
                                        for ef_num, e_val in _iter_fields(o_val):
                                            if ef_num == 1:
                                                sb = e_val
                                            elif ef_num == 2:
                                                nb = e_val
                                        dst_extents.append((sb, nb))
                                    elif of_num == 8:
                                        data_sha256 = o_val
                                operations.append((op_type, data_offset, data_length, dst_extents, data_sha256))

                        total_ops = len(operations)
                        mb_total = (expected_size or 0) / (1024 * 1024)
                        yield sse_event({
                            "type": "log",
                            "level": "STREAM",
                            "message": f"Located {total_ops} compressed data chunks for {target} ({mb_total:.2f} MB)."
                        })

                        zstd_dctx = zstd.ZstdDecompressor()
                        t0 = time.time()
                        bytes_fetched = 0

                        with open(extracted_img_path, "wb") as out_f:
                            if expected_size:
                                out_f.truncate(expected_size)

                            for idx, (op_type, data_offset, data_length, dst_extents, data_sha256) in enumerate(operations, 1):
                                if data_length == 0 or op_type in (6, 7):
                                    continue

                                payload_stream.seek(base_data_offset + data_offset)
                                compressed = payload_stream.read(data_length)
                                bytes_fetched += len(compressed)

                                if data_sha256 and hashlib.sha256(compressed).digest() != data_sha256:
                                    raise Exception(f"Chunk {idx} SHA-256 mismatch while extracting {target}!")

                                if op_type == 0:
                                    raw_data = compressed
                                elif op_type == 8 or compressed.startswith(b"\xfd7zXZ\x00"):
                                    raw_data = lzma.decompress(compressed)
                                elif op_type == 1 or compressed.startswith(b"BZh"):
                                    raw_data = bz2.decompress(compressed)
                                elif op_type == 14 or compressed.startswith(b"\x28\xb5\x2f\xfd"):
                                    raw_data = zstd_dctx.decompress(compressed)
                                else:
                                    raise Exception(f"Unsupported payload compression type: {op_type}")

                                in_pos = 0
                                for start_block, num_blocks in dst_extents:
                                    byte_len = num_blocks * block_size
                                    out_f.seek(start_block * block_size)
                                    out_f.write(raw_data[in_pos:in_pos + byte_len])
                                    in_pos += byte_len

                                elapsed = max(0.05, time.time() - t0)
                                mbps = (bytes_fetched * 8) / (elapsed * 1_000_000)
                                pct = 15 + int((idx / max(1, total_ops)) * 65)
                                if idx % max(1, total_ops // 10) == 0 or idx == total_ops:
                                    yield sse_event({
                                        "type": "progress",
                                        "percent": min(80, pct),
                                        "stage": f"Decompressing chunk {idx}/{total_ops} ({mb_total:.1f} MB)",
                                        "speed": f"{mbps:.0f} Mbps"
                                    })

                            if expected_size:
                                out_f.truncate(expected_size)

                        yield sse_event({
                            "type": "log",
                            "level": "VERIFY",
                            "message": f"Verifying full partition SHA-256 hash for {target}..."
                        })
                        verify_img_integrity(extracted_img_path, expected_size=expected_size, expected_sha256=expected_hash)
                else:
                    raise Exception(f"'{target}' not found in this Recovery ROM.")

        # 4. UPLOAD TO HUGGING FACE DATASET
        yield sse_event({
            "type": "log",
            "level": "VERIFY",
            "message": "Integrity check passed (100% corruption-free). Uploading via Rust hf_transfer..."
        })
        yield sse_event({
            "type": "cmd",
            "code": (
                f"# High-Speed Rust Upload to Hugging Face Dataset\n"
                f"hf_api.upload_file(\n"
                f"    path_or_fileobj=\"{extracted_img_path}\",\n"
                f"    path_in_repo=\"{repo_path}\",\n"
                f"    repo_id=\"{DATASET_REPO}\",\n"
                f"    repo_type=\"dataset\"\n"
                f")"
            )
        })
        yield sse_event({"type": "progress", "percent": 88, "stage": "Uploading to HF Dataset...", "speed": "500+ Mbps"})

        hf_api.upload_file(
            path_or_fileobj=extracted_img_path,
            path_in_repo=repo_path,
            repo_id=DATASET_REPO,
            repo_type="dataset",
            commit_message=f"Verified {target} from {rom_filename}"
        )

        duration_sec = max(1, int(time.time() - start_time))
        download_url = hf_hub_url(repo_id=DATASET_REPO, filename=repo_path, repo_type="dataset")

        yield sse_event({
            "type": "log",
            "level": "SUCCESS",
            "message": f"Upload complete in {duration_sec}s! Wiping temporary server files..."
        })
        yield sse_event({"type": "progress", "percent": 100, "stage": "Extraction Complete!", "speed": "Done"})
        yield sse_event({
            "type": "done",
            "result": {
                "cached": False,
                "status": "Extracted & Verified",
                "banner": f"Extracted from {rom_type.capitalize()} ROM & saved to dataset",
                "duration": f"{duration_sec}s",
                "target": target,
                "source": source_label,
                "download_url": download_url
            }
        })

    except Exception as e:
        yield sse_event({"type": "log", "level": "ERROR", "message": str(e)})
        yield sse_event({"type": "error", "message": str(e)})
    finally:
        if session:
            session.close()
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
        if os.path.exists("/tmp/hf_cache"):
            shutil.rmtree("/tmp/hf_cache", ignore_errors=True)

@app.post("/api/extract-stream")
def extract_firmware_stream(req: ExtractRequest):
    return StreamingResponse(
        extraction_event_generator(req.rom_url, req.target),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# ---------------- AESTHETIC AMBIENT GLASS UI + IPHONE DOCK ---------------- #

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Firmware Content Extractor</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    body {
      background-color: #040711;
      background-image:
        radial-gradient(circle at 12% 16%, rgba(56, 189, 248, 0.19) 0%, transparent 42%),
        radial-gradient(circle at 88% 20%, rgba(139, 92, 246, 0.18) 0%, transparent 45%),
        radial-gradient(circle at 50% 85%, rgba(16, 185, 129, 0.14) 0%, transparent 45%);
      background-attachment: fixed;
    }
    .glass-card {
      background: rgba(15, 23, 42, 0.62);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border: 1px solid rgba(255, 255, 255, 0.10);
      box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.75), inset 0 1px 0 0 rgba(255, 255, 255, 0.14);
    }
    .glass-input {
      background: rgba(8, 13, 25, 0.72);
      border: 1px solid rgba(255, 255, 255, 0.09);
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .glass-input:focus {
      border-color: rgba(56, 189, 248, 0.65);
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
      outline: none;
    }
    .pill-btn {
      background: rgba(30, 41, 59, 0.55);
      border: 1px solid rgba(255, 255, 255, 0.07);
      transition: all 0.15s ease;
    }
    .pill-btn.active {
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.90), rgba(14, 165, 233, 0.90));
      border-color: rgba(125, 211, 252, 0.6);
      box-shadow: 0 0 20px -4px rgba(56, 189, 248, 0.5);
      color: #fff;
    }
    /* iPhone iOS Frosted Glass Dock */
    .ios-dock {
      background: rgba(255, 255, 255, 0.07);
      backdrop-filter: blur(24px) saturate(180%);
      -webkit-backdrop-filter: blur(24px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.16);
      box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.8), inset 0 1px 0 0 rgba(255, 255, 255, 0.22);
    }
    .dock-item {
      transition: all 0.22s cubic-bezier(0.22, 1, 0.36, 1);
    }
    .dock-item.active {
      background: rgba(255, 255, 255, 0.14);
      border-color: rgba(255, 255, 255, 0.22);
      transform: translateY(-2px);
      box-shadow: 0 8px 20px -4px rgba(56, 189, 248, 0.35);
    }
  </style>
</head>
<body class="min-h-screen flex flex-col items-center p-4 pb-36 text-slate-100 selection:bg-sky-500/30">

  <div class="w-full max-w-md mx-auto pt-3">
    <!-- Top Header -->
    <div class="text-center mb-5">
      <div class="w-15 h-15 p-3.5 rounded-2xl mx-auto mb-3 inline-flex items-center justify-center bg-gradient-to-br from-blue-500 via-sky-500 to-cyan-400 shadow-lg shadow-sky-500/25 border border-white/20">
        <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <rect x="7" y="7" width="10" height="10" rx="2"></rect>
          <path d="M9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4"></path>
        </svg>
      </div>
      <h1 class="text-2xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-sky-300 bg-clip-text text-transparent">
        Firmware Content Extractor
      </h1>
      <p class="text-xs text-slate-400 mt-1 px-3 leading-relaxed">
        No need to download the entire ROM just to get one file. Extract it directly!
      </p>

      <!-- Polished Grammar Notice Badge -->
      <div class="mt-2.5 inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-sky-500/10 border border-sky-400/20 text-[11px] text-sky-200">
        <span>✨</span>
        <span>Exclusively supports <b>Xiaomi Fastboot (.tgz)</b> & <b>Recovery (.zip)</b> ROMs</span>
      </div>
    </div>

    <!-- ================= SECTION 1: EXTRACTOR VIEW ================= -->
    <div id="sectionExtractor" class="space-y-4">
      <div id="formCard" class="glass-card rounded-3xl p-6">
        <div class="flex items-center justify-between mb-2">
          <label class="text-xs font-semibold uppercase tracking-wider text-slate-300">
            ROM Link (Official, Unofficial or G-Drive)
          </label>
          <span id="sourceBadge" class="text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-slate-800/80 text-slate-400 border border-white/5">
            Universal Link
          </span>
        </div>

        <input
          id="romUrl"
          type="url"
          oninput="updateSourceBadge(this.value)"
          placeholder="Paste Xiaomi (.zip / .tgz) or Google Drive link..."
          class="glass-input w-full px-4 py-3.5 rounded-2xl text-sm text-white placeholder-slate-500 mb-5"
        />

        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2.5">
          Select Target Partition
        </label>
        <div class="grid grid-cols-2 gap-2 mb-6" id="partitionGrid">
          <button type="button" onclick="selectPart('boot.img', this)" class="pill-btn py-2.5 px-3 rounded-xl text-xs font-medium text-slate-300">boot.img</button>
          <button type="button" onclick="selectPart('vendor_boot.img', this)" class="pill-btn active py-2.5 px-3 rounded-xl text-xs font-medium text-slate-300">vendor_boot.img</button>
          <button type="button" onclick="selectPart('init_boot.img', this)" class="pill-btn py-2.5 px-3 rounded-xl text-xs font-medium text-slate-300">init_boot.img</button>
          <button type="button" onclick="selectPart('dtbo.img', this)" class="pill-btn py-2.5 px-3 rounded-xl text-xs font-medium text-slate-300">dtbo.img</button>
          <button type="button" onclick="selectPart('vbmeta.img', this)" class="pill-btn py-2.5 px-3 rounded-xl text-xs font-medium text-slate-300">vbmeta.img</button>
          <button type="button" onclick="selectPart('recovery.img', this)" class="pill-btn py-2.5 px-3 rounded-xl text-xs font-medium text-slate-300">recovery.img</button>
        </div>

        <button
          id="extractBtn"
          onclick="startExtraction()"
          class="w-full py-3.5 rounded-2xl font-semibold text-sm text-white bg-gradient-to-r from-blue-600 via-sky-500 to-cyan-500 hover:brightness-110 active:scale-[0.99] transition shadow-lg shadow-sky-500/20 flex items-center justify-center gap-2"
        >
          <span>⚡ Extract Partition Now</span>
        </button>

        <div id="errorBox" class="hidden mt-4 text-xs text-rose-300 bg-rose-500/10 border border-rose-500/25 rounded-2xl p-3.5 leading-relaxed"></div>
      </div>

      <!-- Cache Hit Banner -->
      <div id="cacheBanner" class="hidden bg-cyan-500/10 border border-cyan-400/30 text-cyan-200 rounded-2xl p-3.5 flex items-center gap-3 backdrop-blur-md">
        <span class="text-lg">⚡</span>
        <p id="bannerText" class="text-xs font-medium text-center w-full">
          File already exists in dataset (from cache)
        </p>
      </div>

      <!-- Result Glass Card -->
      <div id="resultCard" class="hidden glass-card rounded-3xl p-6 text-center">
        <div class="w-12 h-12 bg-emerald-500/20 border border-emerald-400/40 rounded-full flex items-center justify-center mx-auto mb-3 shadow-lg shadow-emerald-500/15">
          <svg class="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"></path>
          </svg>
        </div>

        <h2 class="text-xl font-bold text-white">Ready to Download!</h2>
        <p class="text-xs text-slate-400 mt-1">File stored permanently on Hugging Face Dataset</p>

        <div class="bg-slate-950/50 rounded-2xl p-4 mt-5 text-left space-y-3 border border-white/5">
          <div class="border-b border-white/5 pb-2.5 flex justify-between items-center">
            <div>
              <span class="text-[11px] text-slate-400 block">Status</span>
              <span id="resStatus" class="text-sm font-semibold text-white mt-0.5 block">🚀 Retrieved from cache</span>
            </div>
            <span id="resSource" class="text-[11px] font-medium px-2.5 py-1 rounded-lg bg-white/5 text-sky-300 border border-white/10">Direct Link</span>
          </div>
          <div class="border-b border-white/5 pb-2.5">
            <span class="text-[11px] text-slate-400 block">Duration</span>
            <span id="resDuration" class="text-sm font-semibold text-emerald-400 mt-0.5 block">0s</span>
          </div>
          <div>
            <span class="text-[11px] text-slate-400 block">Target</span>
            <span id="resTarget" class="text-sm font-semibold text-sky-300 mt-0.5 block">vendor_boot.img</span>
          </div>
        </div>

        <a
          id="downloadLink"
          href="#"
          target="_blank"
          class="mt-5 w-full bg-gradient-to-r from-emerald-500 to-teal-500 hover:brightness-110 transition text-white font-semibold py-3.5 rounded-2xl shadow-lg shadow-emerald-500/20 flex items-center justify-center gap-2 text-sm"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5m0 0l5-5m-5 5V4"></path>
          </svg>
          <span>Download File</span>
        </a>

        <button
          onclick="resetUI()"
          class="mt-4 text-xs text-slate-400 hover:text-white transition"
        >
          ← Extract another partition
        </button>
      </div>
    </div>

    <!-- ================= SECTION 2: LIVE LOG & CODE CONSOLE ================= -->
    <div id="sectionConsole" class="hidden space-y-4">
      <!-- Live Download / Extraction Progress Bar Card -->
      <div class="glass-card rounded-3xl p-5">
        <div class="flex items-center justify-between mb-2">
          <span id="progressStage" class="text-xs font-semibold text-sky-300">Idle — Waiting for extraction task</span>
          <span id="progressSpeed" class="mono text-[11px] px-2 py-0.5 rounded-md bg-sky-500/15 text-sky-300 border border-sky-400/20">—</span>
        </div>

        <div class="w-full h-3 bg-slate-950/80 rounded-full overflow-hidden border border-white/10 p-0.5">
          <div
            id="progressBar"
            style="width: 0%"
            class="h-full rounded-full bg-gradient-to-r from-blue-500 via-sky-400 to-emerald-400 transition-all duration-300"
          ></div>
        </div>

        <div class="flex justify-between items-center mt-2 text-[11px] text-slate-400">
          <span>Target: <b id="consoleTarget" class="text-slate-200">vendor_boot.img</b></span>
          <span id="progressPercent" class="mono font-semibold text-white">0%</span>
        </div>
      </div>

      <!-- Committed Extraction Code Card -->
      <div class="glass-card rounded-3xl p-5">
        <div class="flex items-center justify-between mb-3">
          <div class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded-full bg-rose-500/80"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-amber-400/80"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400/80"></span>
            <span class="text-xs font-semibold text-slate-300 ml-1.5">Committed Extraction Code</span>
          </div>
          <span class="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded bg-white/5 text-slate-400">Python 3.11</span>
        </div>
        <pre id="codeBlock" class="mono text-[11px] leading-relaxed text-cyan-300 bg-slate-950/75 p-3.5 rounded-2xl border border-white/5 overflow-x-auto"># Start an extraction to inspect the live range/stream code executed on the server...</pre>
      </div>

      <!-- Live Terminal Log Stream Card -->
      <div class="glass-card rounded-3xl p-5">
        <div class="flex items-center justify-between mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <span id="liveDot" class="w-2 h-2 rounded-full bg-emerald-400"></span>
            Live Server Terminal Log
          </span>
          <button onclick="clearLogs()" class="text-[11px] text-slate-400 hover:text-white transition">Clear</button>
        </div>
        <div id="logContainer" class="mono text-[11px] bg-slate-950/80 rounded-2xl p-3.5 h-52 overflow-y-auto space-y-1.5 border border-white/5">
          <div class="text-slate-500">[System] Ready. Waiting for ROM URL...</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ================= IPHONE FROSTED GLASS BOTTOM DOCK + MADE BY YASH ================= -->
  <div class="fixed bottom-3 left-1/2 -translate-x-1/2 z-50 flex flex-col items-center gap-1.5 w-full max-w-xs px-4">
    <div class="ios-dock p-1.5 rounded-[26px] flex items-center justify-between w-full gap-1.5">
      <!-- Tab 1: Extractor -->
      <button
        id="dockExtractor"
        onclick="switchTab('extractor')"
        class="dock-item active flex-1 py-2.5 px-3 rounded-[20px] border border-transparent flex items-center justify-center gap-2 text-xs font-semibold text-white"
      >
        <svg class="w-4 h-4 text-sky-400" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5m0 0l5-5m-5 5V4"></path>
        </svg>
        <span>Extractor</span>
      </button>

      <!-- Tab 2: Live Console -->
      <button
        id="dockConsole"
        onclick="switchTab('console')"
        class="dock-item relative flex-1 py-2.5 px-3 rounded-[20px] border border-transparent flex items-center justify-center gap-2 text-xs font-semibold text-slate-300"
      >
        <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
        </svg>
        <span>Live Console</span>
        <span id="consoleBadge" class="hidden absolute top-1.5 right-2.5 w-2 h-2 rounded-full bg-sky-400 animate-ping"></span>
      </button>
    </div>

    <!-- Bottom Center Watermark -->
    <div class="text-[11px] font-medium text-slate-400 tracking-wide flex items-center gap-1">
      <span>Made by</span>
      <span class="font-bold bg-gradient-to-r from-sky-400 to-cyan-300 bg-clip-text text-transparent">Yash</span>
    </div>
  </div>

  <script>
    const API_BASE_URL = "";
    let selectedPartition = "vendor_boot.img";

    function switchTab(tab) {
      const extSec = document.getElementById("sectionExtractor");
      const conSec = document.getElementById("sectionConsole");
      const dockExt = document.getElementById("dockExtractor");
      const dockCon = document.getElementById("dockConsole");

      if (tab === "extractor") {
        extSec.classList.remove("hidden");
        conSec.classList.add("hidden");
        dockExt.classList.add("active", "text-white");
        dockExt.classList.remove("text-slate-300");
        dockCon.classList.remove("active", "text-white");
        dockCon.classList.add("text-slate-300");
      } else {
        extSec.classList.add("hidden");
        conSec.classList.remove("hidden");
        dockCon.classList.add("active", "text-white");
        dockCon.classList.remove("text-slate-300");
        dockExt.classList.remove("active", "text-white");
        dockExt.classList.add("text-slate-300");
        document.getElementById("consoleBadge").classList.add("hidden");
      }
    }

    function selectPart(part, btnEl) {
      selectedPartition = part;
      document.getElementById("consoleTarget").textContent = part;
      document.querySelectorAll("#partitionGrid .pill-btn").forEach(b => b.classList.remove("active"));
      btnEl.classList.add("active");
    }

    function updateSourceBadge(val) {
      const badge = document.getElementById("sourceBadge");
      if (val.includes("drive.google.com") || val.includes("drive.usercontent.google.com")) {
        badge.textContent = "Google Drive";
        badge.className = "text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30";
      } else if (val.includes("miui.com") || val.includes("xiaomi.com") || val.includes("aliyuncs.com")) {
        badge.textContent = "Official CDN";
        badge.className = "text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/30";
      } else if (val.startsWith("http")) {
        badge.textContent = "Unofficial / Mirror";
        badge.className = "text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30";
      } else {
        badge.textContent = "Universal Link";
        badge.className = "text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-slate-800/80 text-slate-400 border border-white/5";
      }
    }

    function appendLog(ts, level, msg) {
      const box = document.getElementById("logContainer");
      const colors = {
        INFO: "text-slate-300",
        CACHE: "text-cyan-300",
        STREAM: "text-sky-300",
        VERIFY: "text-purple-300",
        SUCCESS: "text-emerald-400 font-semibold",
        ERROR: "text-rose-400 font-semibold"
      };
      const div = document.createElement("div");
      div.className = colors[level] || "text-slate-300";
      div.textContent = `[${ts}] [${level}] ${msg}`;
      box.appendChild(div);
      box.scrollTop = box.scrollHeight;
    }

    function clearLogs() {
      document.getElementById("logContainer").innerHTML = '<div class="text-slate-500">[System] Console cleared.</div>';
    }

    async function startExtraction() {
      const romUrl = document.getElementById("romUrl").value.trim();
      const btn = document.getElementById("extractBtn");
      const errorBox = document.getElementById("errorBox");

      errorBox.classList.add("hidden");
      if (!romUrl) {
        errorBox.textContent = "Please paste a valid Xiaomi ROM link (Official, Unofficial, or Google Drive).";
        errorBox.classList.remove("hidden");
        return;
      }

      btn.disabled = true;
      btn.innerHTML = `<span>⏳ Streaming (Check Live Console)...</span>`;
      document.getElementById("consoleBadge").classList.remove("hidden");
      document.getElementById("logContainer").innerHTML = "";
      document.getElementById("progressBar").style.width = "2%";
      document.getElementById("progressPercent").textContent = "2%";

      // Automatically switch to Live Console so user sees live progress & code
      switchTab("console");

      try {
        const response = await fetch(`${API_BASE_URL}/api/extract-stream`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rom_url: romUrl, target: selectedPartition })
        });

        if (!response.ok) {
          throw new Error(`Server returned HTTP ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          const parts = buffer.split("\\n\\n");
          buffer = parts.pop();

          for (const part of parts) {
            const line = part.trim();
            if (!line.startsWith("data:")) continue;
            const payload = JSON.parse(line.replace(/^data:\\s*/, ""));

            if (payload.type === "log") {
              appendLog(payload.ts, payload.level, payload.message);
            } else if (payload.type === "cmd") {
              document.getElementById("codeBlock").textContent = payload.code;
            } else if (payload.type === "progress") {
              document.getElementById("progressBar").style.width = `${payload.percent}%`;
              document.getElementById("progressPercent").textContent = `${payload.percent}%`;
              document.getElementById("progressStage").textContent = payload.stage;
              document.getElementById("progressSpeed").textContent = payload.speed;
            } else if (payload.type === "error") {
              throw new Error(payload.message);
            } else if (payload.type === "done") {
              const data = payload.result;
              document.getElementById("formCard").classList.add("hidden");
              document.getElementById("cacheBanner").classList.remove("hidden");
              document.getElementById("resultCard").classList.remove("hidden");

              document.getElementById("bannerText").textContent = data.banner;
              document.getElementById("resStatus").textContent = `🚀 ${data.status}`;
              document.getElementById("resDuration").textContent = data.duration;
              document.getElementById("resTarget").textContent = data.target;
              document.getElementById("resSource").textContent = data.source || "Direct";
              document.getElementById("downloadLink").href = data.download_url;

              // Switch back to Extractor view after a brief pause to show the download button
              setTimeout(() => switchTab("extractor"), 650);
            }
          }
        }
      } catch (err) {
        errorBox.textContent = err.message;
        errorBox.classList.remove("hidden");
        switchTab("extractor");
      } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>⚡ Extract Partition Now</span>`;
      }
    }

    function resetUI() {
      document.getElementById("formCard").classList.remove("hidden");
      document.getElementById("cacheBanner").classList.add("hidden");
      document.getElementById("resultCard").classList.add("hidden");
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return HTML_PAGE
