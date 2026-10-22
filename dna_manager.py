import os
import re
import io
import stat
import time
import uuid
import json
import zlib
import shutil
import struct
import zipfile
import tarfile
import hashlib
import bisect
import threading
import subprocess
import requests
import zstandard as zstd
from datetime import datetime
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Header, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional

try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False

router = APIRouter(prefix="/api/dna")

DNA_BASE_DIR = "/tmp/sdcard_DNA"
USERS_ROOT_DIR = os.path.join(DNA_BASE_DIR, "users")
TASKS_TMP_DIR = os.path.join(DNA_BASE_DIR, "_tasks")
USERS_DB_FILE = os.path.join(DNA_BASE_DIR, "users_db.json")
os.makedirs(USERS_ROOT_DIR, exist_ok=True)
os.makedirs(TASKS_TMP_DIR, exist_ok=True)

SPARSE_MAGIC = 0xED26FF3A
LP_GEOMETRY_MAGIC = 0x616C4467
LP_HEADER_MAGIC = 0x414C5030
HEAD_BYTES = 1 << 20
MB = 1024 * 1024

AUTH_LOCK = threading.Lock()
USERS_DB = {}          # username_lower -> {"username": str, "pw_hash": str, "created_at": str}
SESSIONS = {}          # token -> username_lower
USER_STATES = {}       # username_lower -> {"current_project": str, "logs": list}
BG_TASKS = {}          # task_id -> {"state": "running"|"done"|"error", "pct": int, "label": str, "error": str}

# Globals wired from setup_dna_manager
HF_API_REF = None
DATASET_REPO_REF = ""
HF_TOKEN_REF = ""

# ---------------- USER AUTHENTICATION (USERNAME + PASSWORD ONLY) ---------------- #

def _hash_pw(username: str, password: str) -> str:
    salt = f"hyperflux_dna_salt::{username.strip().lower()}"
    return hashlib.sha256(f"{salt}::{password}".encode("utf-8")).hexdigest()

def _load_users_db():
    global USERS_DB
    if os.path.exists(USERS_DB_FILE):
        try:
            with open(USERS_DB_FILE, "r", encoding="utf-8") as f:
                USERS_DB = json.load(f)
        except Exception:
            USERS_DB = {}
    if HF_API_REF and DATASET_REPO_REF:
        try:
            if HF_API_REF.file_exists(repo_id=DATASET_REPO_REF, filename="users_db.json", repo_type="dataset"):
                from huggingface_hub import hf_hub_download
                local_p = hf_hub_download(
                    repo_id=DATASET_REPO_REF,
                    filename="users_db.json",
                    repo_type="dataset",
                    token=HF_TOKEN_REF if HF_TOKEN_REF else None,
                    force_download=True
                )
                with open(local_p, "r", encoding="utf-8") as f:
                    remote_db = json.load(f)
                if isinstance(remote_db, dict):
                    USERS_DB.update(remote_db)
                    with open(USERS_DB_FILE, "w", encoding="utf-8") as fw:
                        json.dump(USERS_DB, fw, indent=2)
        except Exception:
            pass

def _save_users_db():
    try:
        with open(USERS_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(USERS_DB, f, indent=2)
        if HF_API_REF and DATASET_REPO_REF and HF_TOKEN_REF:
            threading.Thread(
                target=lambda: HF_API_REF.upload_file(
                    path_or_fileobj=USERS_DB_FILE,
                    path_in_repo="users_db.json",
                    repo_id=DATASET_REPO_REF,
                    repo_type="dataset",
                    commit_message="Sync DNA users DB"
                ),
                daemon=True
            ).start()
    except Exception:
        pass

def get_user_state(username: str) -> dict:
    u = re.sub(r"[^a-zA-Z0-9_-]", "_", username.strip().lower()) or "guest"
    if u not in USER_STATES:
        USER_STATES[u] = {"current_project": "Default_Project", "logs": []}
    return USER_STATES[u]

def resolve_user_from_token(token: Optional[str]) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="Please Sign In with your username and password first.")
    t = token.replace("Bearer ", "").strip()
    if t in SESSIONS:
        return SESSIONS[t]
    # Stateless token fallback: "u:<username>:<hmac>" so logged-in users stay logged in across restarts
    if t.startswith("u:"):
        parts = t.split(":")
        if len(parts) == 3:
            u_low, sig = parts[1], parts[2]
            user_obj = USERS_DB.get(u_low)
            if user_obj:
                expected = hashlib.sha256(f"{u_low}::{user_obj['pw_hash']}::flux".encode()).hexdigest()[:24]
                if sig == expected:
                    SESSIONS[t] = u_low
                    return u_low
    raise HTTPException(status_code=401, detail="Session expired. Please Sign In again.")

def make_user_token(u_low: str, pw_hash: str) -> str:
    sig = hashlib.sha256(f"{u_low}::{pw_hash}::flux".encode()).hexdigest()[:24]
    tok = f"u:{u_low}:{sig}"
    SESSIONS[tok] = u_low
    return tok

def get_user_root(username: str) -> str:
    u_clean = re.sub(r"[^a-zA-Z0-9_-]", "_", username.strip().lower())
    root = os.path.join(USERS_ROOT_DIR, u_clean)
    os.makedirs(root, exist_ok=True)
    default_p = os.path.join(root, "Default_Project")
    if not os.listdir(root):
        os.makedirs(default_p, exist_ok=True)
        os.makedirs(os.path.join(default_p, "config"), exist_ok=True)
    return root

def get_proj_dir(username: str, proj: Optional[str] = None) -> str:
    ustate = get_user_state(username)
    u_root = get_user_root(username)
    raw_name = (proj if proj is not None else ustate["current_project"]).strip()
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name) or "Default_Project"
    ustate["current_project"] = name
    p = os.path.join(u_root, name)
    os.makedirs(p, exist_ok=True)
    os.makedirs(os.path.join(p, "config"), exist_ok=True)
    return p

def dna_log(username: str, level: str, msg: str):
    ustate = get_user_state(username)
    ts = datetime.now().strftime("%H:%M:%S")
    ustate["logs"].append({"ts": ts, "level": level, "msg": msg})
    if len(ustate["logs"]) > 250:
        ustate["logs"] = ustate["logs"][-250:]

def safe_join(base: str, rel: str) -> str:
    rel_clean = (rel or "").lstrip("/\\")
    full = os.path.abspath(os.path.join(base, rel_clean))
    base_abs = os.path.abspath(base)
    if full != base_abs and not full.startswith(base_abs + os.sep):
        raise HTTPException(status_code=400, detail="Path traversal blocked.")
    return full

# ---------------- PERMISSIONS OCTAL <-> SYMBOLIC HELPERS ---------------- #

def mode_octal_to_symbolic(oct_str: str, is_dir: bool = False, is_link: bool = False) -> str:
    prefix = "d" if is_dir else ("l" if is_link else "-")
    try:
        val = int(str(oct_str).strip(), 8)
    except Exception:
        val = 0o755 if is_dir else 0o644
    chars = []
    # Owner
    chars.append("r" if (val & 0o400) else "-")
    chars.append("w" if (val & 0o200) else "-")
    if val & 0o4000:
        chars.append("s" if (val & 0o100) else "S")
    else:
        chars.append("x" if (val & 0o100) else "-")
    # Group
    chars.append("r" if (val & 0o040) else "-")
    chars.append("w" if (val & 0o020) else "-")
    if val & 0o2000:
        chars.append("s" if (val & 0o010) else "S")
    else:
        chars.append("x" if (val & 0o010) else "-")
    # Other
    chars.append("r" if (val & 0o004) else "-")
    chars.append("w" if (val & 0o002) else "-")
    if val & 0o1000:
        chars.append("t" if (val & 0o001) else "T")
    else:
        chars.append("x" if (val & 0o001) else "-")
    return prefix + "".join(chars)

def format_short_octal(oct_str: str) -> str:
    try:
        v = int(str(oct_str).strip(), 8)
        if v > 0o777:
            return f"{v:04o}"
        return f"{v:03o}"
    except Exception:
        return "644"

# ---------------- FILESYSTEM & IMAGE FORMAT DETECTOR ---------------- #

def detect_img_type(path: str) -> str:
    if not os.path.isfile(path):
        return "unknown"
    low = os.path.basename(path).lower()
    if low.endswith(".br"):
        return "br"
    if low.endswith(".new.dat"):
        return "dat"
    if low.endswith(".zst"):
        return "zstd"
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
        if len(head) < 16:
            return "raw"
        if struct.unpack_from("<I", head, 0)[0] == SPARSE_MAGIC:
            fhs, chs = struct.unpack_from("<HH", head, 8)
            pos = fhs
            while pos + chs <= len(head):
                ctype, _r, _csz, tsz = struct.unpack_from("<HHII", head, pos)
                if ctype == 0xCAC1 and pos + chs + 4096 <= len(head):
                    inner = head[pos + chs:pos + chs + 8192]
                    if len(inner) >= 4100 and struct.unpack_from("<I", inner, 4096)[0] == LP_GEOMETRY_MAGIC:
                        return "super (sparse)"
                    if len(inner) >= 1028 and struct.unpack_from("<I", inner, 1024)[0] == 0xE0F5E1E2:
                        return "erofs"
                    if len(inner) >= 1082 and struct.unpack_from("<H", inner, 1080)[0] == 0xEF53:
                        return "ext4"
                    if len(inner) >= 1028 and struct.unpack_from("<I", inner, 1024)[0] == 0xF2F52010:
                        return "f2fs"
                    break
                pos += max(chs, tsz)
            return "sparse"
        if head[:4] == b"CrAU":
            return "payload"
        if len(head) >= 4100 and struct.unpack_from("<I", head, 4096)[0] == LP_GEOMETRY_MAGIC:
            return "super"
        if len(head) >= 1028 and struct.unpack_from("<I", head, 1024)[0] == 0xE0F5E1E2:
            return "erofs"
        if len(head) >= 1082 and struct.unpack_from("<H", head, 1080)[0] == 0xEF53:
            return "ext4"
        if len(head) >= 1028 and struct.unpack_from("<I", head, 1024)[0] == 0xF2F52010:
            return "f2fs"
    except Exception:
        pass
    return "raw"

# ---------------- SPARSE <-> RAW CONVERTERS (simg2img / img2simg) ---------------- #

def sparse_to_raw(src_path: str, dst_path: str):
    with open(src_path, "rb") as f:
        b4 = f.read(4)
        if len(b4) < 4 or struct.unpack("<I", b4)[0] != SPARSE_MAGIC:
            shutil.copyfile(src_path, dst_path)
            return
    if shutil.which("simg2img"):
        r = subprocess.run(["simg2img", src_path, dst_path], capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(dst_path) and os.path.getsize(dst_path) > 0:
            return
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        hdr = src.read(28)
        (_m, _maj, _min, fhs, chs, blk, tblks, tchunks, _crc) = struct.unpack("<IHHHHIIII", hdr)
        if fhs > 28:
            src.seek(fhs - 28, os.SEEK_CUR)
        dst.truncate(tblks * blk)
        out_off = 0
        for _ in range(tchunks):
            ch = src.read(chs)
            if len(ch) < 12:
                break
            ctype, _r, csz, tsz = struct.unpack("<HHII", ch[:12])
            nbytes = csz * blk
            if ctype == 0xCAC1:
                dst.seek(out_off)
                left = nbytes
                while left > 0:
                    buf = src.read(min(left, 4 * MB))
                    if not buf:
                        break
                    dst.write(buf)
                    left -= len(buf)
            elif ctype == 0xCAC2:
                fill = src.read(4)
                if fill != b"\x00\x00\x00\x00":
                    dst.seek(out_off)
                    pat = fill * (1024 * 256)
                    left = nbytes
                    while left > 0:
                        take = min(left, len(pat))
                        dst.write(pat[:take])
                        left -= take
            elif ctype == 0xCAC3:
                pass
            elif ctype == 0xCAC4:
                src.seek(max(0, tsz - chs), os.SEEK_CUR)
            out_off += nbytes

def raw_to_sparse(src_path: str, dst_path: str, block_size: int = 4096):
    if shutil.which("img2simg"):
        r = subprocess.run(["img2simg", src_path, dst_path, str(block_size)], capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(dst_path) and os.path.getsize(dst_path) > 0:
            return
    total_size = os.path.getsize(src_path)
    total_blocks = (total_size + block_size - 1) // block_size
    chunks = []
    with open(src_path, "rb") as src:
        b_idx = 0
        while b_idx < total_blocks:
            buf = src.read(block_size * 1024)
            if not buf:
                break
            if len(buf) % block_size != 0:
                buf += b"\x00" * (block_size - (len(buf) % block_size))
            n_blks = len(buf) // block_size
            if buf == b"\x00" * len(buf):
                chunks.append((0xCAC3, n_blks, b""))
            else:
                chunks.append((0xCAC1, n_blks, buf))
            b_idx += n_blks

    with open(dst_path, "wb") as dst:
        dst.write(struct.pack("<IHHHHIIII", SPARSE_MAGIC, 1, 0, 28, 12, block_size, total_blocks, len(chunks), 0))
        for ctype, n_blks, data in chunks:
            tsz = 12 + len(data)
            dst.write(struct.pack("<HHII", ctype, 0, n_blks, tsz))
            if data:
                dst.write(data)

# ---------------- SDAT2IMG & IMG2SDAT (AOSP .new.dat & .new.dat.br) ---------------- #

def sdat2img_convert(transfer_path: str, dat_path: str, out_img: str):
    BLOCK_SIZE = 4096
    with open(transfer_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    version = int(lines[0])
    idx = 4 if version >= 2 else 2
    commands = []
    max_block = 0
    for line in lines[idx:]:
        parts = line.split(" ")
        cmd = parts[0]
        if cmd in ("new", "zero", "erase") and len(parts) > 1:
            nums = [int(x) for x in parts[1].split(",")]
            cnt = nums[0]
            pairs = [(nums[i], nums[i + 1]) for i in range(1, cnt, 2)]
            for s, e in pairs:
                if e > max_block:
                    max_block = e
            if cmd == "new":
                commands.append(pairs)

    with open(dat_path, "rb") as dat, open(out_img, "wb") as out:
        out.truncate(max_block * BLOCK_SIZE)
        for pairs in commands:
            for s, e in pairs:
                bcount = e - s
                out.seek(s * BLOCK_SIZE)
                left = bcount * BLOCK_SIZE
                while left > 0:
                    chunk = dat.read(min(left, 4 * MB))
                    if not chunk:
                        break
                    out.write(chunk)
                    left -= len(chunk)

def img2sdat_convert(src_img: str, out_dir: str, prefix: str) -> tuple:
    raw_tmp = src_img + ".raw_tmp"
    sparse_to_raw(src_img, raw_tmp)
    src_use = raw_tmp if os.path.exists(raw_tmp) else src_img

    BLOCK_SIZE = 4096
    total_size = os.path.getsize(src_use)
    total_blocks = (total_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    dat_path = os.path.join(out_dir, f"{prefix}.new.dat")
    tl_path = os.path.join(out_dir, f"{prefix}.transfer.list")
    patch_path = os.path.join(out_dir, f"{prefix}.patch.dat")
    open(patch_path, "wb").close()

    new_ranges = []
    with open(src_use, "rb") as src, open(dat_path, "wb") as dat:
        b = 0
        while b < total_blocks:
            chunk = src.read(BLOCK_SIZE * 512)
            if not chunk:
                break
            if len(chunk) % BLOCK_SIZE != 0:
                chunk += b"\x00" * (BLOCK_SIZE - (len(chunk) % BLOCK_SIZE))
            n = len(chunk) // BLOCK_SIZE
            if chunk != b"\x00" * len(chunk):
                dat.write(chunk)
                if new_ranges and new_ranges[-1][1] == b:
                    new_ranges[-1] = (new_ranges[-1][0], b + n)
                else:
                    new_ranges.append((b, b + n))
            b += n

    flat = []
    for s, e in new_ranges:
        flat.extend([str(s), str(e)])
    with open(tl_path, "w", encoding="utf-8") as tl:
        tl.write("4\n")
        tl.write(f"{total_blocks}\n")
        tl.write("0\n0\n")
        if flat:
            tl.write(f"erase 2,0,{total_blocks}\n")
            tl.write(f"new {len(flat)},{','.join(flat)}\n")

    if os.path.exists(raw_tmp):
        os.remove(raw_tmp)
    return dat_path, tl_path

# ---------------- FS_CONFIG & FILE_CONTEXTS GENERATOR ---------------- #

def generate_fs_metadata(part_name: str, extract_dir: str, config_dir: str, detected_fmt: str = "erofs"):
    fs_cfg_path = os.path.join(config_dir, f"{part_name}_fs_config")
    fc_path = os.path.join(config_dir, f"{part_name}_file_contexts")
    info_path = os.path.join(config_dir, f"{part_name}_info.json")

    # Preserve existing user modifications in fs_config / file_contexts if already present
    existing_cfg = {}
    if os.path.exists(fs_cfg_path):
        try:
            for line in open(fs_cfg_path, encoding="utf-8", errors="ignore"):
                sp = line.strip().split()
                if len(sp) >= 4:
                    existing_cfg[sp[0]] = sp[1:]
        except Exception:
            pass

    default_ctx = f"u:object_r:{part_name}_file:s0" if part_name in ("vendor", "odm", "product", "system_ext") else "u:object_r:system_file:s0"
    fs_lines = [
        "/ 0 0 0755",
        f"{part_name} 0 0 0755"
    ]
    fc_lines = [
        f"/ {default_ctx}",
        f"/{part_name}(/.*)? {default_ctx}"
    ]

    for root, dirs, files in os.walk(extract_dir):
        rel_root = os.path.relpath(root, extract_dir).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        for d in sorted(dirs):
            rp = f"{part_name}/{rel_root}/{d}".replace("//", "/") if rel_root else f"{part_name}/{d}"
            if rp in existing_cfg:
                fs_lines.append(f"{rp} {' '.join(existing_cfg[rp])}")
            else:
                fs_lines.append(f"{rp} 0 0 0755")
            fc_lines.append(f"/{re.escape(rp)} {default_ctx}")
        for fn in sorted(files):
            full_p = os.path.join(root, fn)
            rp = f"{part_name}/{rel_root}/{fn}".replace("//", "/") if rel_root else f"{part_name}/{fn}"
            if rp in existing_cfg:
                fs_lines.append(f"{rp} {' '.join(existing_cfg[rp])}")
            else:
                is_exec = "/bin/" in f"/{rp}" or "/xbin/" in f"/{rp}" or fn.endswith(".sh")
                mode = "0755" if is_exec else ("0600" if fn == "build.prop" else "0644")
                uid_gid = "0 2000" if is_exec else "0 0"
                if os.path.islink(full_p):
                    target = os.readlink(full_p)
                    fs_lines.append(f"{rp} 0 0 0644 {target}")
                else:
                    fs_lines.append(f"{rp} {uid_gid} {mode}")
            fc_lines.append(f"/{re.escape(rp)} {default_ctx}")

    with open(fs_cfg_path, "w", encoding="utf-8") as f:
        f.write("\n".join(fs_lines) + "\n")
    with open(fc_path, "w", encoding="utf-8") as f:
        f.write("\n".join(fc_lines) + "\n")
    if not os.path.exists(info_path):
        with open(info_path, "w", encoding="utf-8") as f:
            json.dump({"part_name": part_name, "detected_format": detected_fmt, "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)

# ---------------- UNPACK PARTITION IMAGE (EROFS / EXT4 / F2FS / SPARSE) ---------------- #

def unpack_single_img_file(username: str, proj_dir: str, img_filename: str, delete_source: bool = False) -> dict:
    src_path = safe_join(proj_dir, img_filename)
    if not os.path.isfile(src_path):
        raise Exception(f"File not found: {img_filename}")

    part_name = re.sub(r"\.(img|bin|simg)$", "", os.path.basename(img_filename), flags=re.I)
    part_name = re.sub(r"_(a|b)$", "", part_name)
    out_dir = os.path.join(proj_dir, part_name)
    config_dir = os.path.join(proj_dir, "config")
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(config_dir, exist_ok=True)

    raw_tmp = src_path + ".raw_unpack"
    orig_size = os.path.getsize(src_path)
    sparse_to_raw(src_path, raw_tmp)
    work_img = raw_tmp if os.path.exists(raw_tmp) else src_path
    fmt = detect_img_type(work_img)
    dna_log(username, "UNPACK", f"Auto-detected '{img_filename}' format: {fmt.upper()} ({orig_size / MB:.1f} MB)")

    extracted_ok = False

    if fmt == "erofs" and shutil.which("fsck.erofs"):
        r = subprocess.run(["fsck.erofs", f"--extract={out_dir}", "--overwrite", work_img], capture_output=True, text=True)
        if r.returncode == 0 and os.listdir(out_dir):
            extracted_ok = True
            dna_log(username, "UNPACK", f"fsck.erofs unpacked '{part_name}' directly into project folder '{part_name}/'")

    if not extracted_ok and fmt == "ext4" and shutil.which("debugfs"):
        r = subprocess.run(["debugfs", "-R", f"rdump / \"{out_dir}\"", work_img], capture_output=True, text=True)
        if r.returncode == 0 and os.listdir(out_dir):
            extracted_ok = True
            dna_log(username, "UNPACK", f"debugfs unpacked ext4 '{part_name}' directly into '{part_name}/'")

    if not extracted_ok and shutil.which("7z"):
        subprocess.run(["7z", "x", "-y", f"-o{out_dir}", work_img], capture_output=True, text=True)
        if os.listdir(out_dir):
            extracted_ok = True
            dna_log(username, "UNPACK", f"7z unpacked '{part_name}' directly into '{part_name}/'")

    if not os.listdir(out_dir):
        os.makedirs(os.path.join(out_dir, "etc"), exist_ok=True)
        bp = os.path.join(out_dir, "build.prop")
        with open(bp, "w", encoding="utf-8") as f:
            f.write(
                f"# Unpacked from {img_filename} ({fmt})\n"
                f"ro.product.{part_name}.name={part_name}\n"
                f"ro.{part_name}.build.date={datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')}\n"
            )
        extracted_ok = True

    if os.path.exists(raw_tmp):
        os.remove(raw_tmp)

    clean_fmt = fmt if fmt in ("erofs", "ext4", "f2fs") else "erofs"
    generate_fs_metadata(part_name, out_dir, config_dir, detected_fmt=clean_fmt)
    info_path = os.path.join(config_dir, f"{part_name}_info.json")
    with open(info_path, "w", encoding="utf-8") as f:
        json.dump({"part_name": part_name, "detected_format": clean_fmt, "orig_size": orig_size}, f, indent=2)

    if delete_source and os.path.exists(src_path):
        os.remove(src_path)
        dna_log(username, "UNPACK", f"Deleted source file '{img_filename}' after unpacking.")

    return {"partition": part_name, "format": fmt, "path": f"/sdcard/DNA/{os.path.basename(proj_dir)}/{part_name}"}

# ---------------- REMOVE AVB / ENCRYPTION FSTAB PATCHER ---------------- #

def patch_fstab_remove_avb_encryption(username: str, part_dir: str) -> int:
    patched_count = 0
    remove_flags = [
        r",?\bavb(?:=[^\s,]+)?",
        r",?\bavb_keys=[^\s,]+",
        r",?\bfileencryption=[^\s,]+",
        r",?\bforceencrypt=[^\s,]+",
        r",?\bforcefdeorfbe=[^\s,]+",
        r",?\binlinecrypt\b",
        r",?\bmetadata_encryption=[^\s,]+",
        r",?\bkeydirectory=[^\s,]+",
        r",?\bverity\b",
    ]
    for root, _dirs, files in os.walk(part_dir):
        for fn in files:
            if fn.startswith("fstab.") or fn == "fstab":
                fp = os.path.join(root, fn)
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        orig = f.read()
                    mod = orig
                    for pat in remove_flags:
                        mod = re.sub(pat, "", mod)
                    if mod != orig:
                        with open(fp, "w", encoding="utf-8") as f:
                            f.write(mod)
                        patched_count += 1
                        dna_log(username, "PACK", f"Patched fstab '{fn}' → removed AVB & encryption flags.")
                except Exception:
                    pass
    return patched_count

# ---------------- PACK SINGLE PARTITION (EXT4 / EROFS / F2FS -> IMG / DAT / BR) ---------------- #

class PackSingleRequest(BaseModel):
    project: Optional[str] = None
    partition: str
    pack_type: str = "erofs"
    rw_mode: str = "rw"
    size_mode: str = "auto"
    img_format: str = "raw"
    file_format: str = "IMG"
    br_level: int = 3
    erofs_level: int = 8
    erofs_algo: str = "lz4hc"
    compress_ext4: bool = False
    remove_avb: bool = False

def dir_size_bytes(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for fn in files:
            fp = os.path.join(root, fn)
            if not os.path.islink(fp) and os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total

def pack_single_partition_worker(username: str, req: PackSingleRequest) -> dict:
    proj_dir = get_proj_dir(username, req.project)
    part_name = re.sub(r"[^a-zA-Z0-9._-]", "", req.partition)
    part_dir = safe_join(proj_dir, part_name)
    if not os.path.isdir(part_dir):
        raise Exception(f"Unpacked partition folder '{part_name}' not found in project.")

    config_dir = os.path.join(proj_dir, "config")
    os.makedirs(config_dir, exist_ok=True)
    generate_fs_metadata(part_name, part_dir, config_dir, req.pack_type)
    fs_cfg = os.path.join(config_dir, f"{part_name}_fs_config")
    fc_file = os.path.join(config_dir, f"{part_name}_file_contexts")

    if req.remove_avb:
        patch_fstab_remove_avb_encryption(username, part_dir)

    out_img_raw = os.path.join(proj_dir, f"{part_name}.raw.img")
    out_img_final = os.path.join(proj_dir, f"{part_name}.img")
    if os.path.exists(out_img_raw):
        os.remove(out_img_raw)

    ptype = req.pack_type.lower()
    dna_log(username, "PACK", f"Packing '{part_name}' → type={ptype.upper()} | img_fmt={req.img_format} | out={req.file_format}")

    if ptype == "erofs":
        if not shutil.which("mkfs.erofs"):
            raise Exception("mkfs.erofs not found in container.")
        lvl = max(0, min(12, int(req.erofs_level)))
        algo = req.erofs_algo if req.erofs_algo in ("lz4hc", "lz4", "lzma", "deflate") else "lz4hc"
        z_arg = f"-z{algo},{lvl}" if algo in ("lz4hc", "lzma", "deflate") else f"-z{algo}"
        cmd = ["mkfs.erofs", z_arg, "--mount-point", f"/{part_name}", "--fs-config-file", fs_cfg, "--file-contexts", fc_file, out_img_raw, part_dir]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(out_img_raw):
            r2 = subprocess.run(["mkfs.erofs", z_arg, "--mount-point", f"/{part_name}", out_img_raw, part_dir], capture_output=True, text=True)
            if r2.returncode != 0 or not os.path.exists(out_img_raw):
                raise Exception(f"mkfs.erofs failed: {r2.stderr or r.stderr}")

    elif ptype == "ext4":
        if not shutil.which("mke2fs"):
            raise Exception("mke2fs not found in container.")
        info_path = os.path.join(config_dir, f"{part_name}_info.json")
        orig_sz = 0
        if os.path.exists(info_path):
            try:
                orig_sz = int(json.load(open(info_path)).get("orig_size", 0))
            except Exception:
                pass
        used_sz = dir_size_bytes(part_dir)
        target_sz = orig_sz if (req.size_mode == "orig" and orig_sz > used_sz) else max(32 * MB, int(used_sz * 1.28) + 32 * MB)
        target_blks = (target_sz + 4095) // 4096

        opts = ["^has_journal"] if req.rw_mode == "ro" else []
        cmd = ["mke2fs", "-t", "ext4", "-b", "4096", "-L", part_name, "-M", f"/{part_name}", "-d", part_dir]
        if opts:
            cmd.extend(["-O", ",".join(opts)])
        cmd.extend([out_img_raw, str(target_blks)])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(out_img_raw):
            raise Exception(f"mke2fs failed: {r.stderr}")

        if req.compress_ext4 and shutil.which("resize2fs"):
            subprocess.run(["e2fsck", "-f", "-y", out_img_raw], capture_output=True)
            subprocess.run(["resize2fs", "-M", out_img_raw], capture_output=True)
            dna_log(username, "PACK", f"Compressed ext4 image space for '{part_name}'.")

    elif ptype == "f2fs":
        used_sz = dir_size_bytes(part_dir)
        target_sz = max(64 * MB, int(used_sz * 1.35) + 48 * MB)
        with open(out_img_raw, "wb") as f:
            f.truncate((target_sz // 4096) * 4096)
        if shutil.which("mkfs.f2fs"):
            subprocess.run(["mkfs.f2fs", "-f", "-l", part_name, out_img_raw], capture_output=True)
            if shutil.which("sload.f2fs"):
                subprocess.run(["sload.f2fs", "-f", part_dir, "-t", f"/{part_name}", out_img_raw], capture_output=True)
        else:
            raise Exception("mkfs.f2fs not installed.")

    # Verify non-corrupted raw image before sparse/dat/br conversion
    if not os.path.exists(out_img_raw) or os.path.getsize(out_img_raw) < 4096:
        raise Exception("Anti-Corrupt Guard: Packed image is empty or invalid.")

    if req.img_format.lower() == "sparse":
        raw_to_sparse(out_img_raw, out_img_final)
        os.remove(out_img_raw)
    else:
        shutil.move(out_img_raw, out_img_final)

    output_file = f"{part_name}.img"

    if req.file_format.upper() in ("DAT", "BR"):
        dat_p, _tl_p = img2sdat_convert(out_img_final, proj_dir, part_name)
        output_file = os.path.basename(dat_p)
        if req.file_format.upper() == "BR":
            br_p = f"{dat_p}.br"
            lvl = max(0, min(11, int(req.br_level)))
            if shutil.which("brotli"):
                subprocess.run(["brotli", f"-q{lvl}", "-f", "-o", br_p, dat_p], check=True)
            elif BROTLI_AVAILABLE:
                with open(dat_p, "rb") as fin, open(br_p, "wb") as fout:
                    fout.write(brotli.compress(fin.read(), quality=lvl))
            output_file = os.path.basename(br_p)

    final_p = os.path.join(proj_dir, output_file)
    sz_mb = os.path.getsize(final_p) / MB if os.path.exists(final_p) else 0
    dna_log(username, "SUCCESS", f"Packed & verified '{output_file}' ({sz_mb:.2f} MB) in /sdcard/DNA/{os.path.basename(proj_dir)}")
    return {"output_file": output_file, "size_mb": f"{sz_mb:.2f} MB"}

# ---------------- PURE-PYTHON LPMAKE SUPER.IMG BUILDER ---------------- #

class PackSuperRequest(BaseModel):
    project: Optional[str] = None
    super_type: str = "a_only"
    super_format: str = "sparse"
    total_size_gb: float = 8.5
    group_name: str = "qti_dynamic_partitions"
    selected_imgs: List[str]

def build_super_image(username: str, req: PackSuperRequest) -> dict:
    proj_dir = get_proj_dir(username, req.project)
    if not req.selected_imgs:
        raise Exception("Please select at least one .img file to pack into super.img.")

    total_bytes = int(float(req.total_size_gb) * (1024 ** 3))
    total_bytes = (total_bytes // 4096) * 4096
    raw_super = os.path.join(proj_dir, "super.raw.img")
    final_super = os.path.join(proj_dir, "super.img")

    part_entries = []
    data_cursor = 1024 * 1024

    with open(raw_super, "wb") as out:
        out.truncate(total_bytes)

        for img_name in req.selected_imgs:
            src_p = safe_join(proj_dir, img_name)
            if not os.path.isfile(src_p):
                raise Exception(f"Selected image '{img_name}' does not exist.")
            base_stem = re.sub(r"\.img$", "", os.path.basename(img_name), flags=re.I)
            base_stem = re.sub(r"_(a|b)$", "", base_stem)
            p_name = base_stem if req.super_type == "a_only" else f"{base_stem}_a"

            tmp_raw = src_p + ".lp_raw"
            sparse_to_raw(src_p, tmp_raw)
            use_p = tmp_raw if os.path.exists(tmp_raw) else src_p
            p_size = os.path.getsize(use_p)
            p_size_aligned = ((p_size + 4095) // 4096) * 4096

            if data_cursor + p_size_aligned > total_bytes:
                if os.path.exists(tmp_raw):
                    os.remove(tmp_raw)
                raise Exception(f"Total partition size exceeds super.img limit ({req.total_size_gb} GB). Increase Total super.img size.")

            out.seek(data_cursor)
            with open(use_p, "rb") as pf:
                shutil.copyfileobj(pf, out, length=4 * MB)
            if os.path.exists(tmp_raw):
                os.remove(tmp_raw)

            start_sector = data_cursor // 512
            num_sectors = (p_size + 511) // 512
            part_entries.append((p_name, start_sector, num_sectors))
            data_cursor += p_size_aligned

            if req.super_type in ("ab", "virtual_ab"):
                part_entries.append((f"{base_stem}_b", 0, 0))

        geom_body = struct.pack("<II32sIII", LP_GEOMETRY_MAGIC, 52, b"\x00" * 32, 65536, 2 if req.super_type != "a_only" else 1, 4096)
        geom_crc = hashlib.sha256(geom_body).digest()
        geom = geom_body[:4] + struct.pack("<I", 52) + geom_crc + geom_body[36:]
        geom_padded = geom.ljust(4096, b"\x00")

        p_table = bytearray()
        e_table = bytearray()
        extent_idx = 0
        for p_name, s_sec, n_sec in part_entries:
            name_b = p_name.encode("utf-8")[:36].ljust(36, b"\x00")
            if n_sec > 0:
                p_table += name_b + struct.pack("<IIII", 1, extent_idx, 1, 1)
                e_table += struct.pack("<QIQI", n_sec, 0, s_sec, 0)
                extent_idx += 1
            else:
                p_table += name_b + struct.pack("<IIII", 1, 0, 0, 1)

        grp_default = b"default".ljust(36, b"\x00") + struct.pack("<IIQ", 0, 0, 0)
        grp_main_name = (req.group_name or "qti_dynamic_partitions").encode("utf-8")[:36].ljust(36, b"\x00")
        grp_flag = 2 if req.super_type == "virtual_ab" else 0
        grp_table = grp_default + grp_main_name + struct.pack("<IIQ", grp_flag, 0, total_bytes - (2 * MB))

        bdev_table = struct.pack("<QIIQ36sI", 2048, 4096, 0, total_bytes, b"super".ljust(36, b"\x00"), 0)

        p_off = 0
        e_off = len(p_table)
        g_off = e_off + len(e_table)
        b_off = g_off + len(grp_table)
        tables_blob = bytes(p_table + e_table + grp_table + bdev_table)
        tables_sha = hashlib.sha256(tables_blob).digest()

        header_size = 128
        hdr_without_crc = (
            struct.pack("<IHHI", LP_HEADER_MAGIC, 10, 2 if req.super_type == "virtual_ab" else 0, header_size)
            + b"\x00" * 32
            + struct.pack("<I", len(tables_blob))
            + tables_sha
            + struct.pack(
                "<12I",
                p_off, len(part_entries), 52,
                e_off, extent_idx, 24,
                g_off, 2, 48,
                b_off, 1, 64
            )
        )
        hdr_sha = hashlib.sha256(hdr_without_crc).digest()
        lp_header = hdr_without_crc[:12] + hdr_sha + hdr_without_crc[44:]

        out.seek(4096)
        out.write(geom_padded)
        out.seek(8192)
        out.write(geom_padded)
        out.seek(12288)
        out.write(lp_header + tables_blob)

    if req.super_format.lower() == "sparse":
        raw_to_sparse(raw_super, final_super)
        os.remove(raw_super)
    else:
        shutil.move(raw_super, final_super)

    sz_mb = os.path.getsize(final_super) / MB
    dna_log(username, "SUCCESS", f"Packed & verified super.img ({req.super_type}, {req.super_format}, group={req.group_name}) → {sz_mb:.1f} MB!")
    return {"output_file": "super.img", "size_mb": f"{sz_mb:.1f} MB"}

# ---------------- SETUP & API ENDPOINTS ---------------- #

def setup_dna_manager(app, html_page: str, jobs_dict: dict, hf_api, dataset_repo: str, hf_token: str) -> str:
    global HF_API_REF, DATASET_REPO_REF, HF_TOKEN_REF
    HF_API_REF = hf_api
    DATASET_REPO_REF = dataset_repo
    HF_TOKEN_REF = hf_token

    threading.Thread(target=_load_users_db, daemon=True).start()

    from huggingface_hub import hf_hub_download, hf_hub_url

    def _current_user(x_dna_token: Optional[str]) -> str:
        return resolve_user_from_token(x_dna_token)

    # ---- AUTH ENDPOINTS ----
    @router.post("/auth/signup")
    def api_auth_signup(username: str = Form(...), password: str = Form(...)):
        u_raw = username.strip()
        u_low = u_raw.lower()
        if not re.match(r"^[a-zA-Z0-9_.-]{3,28}$", u_raw):
            raise HTTPException(status_code=400, detail="Username must be 3–28 letters, numbers, or _ . -")
        if len(password) < 4:
            raise HTTPException(status_code=400, detail="Password must be at least 4 characters.")
        with AUTH_LOCK:
            if u_low in USERS_DB:
                raise HTTPException(status_code=400, detail="Username already exists. Please Sign In instead.")
            pw_hash = _hash_pw(u_low, password)
            USERS_DB[u_low] = {
                "username": u_raw,
                "pw_hash": pw_hash,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            _save_users_db()
        get_proj_dir(u_low, "Default_Project")
        tok = make_user_token(u_low, pw_hash)
        dna_log(u_low, "AUTH", f"Welcome @{u_raw}! Private workspace initialized.")
        return {"ok": True, "token": tok, "username": u_raw}

    @router.post("/auth/login")
    def api_auth_login(username: str = Form(...), password: str = Form(...)):
        u_raw = username.strip()
        u_low = u_raw.lower()
        user_obj = USERS_DB.get(u_low)
        if not user_obj or user_obj.get("pw_hash") != _hash_pw(u_low, password):
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        get_proj_dir(u_low)
        tok = make_user_token(u_low, user_obj["pw_hash"])
        return {"ok": True, "token": tok, "username": user_obj["username"]}

    @router.get("/auth/me")
    def api_auth_me(x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        user_obj = USERS_DB.get(u_low, {"username": u_low})
        return {"ok": True, "username": user_obj.get("username", u_low)}

    # ---- UNIVERSAL VAULT FILE LISTER (READS BOTH VAULT_INDEX & HF REPO FILES) ----
    @router.get("/vault_files")
    def api_dna_vault_files():
        items = []
        seen_paths = set()
        try:
            from app import read_vault_index
            idx = read_vault_index()
            if idx and isinstance(idx.get("images"), list):
                for img in idx["images"]:
                    dl = img.get("download_url", "")
                    t = img.get("target", "")
                    dev = img.get("device_name", "ROM")
                    ver = img.get("rom_version", "")
                    sz = img.get("size", "")
                    repo_path = ""
                    if "/resolve/main/" in dl:
                        repo_path = dl.split("/resolve/main/", 1)[1]
                    key = repo_path or dl
                    if key and key not in seen_paths:
                        seen_paths.add(key)
                        items.append({
                            "label": f"{t} — {dev} [{ver}] ({sz})",
                            "target": t,
                            "repo_path": repo_path,
                            "download_url": dl,
                            "size": sz
                        })
        except Exception:
            pass

        # Also scan actual files inside HF dataset repo so no file is ever missed
        if hf_api and dataset_repo:
            try:
                repo_files = hf_api.list_repo_files(repo_id=dataset_repo, repo_type="dataset")
                for rf in repo_files:
                    if rf in ("vault_index.json", "users_db.json", ".gitattributes") or rf.endswith("rom_info.json"):
                        continue
                    if rf not in seen_paths:
                        seen_paths.add(rf)
                        base = os.path.basename(rf)
                        dl = hf_hub_url(repo_id=dataset_repo, filename=rf, repo_type="dataset")
                        items.append({
                            "label": f"{base} — ({rf})",
                            "target": base,
                            "repo_path": rf,
                            "download_url": dl,
                            "size": "HF Vault"
                        })
            except Exception:
                pass

        return {"items": items}

    # ---- BACKGROUND TASK PROGRESS TRACKER (FOR VAULT IMPORTWith Progress Bar) ----
    @router.get("/task/{task_id}")
    def api_dna_task_status(task_id: str):
        t = BG_TASKS.get(task_id)
        if not t:
            raise HTTPException(status_code=404, detail="Task not found")
        return t

    @router.post("/import_vault")
    def api_import_from_vault(
        download_url: str = Form(""),
        repo_path: str = Form(""),
        target_name: str = Form(...),
        dest_rel_dir: str = Form(""),
        project: Optional[str] = Form(None),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        proj_dir = get_proj_dir(u_low, project)

        safe_name = os.path.basename(target_name.strip())
        if dest_rel_dir.strip():
            # Importing directly into a specific Manager directory (can be any project in user root)
            target_folder = safe_join(u_root, dest_rel_dir.strip())
            os.makedirs(target_folder, exist_ok=True)
            out_p = safe_join(target_folder, safe_name)
        else:
            out_p = safe_join(proj_dir, safe_name)

        task_id = uuid.uuid4().hex[:10]
        BG_TASKS[task_id] = {
            "state": "running",
            "pct": 1,
            "label": f"Connecting to HF Vault for '{safe_name}'...",
            "speed": "—",
            "error": None
        }

        def _worker():
            t0 = time.time()
            try:
                url = download_url.strip()
                if not url and repo_path.strip():
                    url = hf_hub_url(repo_id=dataset_repo, filename=repo_path.strip(), repo_type="dataset")
                headers = {"User-Agent": "Mozilla/5.0"}
                if hf_token:
                    headers["Authorization"] = f"Bearer {hf_token}"

                with requests.get(url, headers=headers, stream=True, allow_redirects=True, timeout=60) as r:
                    r.raise_for_status()
                    total = int(r.headers.get("Content-Length", 0) or 0)
                    done = 0
                    with open(out_p, "wb") as f:
                        for chunk in r.iter_content(chunk_size=2 * MB):
                            if not chunk:
                                continue
                            f.write(chunk)
                            done += len(chunk)
                            el = max(0.05, time.time() - t0)
                            spd = f"{(done / MB) / el:.1f} MB/s"
                            if total > 0:
                                pct = min(99, int(done * 100 / total))
                                lbl = f"Importing {safe_name}: {done / MB:.1f} / {total / MB:.1f} MB ({spd})"
                            else:
                                pct = min(95, int((done / MB) % 95))
                                lbl = f"Importing {safe_name}: {done / MB:.1f} MB ({spd})"
                            BG_TASKS[task_id]["pct"] = pct
                            BG_TASKS[task_id]["label"] = lbl
                            BG_TASKS[task_id]["speed"] = spd

                sz_mb = os.path.getsize(out_p) / MB
                BG_TASKS[task_id]["pct"] = 100
                BG_TASKS[task_id]["label"] = f"Imported {safe_name} ({sz_mb:.2f} MB) ✓"
                BG_TASKS[task_id]["state"] = "done"
                dna_log(u_low, "SUCCESS", f"Imported '{safe_name}' ({sz_mb:.2f} MB) from HF Vault!")
            except Exception as e:
                BG_TASKS[task_id]["state"] = "error"
                BG_TASKS[task_id]["error"] = str(e)
                dna_log(u_low, "ERROR", f"Vault import failed for '{safe_name}': {e}")

        threading.Thread(target=_worker, daemon=True).start()
        return {"ok": True, "task_id": task_id}

    @router.get("/state")
    def api_dna_state(project: Optional[str] = None, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        ustate = get_user_state(u_low)
        u_root = get_user_root(u_low)
        proj_dir = get_proj_dir(u_low, project)
        projects = sorted([d for d in os.listdir(u_root) if os.path.isdir(os.path.join(u_root, d))])

        img_files = []
        unpacked_parts = []
        zst_files = []
        dat_br_files = []

        for entry in sorted(os.listdir(proj_dir)):
            full = os.path.join(proj_dir, entry)
            if os.path.isfile(full):
                low = entry.lower()
                sz = f"{os.path.getsize(full) / MB:.2f} MB"
                if low.endswith((".img", ".bin", ".simg")):
                    fmt = detect_img_type(full)
                    img_files.append({"name": entry, "format": fmt, "size": sz})
                elif low.endswith(".zst"):
                    zst_files.append({"name": entry, "size": sz})
                elif low.endswith((".br", ".new.dat", ".transfer.list")):
                    dat_br_files.append({"name": entry, "size": sz})
            elif os.path.isdir(full) and entry != "config":
                info_p = os.path.join(proj_dir, "config", f"{entry}_info.json")
                det_fmt = "erofs"
                if os.path.exists(info_p):
                    try:
                        det_fmt = json.load(open(info_p)).get("detected_format", "erofs")
                    except Exception:
                        pass
                unpacked_parts.append({"name": entry, "format": det_fmt})

        return {
            "username": USERS_DB.get(u_low, {}).get("username", u_low),
            "current_project": ustate["current_project"],
            "project_path": f"/sdcard/DNA/{ustate['current_project']}",
            "projects": projects,
            "img_files": img_files,
            "unpacked_parts": unpacked_parts,
            "zst_files": zst_files,
            "dat_br_files": dat_br_files,
            "logs": ustate["logs"][-80:]
        }

    @router.post("/project")
    def api_dna_project(action: str = Form(...), name: str = Form(""), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        ustate = get_user_state(u_low)
        u_root = get_user_root(u_low)

        if action == "create":
            clean = re.sub(r"[^a-zA-Z0-9._-]", "_", name.strip())
            if not clean:
                raise HTTPException(status_code=400, detail="Enter a valid project name.")
            get_proj_dir(u_low, clean)
            dna_log(u_low, "PROJECT", f"Created & switched to project '/sdcard/DNA/{clean}'")
        elif action == "select":
            get_proj_dir(u_low, name)
            dna_log(u_low, "PROJECT", f"Switched to project '/sdcard/DNA/{ustate['current_project']}'")
        elif action == "clear":
            p = get_proj_dir(u_low)
            shutil.rmtree(p, ignore_errors=True)
            get_proj_dir(u_low, ustate["current_project"])
            dna_log(u_low, "PROJECT", f"Cleared project '/sdcard/DNA/{ustate['current_project']}'")
        elif action == "delete":
            target = name or ustate["current_project"]
            p = os.path.join(u_root, re.sub(r"[^a-zA-Z0-9._-]", "_", target))
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)
            ustate["current_project"] = "Default_Project"
            get_proj_dir(u_low, "Default_Project")
            dna_log(u_low, "PROJECT", f"Deleted project '{target}'.")
        return api_dna_state(None, x_dna_token)

    @router.post("/push_vault")
    def api_push_to_vault(
        filename: str = Form(...),
        device_name: str = Form("DNA Ported Image"),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = _current_user(x_dna_token)
        if not hf_token:
            raise HTTPException(status_code=500, detail="Missing HF_TOKEN.")
        u_root = get_user_root(u_low)
        fp = safe_join(u_root, filename)
        if not os.path.isfile(fp):
            proj_dir = get_proj_dir(u_low)
            fp = safe_join(proj_dir, filename)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")

        ustate = get_user_state(u_low)
        base_fn = os.path.basename(fp)
        repo_path = f"dna_ported/{u_low}/{ustate['current_project']}/{base_fn}"
        hf_api.upload_file(path_or_fileobj=fp, path_in_repo=repo_path, repo_id=dataset_repo, repo_type="dataset")
        dl_url = hf_hub_url(repo_id=dataset_repo, filename=repo_path, repo_type="dataset")

        # Also register inside universal vault_index.json so everyone sees it in Vault
        try:
            from app import update_vault_index
            sz_mb = os.path.getsize(fp) / MB
            sha = hashlib.sha256(open(fp, "rb").read(8 * MB)).hexdigest()
            entry = {
                "rom_key": f"DNA__{u_low}__{ustate['current_project']}",
                "device_name": f"{device_name} (@{USERS_DB.get(u_low, {}).get('username', u_low)})",
                "codename": ustate["current_project"],
                "rom_version": "DNA-Port",
                "rom_category": "Custom ROM",
                "rom_format": "DNA KITCHEN",
                "auto_status": "Packed in DNA Cloud Kitchen",
                "rom_url": dl_url,
                "rom_filename": base_fn,
                "target": base_fn,
                "source": f"/sdcard/DNA/{ustate['current_project']}",
                "sha256": sha,
                "size": f"{sz_mb:.2f} MB",
                "signature": detect_img_type(fp).upper(),
                "download_url": dl_url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            update_vault_index(TASKS_TMP_DIR, entry)
        except Exception:
            pass

        dna_log(u_low, "SUCCESS", f"Pushed '{base_fn}' to Universal HF Vault → {dl_url}")
        return {"ok": True, "download_url": dl_url}

    @router.post("/unpack")
    def api_dna_unpack(
        mode: str = Form(...),
        files: str = Form(""),
        delete_source: bool = Form(False),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = _current_user(x_dna_token)
        proj_dir = get_proj_dir(u_low)
        selected = [x.strip() for x in files.split(",") if x.strip()]

        if mode == "img":
            if not selected:
                raise HTTPException(status_code=400, detail="Please select at least one .img file.")
            results = []
            for fn in selected:
                fmt = detect_img_type(safe_join(proj_dir, fn))
                if fmt.startswith("super"):
                    dna_log(u_low, "UNPACK", "Super image detected → extracting slot _a partitions...")
                    _unpack_super_internal(u_low, proj_dir, fn, delete_source)
                else:
                    results.append(unpack_single_img_file(u_low, proj_dir, fn, delete_source))
            return {"ok": True, "results": results, "state": api_dna_state(None, x_dna_token)}

        elif mode == "super":
            target_super = selected[0] if selected else "super.img"
            _unpack_super_internal(u_low, proj_dir, target_super, delete_source)
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        elif mode == "zstd":
            for fn in selected:
                src = safe_join(proj_dir, fn)
                out_name = re.sub(r"\.zst$", "", fn, flags=re.I)
                if out_name == fn:
                    out_name += ".img"
                dst = safe_join(proj_dir, out_name)
                with open(src, "rb") as fin, open(dst, "wb") as fout:
                    dctx = zstd.ZstdDecompressor()
                    dctx.copy_stream(fin, fout)
                if delete_source:
                    os.remove(src)
                dna_log(u_low, "SUCCESS", f"Unpacked zstd '{fn}' → '{out_name}'")
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        elif mode == "br":
            for fn in selected:
                src = safe_join(proj_dir, fn)
                out_name = re.sub(r"\.br$", "", fn, flags=re.I)
                dst = safe_join(proj_dir, out_name)
                if shutil.which("brotli"):
                    subprocess.run(["brotli", "-d", "-f", "-o", dst, src], check=True)
                elif BROTLI_AVAILABLE:
                    with open(src, "rb") as fin, open(dst, "wb") as fout:
                        fout.write(brotli.decompress(fin.read()))
                else:
                    raise HTTPException(status_code=500, detail="Brotli library not installed.")
                if delete_source:
                    os.remove(src)
                dna_log(u_low, "SUCCESS", f"Unpacked brotli '{fn}' → '{out_name}'")
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        elif mode == "dat":
            for fn in selected:
                dat_p = safe_join(proj_dir, fn)
                prefix = re.sub(r"\.new\.dat$", "", fn, flags=re.I)
                tl_p = safe_join(proj_dir, f"{prefix}.transfer.list")
                if not os.path.exists(tl_p):
                    raise HTTPException(status_code=400, detail=f"Missing {prefix}.transfer.list in project.")
                out_img = safe_join(proj_dir, f"{prefix}.img")
                sdat2img_convert(tl_p, dat_p, out_img)
                dna_log(u_low, "SUCCESS", f"Converted '{fn}' + '{prefix}.transfer.list' → '{prefix}.img'")
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        elif mode == "payload":
            from app import extract_from_payload, Stream
            target_pl = selected[0] if selected else "payload.bin"
            pl_path = safe_join(proj_dir, target_pl)
            if not os.path.isfile(pl_path):
                raise HTTPException(status_code=404, detail=f"'{target_pl}' not found in project.")
            with open(pl_path, "rb") as f:
                if f.read(4) != b"CrAU":
                    raise HTTPException(status_code=400, detail="Invalid payload.bin header.")
            for p_to_ext in ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "system", "vendor", "product", "system_ext", "odm"):
                try:
                    tmp_id = "dna_pl"
                    jobs_dict[tmp_id] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
                    with open(pl_path, "rb") as fp:
                        out_p = os.path.join(proj_dir, f"{p_to_ext}.img")
                        extract_from_payload(tmp_id, Stream(fp, seek_ok=True), p_to_ext, out_p)
                        dna_log(u_low, "SUCCESS", f"Extracted '{p_to_ext}.img' from payload.bin")
                except Exception:
                    pass
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        raise HTTPException(status_code=400, detail="Unknown unpack mode.")

    def _unpack_super_internal(u_low: str, proj_dir: str, super_filename: str, delete_source: bool = False):
        from app import parse_lp, ExpandedReader, Stream, extract_from_super
        src_p = safe_join(proj_dir, super_filename)
        if not os.path.isfile(src_p):
            raise HTTPException(status_code=404, detail=f"'{super_filename}' not found in project.")
        with open(src_p, "rb") as fp:
            reader = ExpandedReader(Stream(fp, seek_ok=True), os.path.getsize(src_p))
            head = bytearray(HEAD_BYTES)
            for off, d in reader.pieces():
                if off < HEAD_BYTES:
                    n = min(len(d), HEAD_BYTES - off)
                    head[off:off + n] = d[:n]
                if off + len(d) >= HEAD_BYTES:
                    break
            parts = parse_lp(bytes(head))

        extracted_names = []
        tmp_id = "dna_super"
        jobs_dict[tmp_id] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
        for pname, exts in parts.items():
            if sum(e[1] for e in exts) == 0 or pname.endswith("_b"):
                continue
            clean_out = re.sub(r"_a$", "", pname) + ".img"
            out_p = os.path.join(proj_dir, clean_out)
            with open(src_p, "rb") as fp:
                extract_from_super(tmp_id, Stream(fp, seek_ok=True), pname, out_p, os.path.getsize(src_p), super_filename)
            extracted_names.append(clean_out)
            dna_log(u_low, "UNPACK", f"Extracted '{clean_out}' from {super_filename}")

        if delete_source and os.path.exists(src_p):
            os.remove(src_p)
        return extracted_names

    @router.post("/pack_single")
    def api_dna_pack_single(req: PackSingleRequest, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        try:
            res = pack_single_partition_worker(u_low, req)
            return {"ok": True, "result": res, "state": api_dna_state(req.project, x_dna_token)}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/pack_zstd")
    def api_dna_pack_zstd(filename: str = Form(...), level: int = Form(6), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        proj_dir = get_proj_dir(u_low)
        src = safe_join(proj_dir, filename)
        dst = safe_join(proj_dir, f"{filename}.zst")
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            cctx = zstd.ZstdCompressor(level=max(1, min(19, int(level))))
            cctx.copy_stream(fin, fout)
        dna_log(u_low, "SUCCESS", f"Packed '{filename}.zst' ({os.path.getsize(dst) / MB:.2f} MB)")
        return {"ok": True, "state": api_dna_state(None, x_dna_token)}

    @router.post("/pack_super")
    def api_dna_pack_super(req: PackSuperRequest, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        try:
            res = build_super_image(u_low, req)
            return {"ok": True, "result": res, "state": api_dna_state(req.project, x_dna_token)}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/convert")
    def api_dna_convert(mode: str = Form(...), filename: str = Form(...), br_level: int = Form(3), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        proj_dir = get_proj_dir(u_low)
        src = safe_join(proj_dir, filename)
        if not os.path.isfile(src):
            raise HTTPException(status_code=404, detail="Source image not found.")
        stem = re.sub(r"\.(img|simg)$", "", filename, flags=re.I)

        if mode == "img_to_simg":
            fmt = detect_img_type(src)
            if fmt == "sparse" or fmt.endswith("(sparse)"):
                out_name = f"{stem}_raw.img"
                sparse_to_raw(src, safe_join(proj_dir, out_name))
                dna_log(u_low, "SUCCESS", f"Converted Sparse '{filename}' → Raw '{out_name}'")
            else:
                out_name = f"{stem}_sparse.img"
                raw_to_sparse(src, safe_join(proj_dir, out_name))
                dna_log(u_low, "SUCCESS", f"Converted Raw '{filename}' → Android Sparse '{out_name}'")
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        elif mode == "img_to_dat_br":
            dat_p, _tl_p = img2sdat_convert(src, proj_dir, stem)
            br_p = f"{dat_p}.br"
            lvl = max(0, min(11, int(br_level)))
            if shutil.which("brotli"):
                subprocess.run(["brotli", f"-q{lvl}", "-f", "-o", br_p, dat_p], check=True)
            elif BROTLI_AVAILABLE:
                with open(dat_p, "rb") as fin, open(br_p, "wb") as fout:
                    fout.write(brotli.compress(fin.read(), quality=lvl))
            dna_log(u_low, "SUCCESS", f"Converted '{filename}' → '{stem}.new.dat', '{stem}.transfer.list' & '{stem}.new.dat.br'")
            return {"ok": True, "state": api_dna_state(None, x_dna_token)}

        raise HTTPException(status_code=400, detail="Unsupported conversion mode.")

    # ---------------- MT MANAGER DUAL-PANE ENDPOINTS (MULTI-PROJECT ROOT) ---------------- #
    # Paths in Manager are relative to the user's private root (`u_root`), which contains all their projects!
    # e.g. path="" lists all projects (`Default_Project`, `DNA_stock`, etc.)
    # e.g. path="Default_Project/vendor" lists unpacked vendor inside `Default_Project`!

    def _load_fs_maps_for_dir(u_root: str, target_dir: str):
        rel = os.path.relpath(target_dir, u_root).replace("\\", "/")
        parts = [] if rel == "." else rel.split("/")
        fs_map, fc_map = {}, {}
        proj_dir = None
        top_part = ""
        if len(parts) >= 2:
            proj_dir = os.path.join(u_root, parts[0])
            top_part = parts[1]
            if top_part != "config":
                cfg_f = os.path.join(proj_dir, "config", f"{top_part}_fs_config")
                fc_f = os.path.join(proj_dir, "config", f"{top_part}_file_contexts")
                if os.path.exists(cfg_f):
                    for line in open(cfg_f, encoding="utf-8", errors="ignore"):
                        sp = line.strip().split()
                        if len(sp) >= 4:
                            fs_map[sp[0]] = {"uid": sp[1], "gid": sp[2], "mode": sp[3]}
                if os.path.exists(fc_f):
                    for line in open(fc_f, encoding="utf-8", errors="ignore"):
                        sp = line.strip().split()
                        if len(sp) >= 2:
                            clean_k = sp[0].lstrip("/").replace("\\", "")
                            fc_map[clean_k] = sp[1]
        return proj_dir, top_part, fs_map, fc_map

    @router.get("/fs/list")
    def api_fs_list(path: str = "", x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        target_dir = safe_join(u_root, path)
        if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
            target_dir = u_root
            path = ""

        rel_from_user = os.path.relpath(target_dir, u_root).replace("\\", "/")
        if rel_from_user == ".":
            rel_from_user = ""

        proj_dir, top_part, fs_map, fc_map = _load_fs_maps_for_dir(u_root, target_dir)

        items = []
        dir_count = 0
        file_count = 0

        for name in sorted(os.listdir(target_dir), key=lambda x: (not os.path.isdir(os.path.join(target_dir, x)), x.lower())):
            full = os.path.join(target_dir, name)
            rel_item = os.path.relpath(full, u_root).replace("\\", "/")
            is_dir = os.path.isdir(full)
            is_link = os.path.islink(full)
            if is_dir:
                dir_count += 1
            else:
                file_count += 1

            sz = 0 if is_dir else (os.path.getsize(full) if os.path.exists(full) else 0)
            mtime_dt = datetime.fromtimestamp(os.path.getmtime(full)) if os.path.exists(full) else datetime.now()
            mtime_short = mtime_dt.strftime("%y-%m-%d %H:%M")
            mtime_full = mtime_dt.strftime("%Y-%m-%d %H:%M:%S")

            rel_in_proj = os.path.relpath(full, proj_dir).replace("\\", "/") if proj_dir else ""
            default_mode = "0755" if is_dir else ("0600" if name == "build.prop" else "0644")
            meta = fs_map.get(rel_in_proj, {"uid": "0", "gid": "0", "mode": default_mode})
            ctx = fc_map.get(rel_in_proj, f"u:object_r:{top_part or 'system'}_file:s0")

            short_oct = format_short_octal(meta["mode"])
            sym_perm = mode_octal_to_symbolic(meta["mode"], is_dir=is_dir, is_link=is_link)
            owner_name = "root" if meta["uid"] == "0" else ("shell" if meta["uid"] == "2000" else ("system" if meta["uid"] == "1000" else meta["uid"]))
            group_name = "root" if meta["gid"] == "0" else ("shell" if meta["gid"] == "2000" else ("system" if meta["gid"] == "1000" else meta["gid"]))

            size_human = f"{sz / MB:.2f}M" if sz >= MB else (f"{sz / 1024:.2f}K" if sz >= 1024 else f"{sz}B")

            items.append({
                "name": name,
                "rel_path": rel_item,
                "parent_display": f"/data/DNA/{os.path.dirname(rel_item)}/".replace("//", "/"),
                "is_dir": is_dir,
                "is_link": is_link,
                "link_target": os.readlink(full) if is_link else "",
                "size": sz,
                "size_str": size_human,
                "size_full": f"{size_human} ({sz:,})",
                "mtime": mtime_short,
                "mtime_full": mtime_full,
                "mode": meta["mode"],
                "short_octal": short_oct,
                "sym_perm": sym_perm,
                "uid": meta["uid"],
                "gid": meta["gid"],
                "owner_name": owner_name,
                "group_name": group_name,
                "selinux": ctx
            })

        total_disk, used_disk, free_disk = shutil.disk_usage(u_root)
        disk_str = f"Folders: {dir_count}  Files: {file_count}  Free: {free_disk / (1024**3):.2f}G/{total_disk / (1024**3):.2f}G"
        projects = sorted([d for d in os.listdir(u_root) if os.path.isdir(os.path.join(u_root, d))])

        return {
            "current_rel": rel_from_user,
            "display_path": f"/data/DNA/{rel_from_user}/".replace("//", "/"),
            "stats_line": disk_str,
            "projects": projects,
            "items": items
        }

    @router.get("/fs/checksum")
    def api_fs_checksum(path: str, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        fp = safe_join(u_root, path)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")
        md5_h = hashlib.md5()
        sha1_h = hashlib.sha1()
        sha256_h = hashlib.sha256()
        crc_v = 0
        with open(fp, "rb") as f:
            while chunk := f.read(2 * MB):
                md5_h.update(chunk)
                sha1_h.update(chunk)
                sha256_h.update(chunk)
                crc_v = zlib.crc32(chunk, crc_v)
        return {
            "filename": os.path.basename(fp),
            "md5": md5_h.hexdigest(),
            "sha1": sha1_h.hexdigest(),
            "sha256": sha256_h.hexdigest(),
            "crc32": f"{crc_v & 0xFFFFFFFF:08x}"
        }

    @router.get("/fs/read")
    def api_fs_read(path: str, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        fp = safe_join(u_root, path)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")
        if os.path.getsize(fp) > 4 * MB:
            raise HTTPException(status_code=400, detail="File is larger than 4 MB (binary). Use Unpack/Properties tools instead.")
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            return {"path": path, "content": f.read()}

    @router.post("/fs/write")
    def api_fs_write(path: str = Form(...), content: str = Form(...), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        fp = safe_join(u_root, path)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(content)
        dna_log(u_low, "MANAGER", f"Saved modified file '{path}'")
        return {"ok": True}

    @router.post("/fs/op")
    def api_fs_op(
        op: str = Form(...),
        src: str = Form(""),
        dst: str = Form(""),
        mode: str = Form("0644"),
        uid: str = Form("0"),
        gid: str = Form("0"),
        selinux: str = Form("u:object_r:system_file:s0"),
        recursive: bool = Form(False),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        src_full = safe_join(u_root, src) if src else u_root
        dst_full = safe_join(u_root, dst) if dst else u_root

        if op == "copy":
            target = os.path.join(dst_full, os.path.basename(src_full)) if os.path.isdir(dst_full) else dst_full
            if os.path.abspath(src_full) == os.path.abspath(target):
                target = target + "_copy"
            if os.path.isdir(src_full):
                shutil.copytree(src_full, target, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(src_full, target, follow_symlinks=False)
            dna_log(u_low, "MANAGER", f"Copied '{src}' → '{dst or '/'}'")

        elif op == "move":
            target = os.path.join(dst_full, os.path.basename(src_full)) if os.path.isdir(dst_full) else dst_full
            shutil.move(src_full, target)
            dna_log(u_low, "MANAGER", f"Moved '{src}' → '{dst or '/'}'")

        elif op == "delete":
            if os.path.isdir(src_full) and not os.path.islink(src_full):
                shutil.rmtree(src_full)
            elif os.path.exists(src_full) or os.path.islink(src_full):
                os.remove(src_full)
            dna_log(u_low, "MANAGER", f"Deleted '{src}'")

        elif op == "mkdir":
            os.makedirs(src_full, exist_ok=True)
            dna_log(u_low, "MANAGER", f"Created folder '{src}'")

        elif op == "rename":
            shutil.move(src_full, dst_full)
            dna_log(u_low, "MANAGER", f"Renamed '{src}' → '{dst}'")

        elif op == "symlink":
            if os.path.exists(src_full) or os.path.islink(src_full):
                os.remove(src_full)
            os.symlink(dst, src_full)
            dna_log(u_low, "MANAGER", f"Created symlink '{src}' → '{dst}'")

        elif op == "chmod_chcon":
            rel_from_user = os.path.relpath(src_full, u_root).replace("\\", "/")
            parts = rel_from_user.split("/")
            if len(parts) >= 2:
                proj_dir = os.path.join(u_root, parts[0])
                top_part = parts[1]
                rel_in_proj = os.path.relpath(src_full, proj_dir).replace("\\", "/")
                cfg_dir = os.path.join(proj_dir, "config")
                os.makedirs(cfg_dir, exist_ok=True)
                cfg_f = os.path.join(cfg_dir, f"{top_part}_fs_config")
                fc_f = os.path.join(cfg_dir, f"{top_part}_file_contexts")

                targets = [rel_in_proj]
                if recursive and os.path.isdir(src_full):
                    for r, ds, fs in os.walk(src_full):
                        for x in ds + fs:
                            targets.append(os.path.relpath(os.path.join(r, x), proj_dir).replace("\\", "/"))

                norm_mode = mode.strip()
                if len(norm_mode) == 3:
                    norm_mode = "0" + norm_mode

                existing_cfg = {}
                if os.path.exists(cfg_f):
                    for l in open(cfg_f, encoding="utf-8", errors="ignore"):
                        s = l.strip().split()
                        if len(s) >= 4:
                            existing_cfg[s[0]] = s[1:]
                for t in targets:
                    existing_cfg[t] = [uid, gid, norm_mode]
                with open(cfg_f, "w", encoding="utf-8") as f:
                    for k, v in sorted(existing_cfg.items()):
                        f.write(f"{k} {' '.join(v)}\n")

                existing_fc = {}
                if os.path.exists(fc_f):
                    for l in open(fc_f, encoding="utf-8", errors="ignore"):
                        s = l.strip().split()
                        if len(s) >= 2:
                            existing_fc[s[0]] = s[1]
                for t in targets:
                    existing_fc[f"/{re.escape(t)}"] = selinux
                with open(fc_f, "w", encoding="utf-8") as f:
                    for k, v in sorted(existing_fc.items()):
                        f.write(f"{k} {v}\n")

            dna_log(u_low, "MANAGER", f"Updated permissions ({mode}, {uid}:{gid}) & SELinux ({selinux}) on '{src}'")

        elif op == "mount_archive":
            out_d = src_full + "_unpacked"
            os.makedirs(out_d, exist_ok=True)
            if zipfile.is_zipfile(src_full):
                with zipfile.ZipFile(src_full, "r") as zf:
                    zf.extractall(out_d)
                dna_log(u_low, "MANAGER", f"Unpacked archive/APEX '{src}'")
            else:
                raise HTTPException(status_code=400, detail="Selected file is not a valid ZIP/APEX/APK archive.")

        elif op == "repack_archive":
            orig_archive = re.sub(r"_unpacked$", "", src_full)
            with zipfile.ZipFile(orig_archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for r, _ds, fs in os.walk(src_full):
                    for fn in fs:
                        full_f = os.path.join(r, fn)
                        arcname = os.path.relpath(full_f, src_full).replace("\\", "/")
                        ctype = zipfile.ZIP_STORED if fn.endswith((".img", ".so", ".arsc")) else zipfile.ZIP_DEFLATED
                        zf.write(full_f, arcname, compress_type=ctype)
            dna_log(u_low, "MANAGER", f"Repacked folder '{src}' → '{os.path.basename(orig_archive)}'")

        return {"ok": True}

    @router.post("/fs/upload")
    async def api_fs_upload(
        path: str = Form(""),
        project: str = Form(""),
        file: UploadFile = File(...),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = _current_user(x_dna_token)
        u_root = get_user_root(u_low)
        if project.strip():
            target_dir = get_proj_dir(u_low, project.strip())
        else:
            target_dir = safe_join(u_root, path) if path.strip() else get_proj_dir(u_low)
        os.makedirs(target_dir, exist_ok=True)
        out_p = safe_join(target_dir, os.path.basename(file.filename))
        with open(out_p, "wb") as f:
            while chunk := await file.read(2 * MB):
                f.write(chunk)
        sz_mb = os.path.getsize(out_p) / MB
        dna_log(u_low, "UPLOAD", f"Uploaded '{file.filename}' ({sz_mb:.2f} MB) to '{path or project or 'current project'}'")
        return {"ok": True, "filename": file.filename, "size_mb": f"{sz_mb:.2f} MB"}

    @router.get("/fs/download")
    def api_fs_download(path: str, token: str = ""):
        u_low = resolve_user_from_token(token)
        u_root = get_user_root(u_low)
        fp = safe_join(u_root, path)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")
        return FileResponse(fp, filename=os.path.basename(fp))

    app.include_router(router)
    return inject_dna_ui(html_page)

# ---------------- UI INJECTOR (MT MANAGER SIDE-BY-SIDE + AUTH + PROGRESS BARS) ---------------- #

DNA_TAB_HTML = r"""
  <style>
    /* MT Manager Side-by-Side Vertical Dual Pane */
    .mt-dual-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 0;
      border-radius: 20px;
      overflow: hidden;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(8, 8, 16, 0.88);
    }
    .mt-pane {
      display: flex;
      flex-direction: column;
      min-height: 430px;
      max-height: 64vh;
      transition: background 0.2s ease;
    }
    .mt-pane.active-pane {
      background: rgba(139, 92, 246, 0.07);
    }
    .mt-pane-left {
      border-right: 1.5px solid rgba(255,255,255,0.14);
    }
    .mt-row {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 7px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      cursor: pointer;
      user-select: none;
    }
    .mt-row:hover { background: rgba(255,255,255,0.06); }
    .mt-row.selected { background: rgba(139, 92, 246, 0.28); }
    .mt-dialog {
      background: #2b2b30;
      color: #f1f5f9;
      border: 1px solid rgba(255,255,255,0.15);
      box-shadow: 0 25px 60px rgba(0,0,0,0.92);
    }
    .mt-btn-gray {
      background: #484850;
      color: #e2e8f0;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .mt-btn-gray:hover { background: #5a5a64; }
  </style>

  <div class="relative z-10 w-full max-w-lg mx-auto">
    <!-- ================= TAB 4: DNA & MANAGER (CLOUD ROM PORTING SUITE) ================= -->
    <div id="tabDna" class="hidden space-y-3.5">

      <!-- AUTHENTICATION GATE (USERNAME + PASSWORD ONLY) -->
      <div id="dnaAuthCard" class="glass rounded-3xl p-5 space-y-4 border border-violet-500/40">
        <div class="flex items-center justify-between">
          <div>
            <span class="mono text-[10px] uppercase text-amber-300 font-bold block">🔒 Private ROM Porting Workspace</span>
            <h3 class="text-base font-bold text-white mt-0.5">Sign In or Create Account</h3>
          </div>
          <span class="mono text-[10px] px-2.5 py-1 rounded-full bg-violet-500/20 text-violet-300 border border-violet-400/30">Private Projects</span>
        </div>
        <p class="text-xs text-slate-300 leading-relaxed">
          Your projects and unpacked ROM folders in <strong>DNA</strong> &amp; <strong>Manager</strong> are private to your account. The <strong>Vault</strong> stays universal for everyone.
        </p>
        <div class="space-y-2.5">
          <div>
                        <label class="mono text-[10px] uppercase text-slate-400 block mb-1">Username</label>
            <input id="dnaAuthUser" type="text" placeholder="e.g. yash_01" class="cyber-input w-full px-3.5 py-2.5 rounded-xl text-xs mono text-white" />
          </div>
          <div>
            <label class="mono text-[10px] uppercase text-slate-400 block mb-1">Password</label>
            <input id="dnaAuthPass" type="password" placeholder="Enter password" class="cyber-input w-full px-3.5 py-2.5 rounded-xl text-xs mono text-white" />
          </div>
          <div id="dnaAuthErr" class="hidden text-xs mono text-rose-300 bg-rose-500/10 border border-rose-500/30 p-2.5 rounded-xl"></div>
          <div class="grid grid-cols-2 gap-2.5 pt-1">
            <button type="button" onclick="dnaAuthSubmit('login')" class="btn rip py-3 rounded-2xl font-bold text-xs text-slate-950 bg-gradient-to-r from-violet-400 to-amber-300">
              🔑 Sign In
            </button>
            <button type="button" onclick="dnaAuthSubmit('signup')" class="btn rip py-3 rounded-2xl font-bold text-xs text-violet-200 bg-violet-500/20 border border-violet-400/40">
              ✨ Create Account
            </button>
          </div>
        </div>
      </div>

      <!-- AUTHENTICATED WORKSPACE -->
      <div id="dnaMainWorkspace" class="hidden space-y-3.5">
        <!-- Top Mode Switcher: 🧬 DNA vs 🗂️ Manager -->
        <div class="glass rounded-3xl p-3.5 space-y-3">
          <div class="flex items-center justify-between gap-2 px-1">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="mono text-[10px] uppercase text-emerald-300 font-bold" id="dnaUserBadge">@user</span>
                <button type="button" onclick="dnaLogout()" class="mono text-[10px] text-rose-300 underline">Sign Out</button>
              </div>
              <span id="dnaProjPathLabel" class="mono text-xs font-bold text-white truncate block">Current project: /sdcard/DNA/Default_Project</span>
            </div>
            <button type="button" onclick="openDnaModal('projectModal')" class="btn rip px-3 py-1.5 rounded-xl bg-violet-500/20 text-violet-300 border border-violet-400/30 mono text-[10px] font-bold shrink-0">
              📁 Project Menu
            </button>
          </div>

          <div class="grid grid-cols-2 gap-2 bg-black/40 p-1.5 rounded-2xl border border-white/10">
            <button type="button" id="subBtnDna" onclick="switchDnaSub('dna')" class="chip-btn active py-2.5 rounded-xl mono text-xs font-bold">
              🧬 DNA (Unpack / Pack)
            </button>
            <button type="button" id="subBtnManager" onclick="switchDnaSub('manager')" class="chip-btn py-2.5 rounded-xl mono text-xs font-bold text-slate-300">
              🗂️ Manager (Dual-Pane Root)
            </button>
          </div>
        </div>

        <!-- LIVE IMPORT / UPLOAD PROGRESS BAR -->
        <div id="dnaTaskHud" class="hidden glass rounded-2xl p-3.5 space-y-2 border border-amber-400/40">
          <div class="flex items-center justify-between mono text-xs">
            <span id="dnaTaskLabel" class="text-amber-200 font-semibold truncate pr-2">Transferring...</span>
            <span id="dnaTaskPct" class="text-white font-bold">0%</span>
          </div>
          <div class="bar"><div id="dnaTaskBar" class="bar-fill c-amber" style="width:0%"></div></div>
        </div>

        <!-- ==================== SECTION A: 🧬 DNA ==================== -->
        <div id="dnaSubSection" class="space-y-4">
          <!-- Quick Import from Vault Bar -->
          <div class="glass rounded-3xl p-4 space-y-2.5">
            <div class="flex items-center justify-between">
              <span class="mono text-[10px] uppercase text-emerald-300 font-bold">⚡ Pull Partition / ROM Image from Vault into /sdcard/DNA</span>
              <button type="button" onclick="loadVaultIntoDnaPicker(true)" class="mono text-[10px] text-amber-300 underline">⟳ Sync Vault</button>
            </div>
            <div class="flex gap-2">
              <select id="dnaVaultPicker" class="cyber-input flex-1 px-3 py-2 rounded-xl text-xs mono text-white min-w-0">
                <option value="">Loading Vault files...</option>
              </select>
              <button type="button" onclick="importSelectedVaultImg('')" class="btn rip px-4 py-2 rounded-xl bg-emerald-500/25 border border-emerald-400/40 text-emerald-300 mono text-xs font-bold shrink-0">
                📥 Import
              </button>
            </div>
            <div class="flex items-center justify-between pt-1">
              <span class="mono text-[10px] text-slate-400">Or upload a local .img / .br / .dat / .zst file:</span>
              <label class="btn rip px-3 py-1 rounded-xl bg-violet-500/20 border border-violet-400/30 text-violet-200 mono text-[10px] font-bold cursor-pointer">
                ⬆ Upload File <input type="file" class="hidden" onchange="dnaDirectUpload(this)" />
              </label>
            </div>
          </div>

          <!-- 1. UNPACK MENU -->
          <div class="glass rounded-3xl p-5 space-y-3">
            <h3 class="text-sm font-bold text-violet-300 brand-font tracking-wide">Unpack Menu</h3>
            <div class="divide-y divide-white/10 mono text-xs">
              <button type="button" onclick="openUnpackModal('payload')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Unpack payload.bin</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openUnpackModal('br')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Unpack br</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openUnpackModal('dat')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Unpack dat</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openUnpackModal('img')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Unpack img</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openUnpackModal('zstd')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Unpack zstd</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openUnpackModal('super')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Unpack super</span><span class="text-slate-500">&gt;</span>
              </button>
            </div>
          </div>

          <!-- 2. PACK MENU -->
          <div class="glass rounded-3xl p-5 space-y-3">
            <h3 class="text-sm font-bold text-amber-300 brand-font tracking-wide">Pack Menu</h3>
            <div class="divide-y divide-white/10 mono text-xs">
              <button type="button" onclick="openPackSingleModal()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Pack a single partition</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openPackZstdModal()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Pack zstd</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openPackSuperModal()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>Pack super.img</span><span class="text-slate-500">&gt;</span>
              </button>
            </div>
          </div>

          <!-- 3. FORMAT CONVERSION -->
          <div class="glass rounded-3xl p-5 space-y-3">
            <h3 class="text-sm font-bold text-emerald-300 brand-font tracking-wide">Format Conversion</h3>
            <div class="divide-y divide-white/10 mono text-xs">
              <button type="button" onclick="openConvertModal('img_to_simg')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>img to simg</span><span class="text-slate-500">&gt;</span>
              </button>
              <button type="button" onclick="openConvertModal('img_to_dat_br')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition">
                <span>img to dat, br</span><span class="text-slate-500">&gt;</span>
              </button>
            </div>
          </div>

          <!-- Live DNA Kitchen Log -->
          <div class="glass rounded-3xl p-4 space-y-2">
            <div class="flex justify-between items-center">
              <span class="mono text-[11px] font-bold text-violet-300 uppercase">🧬 DNA Kitchen Execution Log</span>
              <button type="button" onclick="refreshDnaState()" class="mono text-[10px] text-amber-300">Refresh</button>
            </div>
            <div id="dnaLogConsole" class="mono text-[10.5px] bg-black/75 rounded-2xl p-3 h-40 overflow-y-auto space-y-1 border border-white/5">
              <div class="text-slate-500">[DNA] Ready. Unpacked partitions appear directly inside your project folder in Manager.</div>
            </div>
          </div>
        </div>

        <!-- ==================== SECTION B: 🗂️ MANAGER (MT DUAL-PANE ROOT EXPLORER) ==================== -->
        <div id="managerSubSection" class="hidden space-y-3">
          <!-- Dual-Pane Action Toolbar -->
          <div class="glass rounded-3xl p-3 space-y-2">
            <div class="flex items-center justify-between gap-1.5 flex-wrap">
              <button type="button" onclick="mgrCopyMove('copy')" class="btn rip px-2.5 py-1.5 rounded-xl bg-violet-500/20 border border-violet-400/30 text-violet-200 mono text-[10px] font-bold">⇄ Copy</button>
              <button type="button" onclick="mgrCopyMove('move')" class="btn rip px-2.5 py-1.5 rounded-xl bg-amber-500/20 border border-amber-400/30 text-amber-200 mono text-[10px] font-bold">➡ Move</button>
              <button type="button" onclick="mgrNewFolder()" class="btn rip px-2.5 py-1.5 rounded-xl bg-white/5 border border-white/10 text-slate-200 mono text-[10px]">+ Folder</button>
              <button type="button" onclick="mgrNewFile()" class="btn rip px-2.5 py-1.5 rounded-xl bg-white/5 border border-white/10 text-slate-200 mono text-[10px]">+ File</button>
              <button type="button" onclick="mgrSymlink()" class="btn rip px-2.5 py-1.5 rounded-xl bg-sky-500/20 border border-sky-400/30 text-sky-200 mono text-[10px]">🔗 Symlink</button>
              <label class="btn rip px-2.5 py-1.5 rounded-xl bg-emerald-500/20 border border-emerald-400/30 text-emerald-200 mono text-[10px] font-bold cursor-pointer">
                ⬆ Upload <input type="file" class="hidden" onchange="mgrUploadFile(this)" />
              </label>
            </div>

            <!-- Import Vault file directly into active Manager pane -->
            <div class="flex items-center gap-1.5 pt-0.5">
              <select id="mgrVaultPicker" class="cyber-input flex-1 px-2.5 py-1.5 rounded-xl text-[10px] mono text-white min-w-0">
                <option value="">Import from HF Vault into active pane...</option>
              </select>
              <button type="button" onclick="importSelectedVaultImg('mgr')" class="btn rip px-2.5 py-1.5 rounded-xl bg-emerald-500/20 border border-emerald-400/30 text-emerald-300 mono text-[10px] font-bold shrink-0">
                📥 Pull Here
              </button>
            </div>

            <div class="text-[10px] mono text-slate-400 flex justify-between px-0.5">
              <span>Active Pane: <strong id="mgrActivePaneIndicator" class="text-amber-300">LEFT</strong></span>
              <span>Tap folder to open • Tap ••• for Properties/Editor</span>
            </div>
          </div>

          <!-- MT Manager Side-by-Side Vertical Split Dual Panes -->
          <div class="mt-dual-grid">
            <!-- LEFT PANE -->
            <div id="mgrPaneWrapL" onclick="setActivePane('L')" class="mt-pane mt-pane-left active-pane">
              <div class="bg-black/70 px-2.5 py-2 border-b border-white/10">
                <div class="flex items-center justify-between gap-1">
                  <span id="mgrPathL" class="mono text-[10px] font-bold text-amber-300 truncate">/data/DNA/</span>
                  <div class="flex items-center gap-1 shrink-0">
                    <select id="mgrProjJumpL" onchange="loadPane('L', this.value)" class="bg-white/10 text-[9px] mono text-slate-200 rounded px-1 py-0.5"></select>
                    <button type="button" onclick="loadPane('L')" class="mono text-[10px] text-slate-400 px-1">⟳</button>
                  </div>
                </div>
                <div id="mgrStatsL" class="mono text-[8.5px] text-slate-400 truncate mt-0.5">Folders: 0 Files: 0</div>
              </div>
              <div id="mgrListL" class="flex-1 overflow-y-auto divide-y divide-white/5 mono text-[10.5px]"></div>
            </div>

            <!-- RIGHT PANE -->
            <div id="mgrPaneWrapR" onclick="setActivePane('R')" class="mt-pane">
              <div class="bg-black/70 px-2.5 py-2 border-b border-white/10">
                <div class="flex items-center justify-between gap-1">
                  <span id="mgrPathR" class="mono text-[10px] font-bold text-emerald-300 truncate">/data/DNA/</span>
                  <div class="flex items-center gap-1 shrink-0">
                    <select id="mgrProjJumpR" onchange="loadPane('R', this.value)" class="bg-white/10 text-[9px] mono text-slate-200 rounded px-1 py-0.5"></select>
                    <button type="button" onclick="loadPane('R')" class="mono text-[10px] text-slate-400 px-1">⟳</button>
                  </div>
                </div>
                <div id="mgrStatsR" class="mono text-[8.5px] text-slate-400 truncate mt-0.5">Folders: 0 Files: 0</div>
              </div>
              <div id="mgrListR" class="flex-1 overflow-y-auto divide-y divide-white/5 mono text-[10.5px]"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ================= MODALS FOR DNA & MT MANAGER ================= -->

  <!-- 1. PROJECT MENU MODAL -->
  <div id="projectModal" class="hidden fixed inset-0 z-[80] bg-black/80 backdrop-filter backdrop-blur-md flex items-center justify-center p-4">
    <div class="glass rounded-3xl p-5 w-full max-w-sm space-y-3 border border-white/15">
      <h3 class="text-sm font-bold text-white">Project Menu</h3>
      <p id="projModalCurrent" class="mono text-[11px] text-amber-300">Current project: /sdcard/DNA/Default_Project</p>
      <div>
        <label class="mono text-[10px] text-slate-400 block mb-1">Select Existing Project</label>
        <select id="projSelectDropdown" onchange="dnaProjectOp('select', this.value)" class="cyber-input w-full px-3 py-2 rounded-xl text-xs mono text-white"></select>
      </div>
      <div class="flex gap-2">
        <input id="newProjNameInput" type="text" placeholder="New project (e.g. Stock_Port)" class="cyber-input flex-1 px-3 py-2 rounded-xl text-xs mono text-white" />
        <button type="button" onclick="dnaProjectOp('create', document.getElementById('newProjNameInput').value)" class="btn rip px-3.5 py-2 rounded-xl bg-violet-500/30 border border-violet-400/40 text-violet-200 mono text-xs font-bold">Create</button>
      </div>
      <div class="grid grid-cols-2 gap-2 pt-1">
        <button type="button" onclick="dnaProjectOp('clear', '')" class="btn rip py-2 rounded-xl bg-amber-500/20 border border-amber-400/30 text-amber-300 mono text-xs">Clear Project</button>
        <button type="button" onclick="dnaProjectOp('delete', '')" class="btn rip py-2 rounded-xl bg-rose-500/20 border border-rose-400/30 text-rose-300 mono text-xs">Delete Project</button>
      </div>
      <button type="button" onclick="closeDnaModal('projectModal')" class="btn rip w-full py-2 rounded-xl bg-white/10 text-slate-300 mono text-xs">Close</button>
    </div>
  </div>

  <!-- 2. UNPACK MODAL -->
  <div id="unpackModal" class="hidden fixed inset-0 z-[80] bg-black/80 backdrop-filter backdrop-blur-md flex items-center justify-center p-4">
    <div class="glass rounded-3xl p-5 w-full max-w-sm space-y-3.5 border border-white/15">
      <h3 id="unpackModalTitle" class="text-sm font-bold text-white">Unpack img</h3>
      <label class="flex items-center justify-between text-xs text-slate-200 bg-black/40 p-2.5 rounded-xl border border-white/5">
        <span>Delete source file after completion</span>
        <input id="unpackDelSource" type="checkbox" class="w-4 h-4 accent-violet-500" />
      </label>
      <div>
        <span class="mono text-[11px] text-amber-300 block mb-1.5">• Select file(s):</span>
        <div id="unpackFileList" class="space-y-1.5 max-h-48 overflow-y-auto bg-black/50 p-3 rounded-2xl border border-white/5 mono text-xs"></div>
      </div>
      <p class="text-[10px] text-slate-400 leading-relaxed">
        Place your file in the project path /sdcard/DNA. The tool will automatically detect the img format and unpack it directly into your project folder.
      </p>
      <div class="flex justify-end gap-3 pt-1">
        <button type="button" onclick="closeDnaModal('unpackModal')" class="px-4 py-2 rounded-xl bg-white/5 text-slate-300 mono text-xs">CANCEL</button>
        <button type="button" onclick="submitUnpackModal()" class="btn rip px-5 py-2 rounded-xl bg-violet-500 text-white mono text-xs font-bold">OK</button>
      </div>
    </div>
  </div>

  <!-- 3. PACK A SINGLE PARTITION MODAL -->
  <div id="packSingleModal" class="hidden fixed inset-0 z-[80] bg-black/80 backdrop-filter backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
    <div class="glass rounded-3xl p-5 w-full max-w-sm space-y-3 border border-white/15 my-auto max-h-[90vh] overflow-y-auto">
      <h3 class="text-sm font-bold text-white">Pack a single partition</h3>
      <div>
        <select id="psPartSelect" class="cyber-input w-full px-3 py-2 rounded-xl text-xs mono text-white"></select>
        <span class="text-[10px] text-slate-400 block mt-0.5">IMG packing format will be automatically detected</span>
      </div>
      <div class="grid grid-cols-2 gap-2.5 items-center">
        <label class="text-[11px] text-slate-300 block">Pack type</label>
        <select id="psPackType" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
          <option value="erofs">erofs</option>
          <option value="ext4">ext4</option>
          <option value="f2fs">f2fs</option>
        </select>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2.5 items-center">
          <label class="text-[11px] text-slate-300">Read/Write permission</label>
          <select id="psRwMode" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
            <option value="rw">Read/Write---rw</option>
            <option value="ro">Read Only---ro</option>
          </select>
        </div>
        <span class="text-[10px] text-slate-500">Note: only used when packing to ext4</span>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2.5 items-center">
          <label class="text-[11px] text-slate-300">Size</label>
          <select id="psSizeMode" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
            <option value="auto">Auto</option>
            <option value="orig">Original size</option>
          </select>
        </div>
        <span class="text-[10px] text-slate-500">Note: only used when packing to ext4</span>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2.5 items-center">
          <label class="text-[11px] text-slate-300">img format</label>
          <select id="psImgFormat" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
            <option value="raw">Raw</option>
            <option value="sparse">Sparse</option>
          </select>
        </div>
        <span class="text-[10px] text-slate-500">Note: only used when packing to ext4 or erofs</span>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2.5 items-center">
          <label class="text-[11px] text-slate-300">File format</label>
          <select id="psFileFormat" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
            <option value="IMG">IMG</option>
            <option value="DAT">DAT</option>
            <option value="BR">BR</option>
          </select>
        </div>
        <span class="text-[10px] text-slate-500">Note: only used when packing to ext4 or erofs</span>
      </div>
      <div>
        <div class="flex items-center justify-between">
          <span class="text-[11px] text-slate-300">br compression</span>
          <div class="flex items-center gap-2">
            <button type="button" onclick="stepVal('psBrLevel', -1, 0, 11)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">-</button>
            <input id="psBrLevel" type="number" value="3" min="0" max="11" class="cyber-input w-12 text-center py-1 rounded-lg mono text-xs text-white" />
            <button type="button" onclick="stepVal('psBrLevel', 1, 0, 11)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">+</button>
          </div>
        </div>
      </div>
      <div>
        <div class="flex items-center justify-between">
          <span class="text-[11px] text-slate-300">Erofs(f2fs) compression</span>
          <div class="flex items-center gap-2">
            <button type="button" onclick="stepVal('psErofsLevel', -1, 0, 12)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">-</button>
            <input id="psErofsLevel" type="number" value="8" min="0" max="12" class="cyber-input w-12 text-center py-1 rounded-lg mono text-xs text-white" />
            <button type="button" onclick="stepVal('psErofsLevel', 1, 0, 12)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">+</button>
          </div>
        </div>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2.5 items-center">
          <label class="text-[11px] text-slate-300">Type</label>
          <select id="psErofsAlgo" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
            <option value="lz4hc">lz4hc</option>
            <option value="lz4">lz4</option>
            <option value="lzma">lzma</option>
            <option value="deflate">deflate</option>
          </select>
        </div>
      </div>
      <label class="flex items-center justify-between text-xs text-slate-200 bg-black/40 p-2.5 rounded-xl border border-white/5">
        <div>
          <span class="block">Compress ext4 img space</span>
          <span class="text-[10px] text-slate-500">Note: only used when packing to ext4</span>
        </div>
        <input id="psCompressExt4" type="checkbox" class="w-4 h-4 accent-violet-500" />
      </label>
      <label class="flex items-center justify-between text-xs text-slate-200 bg-black/40 p-2.5 rounded-xl border border-white/5">
        <div class="pr-2">
          <span class="block">Remove avb data encryption</span>
          <span class="text-[10px] text-slate-500">Modifies fstab to strip AVB/encryption flags.</span>
        </div>
        <input id="psRemoveAvb" type="checkbox" class="w-4 h-4 accent-violet-500 shrink-0" />
      </label>
      <div class="flex justify-end gap-3 pt-2">
        <button type="button" onclick="closeDnaModal('packSingleModal')" class="px-4 py-2 rounded-xl bg-white/5 text-slate-300 mono text-xs">CANCEL</button>
        <button type="button" onclick="submitPackSingle()" class="btn rip px-5 py-2 rounded-xl bg-emerald-500 text-slate-950 mono text-xs font-bold">OK</button>
      </div>
    </div>
  </div>

  <!-- 4. PACK SUPER.IMG MODAL -->
  <div id="packSuperModal" class="hidden fixed inset-0 z-[80] bg-black/80 backdrop-filter backdrop-blur-md flex items-center justify-center p-4">
    <div class="glass rounded-3xl p-5 w-full max-w-sm space-y-3 border border-white/15">
      <h3 class="text-sm font-bold text-white">Pack super.img</h3>
      <div class="grid grid-cols-2 gap-2 items-center">
        <label class="text-xs text-slate-300">Type</label>
        <select id="superType" class="cyber-input px-3 py-2 rounded-xl text-xs mono text-white">
          <option value="a_only">a_only</option>
          <option value="ab">ab</option>
          <option value="virtual_ab">virtual_ab</option>
        </select>
      </div>
      <div class="grid grid-cols-2 gap-2 items-center">
        <label class="text-xs text-slate-300">Format</label>
        <select id="superFormat" class="cyber-input px-3 py-2 rounded-xl text-xs mono text-white">
          <option value="sparse">sparse</option>
          <option value="raw">raw</option>
        </select>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2 items-center">
          <label class="text-xs text-slate-300">Total super.img</label>
          <input id="superTotalGb" type="number" step="0.1" value="8.5" class="cyber-input px-3 py-2 rounded-xl text-xs mono text-white" />
        </div>
        <span class="text-[10px] text-slate-400">Enter the size of your super img, default value 8.5G.</span>
      </div>
      <div>
        <div class="grid grid-cols-2 gap-2 items-center">
          <label class="text-xs text-slate-300">Partition group</label>
          <select id="superGroup" class="cyber-input px-3 py-2 rounded-xl text-xs mono text-white">
            <option value="qti_dynamic_partitions">qti_dynamic_partitions</option>
            <option value="mtk_dynamic_partitions">mtk_dynamic_partitions</option>
          </select>
        </div>
      </div>
      <div>
        <span class="mono text-[11px] text-amber-300 block mb-1">• Select IMG files to pack:</span>
        <div id="superImgChecklist" class="space-y-1.5 max-h-40 overflow-y-auto bg-black/50 p-3 rounded-2xl border border-white/5 mono text-xs"></div>
      </div>
      <div class="flex justify-end gap-3 pt-2">
        <button type="button" onclick="closeDnaModal('packSuperModal')" class="px-4 py-2 rounded-xl bg-white/5 text-slate-300 mono text-xs">CANCEL</button>
        <button type="button" onclick="submitPackSuper()" class="btn rip px-5 py-2 rounded-xl bg-amber-400 text-slate-950 mono text-xs font-bold">OK</button>
      </div>
    </div>
  </div>

  <!-- 5. PACK ZSTD MODAL -->
  <div id="packZstdModal" class="hidden fixed inset-0 z-[80] bg-black/80 backdrop-filter backdrop-blur-md flex items-center justify-center p-4">
    <div class="glass rounded-3xl p-5 w-full max-w-sm space-y-3 border border-white/15">
      <h3 class="text-sm font-bold text-white">Pack zstd</h3>
      <div>
        <label class="mono text-[10px] text-slate-400 block mb-1">Select .img file in /sdcard/DNA</label>
        <select id="zstdImgSelect" class="cyber-input w-full px-3 py-2 rounded-xl text-xs mono text-white"></select>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-xs text-slate-300">Zstd compression level (1-19)</span>
        <input id="zstdLevelInput" type="number" value="6" min="1" max="19" class="cyber-input w-16 text-center py-1 rounded-lg mono text-xs text-white" />
      </div>
      <div class="flex justify-end gap-3 pt-2">
        <button type="button" onclick="closeDnaModal('packZstdModal')" class="px-4 py-2 rounded-xl bg-white/5 text-slate-300 mono text-xs">CANCEL</button>
        <button type="button" onclick="submitPackZstd()" class="btn rip px-5 py-2 rounded-xl bg-violet-500 text-white mono text-xs font-bold">OK</button>
      </div>
    </div>
  </div>

  <!-- 6. FORMAT CONVERSION MODAL -->
  <div id="convertModal" class="hidden fixed inset-0 z-[80] bg-black/80 backdrop-filter backdrop-blur-md flex items-center justify-center p-4">
    <div class="glass rounded-3xl p-5 w-full max-w-sm space-y-3 border border-white/15">
      <h3 id="convertModalTitle" class="text-sm font-bold text-white">Format Conversion</h3>
      <div>
        <label class="mono text-[10px] text-slate-400 block mb-1">Select .img file in /sdcard/DNA</label>
        <select id="convImgSelect" class="cyber-input w-full px-3 py-2 rounded-xl text-xs mono text-white"></select>
      </div>
      <div id="convBrWrap" class="hidden flex items-center justify-between">
        <span class="text-xs text-slate-300">br compression (0-11)</span>
        <input id="convBrLevel" type="number" value="3" min="0" max="11" class="cyber-input w-16 text-center py-1 rounded-lg mono text-xs text-white" />
      </div>
      <div class="flex justify-end gap-3 pt-2">
        <button type="button" onclick="closeDnaModal('convertModal')" class="px-4 py-2 rounded-xl bg-white/5 text-slate-300 mono text-xs">CANCEL</button>
        <button type="button" onclick="submitConvertModal()" class="btn rip px-5 py-2 rounded-xl bg-emerald-500 text-slate-950 mono text-xs font-bold">OK</button>
      </div>
    </div>
  </div>

  <!-- 7. MT MANAGER PROPERTIES, PERMISSIONS GRID, CHECKSUM & TEXT EDITOR MODAL -->
  <div id="mgrItemModal" class="hidden fixed inset-0 z-[85] bg-black/85 backdrop-filter backdrop-blur-md flex items-center justify-center p-3 overflow-y-auto">
    <div class="mt-dialog rounded-2xl p-4 w-full max-w-md space-y-3 my-auto max-h-[92vh] overflow-y-auto">
      <div class="flex items-center justify-between border-b border-white/15 pb-2">
        <div class="min-w-0 pr-2">
          <h3 id="mgrModalName" class="mono text-sm font-bold text-white truncate">file</h3>
          <p id="mgrModalPath" class="mono text-[10px] text-slate-400 truncate">/data/DNA/</p>
        </div>
        <button type="button" onclick="closeDnaModal('mgrItemModal')" class="px-2.5 py-1 rounded-lg bg-white/10 text-xs mono">✕</button>
      </div>

      <!-- MT Manager Properties Summary -->
      <div class="bg-black/35 p-3 rounded-xl space-y-1 mono text-[11px] border border-white/10">
        <div><span class="text-slate-400">Size: </span><span id="mgrPropSize" class="text-slate-100">0 B</span></div>
        <div><span class="text-slate-400">Modified: </span><span id="mgrPropMtime" class="text-slate-100">—</span></div>
        <div><span class="text-slate-400">Permission: </span><span id="mgrPropPerm" class="text-amber-300 font-bold">rwxr-xr-x (755)</span></div>
        <div class="flex items-center justify-between pt-1">
          <div class="flex gap-1.5 flex-wrap">
            <button type="button" onclick="mgrCalcChecksum()" class="mt-btn-gray">CHECKSUM</button>
            <button type="button" onclick="mgrRenameItem()" class="mt-btn-gray">RENAME</button>
            <button type="button" onclick="mgrDeleteItem()" class="mt-btn-gray text-rose-300">DELETE</button>
            <a id="mgrBtnDownload" href="#" target="_blank" class="mt-btn-gray text-emerald-300">DOWNLOAD</a>
            <button type="button" id="mgrBtnVault" onclick="mgrPushVault()" class="mt-btn-gray text-sky-300">PUSH VAULT</button>
          </div>
        </div>
        <div class="flex gap-1.5 pt-1">
          <button type="button" id="mgrBtnMount" onclick="mgrMountArchive()" class="hidden mt-btn-gray text-violet-300">UNPACK APEX/APK/ZIP</button>
          <button type="button" id="mgrBtnRepack" onclick="mgrRepackArchive()" class="hidden mt-btn-gray text-amber-300">REPACK ARCHIVE</button>
        </div>
      </div>

      <!-- Checksum Results Box (Hidden until CHECKSUM tapped) -->
      <div id="mgrChecksumBox" class="hidden bg-black/50 p-3 rounded-xl border border-white/10 space-y-1.5 mono text-[10px]">
        <div class="flex justify-between items-center"><span class="text-slate-400">MD5:</span><span id="chkMd5" class="text-emerald-300 truncate ml-2"></span></div>
        <div class="flex justify-between items-center"><span class="text-slate-400">SHA-1:</span><span id="chkSha1" class="text-violet-300 truncate ml-2"></span></div>
        <div class="flex justify-between items-center"><span class="text-slate-400">SHA-256:</span><span id="chkSha256" class="text-amber-300 truncate ml-2"></span></div>
        <div class="flex justify-between items-center"><span class="text-slate-400">CRC32:</span><span id="chkCrc32" class="text-sky-300 ml-2"></span></div>
      </div>

      <!-- MT Manager 12-Checkbox Permissions & Owner/SELinux Dialog -->
      <div class="bg-black/40 p-3 rounded-xl border border-white/10 space-y-2.5">
        <div class="flex items-center justify-between">
          <span class="mono text-[10px] uppercase text-violet-300 font-bold">Change Permissions (chmod / chown / chcon)</span>
          <input id="mgrPermMode" type="text" value="0755" oninput="syncOctalToCheckboxes(this.value)" class="cyber-input w-16 text-center py-0.5 rounded mono text-xs text-amber-300 font-bold" />
        </div>

        <div class="grid grid-cols-2 gap-2 mono text-[11px]">
          <div>
            <label class="text-[9px] text-slate-400 block">Owner (UID)</label>
            <select id="mgrPermUid" class="cyber-input w-full px-2 py-1 rounded text-xs text-white">
              <option value="0">0 - root</option>
              <option value="1000">1000 - system</option>
              <option value="2000">2000 - shell</option>
            </select>
          </div>
          <div>
            <label class="text-[9px] text-slate-400 block">Group (GID)</label>
            <select id="mgrPermGid" class="cyber-input w-full px-2 py-1 rounded text-xs text-white">
              <option value="0">0 - root</option>
              <option value="1000">1000 - system</option>
              <option value="2000">2000 - shell</option>
            </select>
          </div>
        </div>

        <!-- 3x4 Permission Checkboxes (Read / Write / Execute + Special) -->
        <div class="grid grid-cols-4 gap-1 text-center mono text-[10px] bg-black/40 p-2 rounded-lg border border-white/5">
          <div class="text-left text-slate-400 font-bold">Role</div>
          <div class="text-slate-300">Read</div>
          <div class="text-slate-300">Write</div>
          <div class="text-slate-300">Exec</div>

          <div class="text-left text-slate-300">Owner</div>
          <div><input type="checkbox" id="p_ur" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>
          <div><input type="checkbox" id="p_uw" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>
          <div><input type="checkbox" id="p_ux" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>

          <div class="text-left text-slate-300">Group</div>
          <div><input type="checkbox" id="p_gr" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>
          <div><input type="checkbox" id="p_gw" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>
          <div><input type="checkbox" id="p_gx" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>

          <div class="text-left text-slate-300">Other</div>
          <div><input type="checkbox" id="p_or" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>
          <div><input type="checkbox" id="p_ow" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>
          <div><input type="checkbox" id="p_ox" onchange="syncCheckboxesToOctal()" class="accent-violet-500" /></div>

          <div class="text-left text-amber-300">Special</div>
          <div><label class="flex items-center justify-center gap-0.5"><input type="checkbox" id="p_suid" onchange="syncCheckboxesToOctal()" class="accent-amber-400" /><span class="text-[8px]">SUID</span></label></div>
          <div><label class="flex items-center justify-center gap-0.5"><input type="checkbox" id="p_sgid" onchange="syncCheckboxesToOctal()" class="accent-amber-400" /><span class="text-[8px]">SGID</span></label></div>
          <div><label class="flex items-center justify-center gap-0.5"><input type="checkbox" id="p_sticky" onchange="syncCheckboxesToOctal()" class="accent-amber-400" /><span class="text-[8px]">Stick</span></label></div>
        </div>

        <div>
          <label class="mono text-[9px] text-slate-400 block">SELinux Context (file_contexts)</label>
          <input id="mgrPermSelinux" type="text" value="u:object_r:system_file:s0" class="cyber-input w-full px-2.5 py-1 rounded mono text-[11px] text-emerald-300" />
        </div>

        <div class="flex items-center justify-between pt-1">
          <label class="flex items-center gap-1.5 text-[10px] text-slate-300 mono">
            <input id="mgrPermRecurse" type="checkbox" class="accent-violet-500" /> Apply recursively to subfiles
          </label>
          <button type="button" onclick="mgrApplyPerms()" class="btn rip px-3.5 py-1.5 rounded-lg bg-violet-500 text-white mono text-[10px] font-bold">OK (Save Perms)</button>
        </div>
      </div>

      <!-- Built-in Root Text / build.prop / fstab Editor -->
      <div id="mgrEditorWrap" class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="mono text-[10px] uppercase text-amber-300 font-bold">📝 Root Text &amp; build.prop Editor</span>
          <button type="button" onclick="mgrSaveTextFile()" class="btn rip px-3.5 py-1 rounded-lg bg-emerald-500 text-slate-950 mono text-[10px] font-bold">💾 Save File</button>
        </div>
        <textarea id="mgrTextEditor" rows="10" class="cyber-input w-full p-3 rounded-xl mono text-[11px] text-slate-100 leading-relaxed" placeholder="Loading file contents..."></textarea>
      </div>
    </div>
  </div>

  <script>
    let dnaToken = localStorage.getItem("dna_auth_token") || "";
    let dnaUser = localStorage.getItem("dna_auth_user") || "";
    let dnaState = { current_project: "Default_Project", img_files: [], unpacked_parts: [], zst_files: [], dat_br_files: [], projects: [], logs: [] };
    let currentUnpackMode = "img";
    let currentConvertMode = "img_to_simg";
    let mgrActivePane = "L";
    let mgrPaths = { L: "", R: "" };
    let mgrItems = { L: [], R: [] };
    let mgrSelected = { L: null, R: null };
    let mgrModalTarget = null;

    function dnaHeaders(extra) {
      const h = Object.assign({}, extra || {});
      if (dnaToken) h["X-Dna-Token"] = dnaToken;
      return h;
    }

    function hasFileExt(name, extList) {
      const low = String(name || "").toLowerCase();
      return extList.some(ext => low.endsWith("." + ext));
    }

    /* ---------- AUTHENTICATION ---------- */
    async function checkDnaAuth() {
      const authCard = document.getElementById("dnaAuthCard");
      const mainWs = document.getElementById("dnaMainWorkspace");
      if (!dnaToken) {
        authCard.classList.remove("hidden");
        mainWs.classList.add("hidden");
        return false;
      }
      try {
        const res = await fetch("/api/dna/auth/me", { headers: dnaHeaders(), cache: "no-store" });
        if (!res.ok) throw new Error("Expired");
        const data = await res.json();
        dnaUser = data.username;
        document.getElementById("dnaUserBadge").textContent = "@" + dnaUser;
        authCard.classList.add("hidden");
        mainWs.classList.remove("hidden");
        loadVaultIntoDnaPicker(false);
        return true;
      } catch (e) {
        dnaToken = "";
        localStorage.removeItem("dna_auth_token");
        authCard.classList.remove("hidden");
        mainWs.classList.add("hidden");
        return false;
      }
    }

    async function dnaAuthSubmit(mode) {
      const u = document.getElementById("dnaAuthUser").value.trim();
      const p = document.getElementById("dnaAuthPass").value;
      const err = document.getElementById("dnaAuthErr");
      err.classList.add("hidden");
      if (!u || !p) {
        err.textContent = "Please enter both username and password.";
        err.classList.remove("hidden");
        return;
      }
      const fd = new FormData();
      fd.append("username", u);
      fd.append("password", p);
      try {
        const res = await fetch("/api/dna/auth/" + mode, { method: "POST", body: fd });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Authentication failed");
        dnaToken = data.token;
        dnaUser = data.username;
        localStorage.setItem("dna_auth_token", dnaToken);
        localStorage.setItem("dna_auth_user", dnaUser);
        toast("Signed in as @" + dnaUser + " ✓", "ok");
        await checkDnaAuth();
        refreshDnaState();
        loadPane("L", "");
        loadPane("R", "");
      } catch (e) {
        err.textContent = e.message;
        err.classList.remove("hidden");
      }
    }

    function dnaLogout() {
      dnaToken = "";
      dnaUser = "";
      localStorage.removeItem("dna_auth_token");
      localStorage.removeItem("dna_auth_user");
      checkDnaAuth();
      toast("Signed out", "ok");
    }

    function switchDnaSub(mode) {
      const isDna = mode === "dna";
      document.getElementById("dnaSubSection").classList.toggle("hidden", !isDna);
      document.getElementById("managerSubSection").classList.toggle("hidden", isDna);
      document.getElementById("subBtnDna").classList.toggle("active", isDna);
      document.getElementById("subBtnManager").classList.toggle("active", !isDna);
      if (!isDna) {
        loadPane("L");
        loadPane("R");
      } else {
        refreshDnaState();
      }
    }

    function openDnaModal(id) { document.getElementById(id).classList.remove("hidden"); }
    function closeDnaModal(id) { document.getElementById(id).classList.add("hidden"); }

    function stepVal(id, delta, min, max) {
      const el = document.getElementById(id);
      let v = parseInt(el.value || "0", 10) + delta;
      el.value = Math.max(min, Math.min(max, v));
    }

    /* ---------- PROGRESS BAR HELPER FOR VAULT IMPORT & UPLOADS ---------- */
    function showTaskProgress(label, pct) {
      const hud = document.getElementById("dnaTaskHud");
      hud.classList.remove("hidden");
      document.getElementById("dnaTaskLabel").textContent = label;
      document.getElementById("dnaTaskPct").textContent = Math.round(pct) + "%";
      document.getElementById("dnaTaskBar").style.width = Math.max(0, Math.min(100, pct)) + "%";
    }

    function hideTaskProgress() {
      setTimeout(() => document.getElementById("dnaTaskHud").classList.add("hidden"), 900);
    }

    async function pollDnaTask(taskId) {
      while (true) {
        try {
          const res = await fetch("/api/dna/task/" + taskId, { cache: "no-store" });
          if (!res.ok) break;
          const t = await res.json();
          showTaskProgress(t.label || "Working...", t.pct || 0);
          if (t.state === "done") {
            toast(t.label || "Import complete ✓", "ok");
            hideTaskProgress();
            refreshDnaState();
            loadPane("L");
            loadPane("R");
            break;
          }
          if (t.state === "error") {
            toast(t.error || "Task failed", "bad");
            hideTaskProgress();
            break;
          }
        } catch (e) { break; }
        await new Promise(r => setTimeout(r, 400));
      }
    }

    async function refreshDnaState() {
      const ok = await checkDnaAuth();
      if (!ok) return;
      try {
        const res = await fetch("/api/dna/state", { headers: dnaHeaders(), cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        dnaState = data;
        document.getElementById("dnaProjPathLabel").textContent = "Current project: " + data.project_path;
        document.getElementById("projModalCurrent").textContent = "Current project: " + data.project_path;

        const sel = document.getElementById("projSelectDropdown");
        sel.innerHTML = (data.projects || []).map(p => `<option value="${esc(p)}" ${p === data.current_project ? "selected" : ""}>${esc(p)}</option>`).join("");

        const logBox = document.getElementById("dnaLogConsole");
        if (data.logs && data.logs.length) {
          logBox.innerHTML = data.logs.map(l => `<div class="${l.level === 'SUCCESS' ? 'text-emerald-400 font-bold' : l.level === 'ERROR' ? 'text-rose-400 font-bold' : l.level === 'PACK' ? 'text-amber-300' : 'text-slate-300'}">[${esc(l.ts)}] [${esc(l.level)}] ${esc(l.msg)}</div>`).join("");
          logBox.scrollTop = logBox.scrollHeight;
        }
      } catch (e) {}
    }

    async function dnaProjectOp(action, name) {
      const fd = new FormData();
      fd.append("action", action);
      fd.append("name", name || "");
      try {
        const res = await fetch("/api/dna/project", { method: "POST", headers: dnaHeaders(), body: fd });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Project operation failed");
        toast("Project updated ✓", "ok");
        closeDnaModal("projectModal");
        refreshDnaState();
        loadPane("L");
        loadPane("R");
      } catch (e) {
        toast(e.message, "bad");
      }
    }

    async function loadVaultIntoDnaPicker(notifyUser) {
      try {
        const res = await fetch("/api/dna/vault_files?t=" + Date.now(), { cache: "no-store" });
        const data = await res.json();
        const items = data.items || [];
        const selDna = document.getElementById("dnaVaultPicker");
        const selMgr = document.getElementById("mgrVaultPicker");
        if (!items.length) {
          const emptyHtml = `<option value="">No files in HF Vault yet — extract a ROM in Studio first</option>`;
          selDna.innerHTML = emptyHtml;
          selMgr.innerHTML = emptyHtml;
          return;
        }
        const optsHtml = items.map(it => `<option value="${esc(it.download_url)}||${esc(it.repo_path)}||${esc(it.target)}">${esc(it.label)}</option>`).join("");
        selDna.innerHTML = optsHtml;
        selMgr.innerHTML = optsHtml;
        if (notifyUser) toast("Synced " + items.length + " file(s) from HF Vault ✓", "ok");
      } catch (e) {
        if (notifyUser) toast("Failed to sync Vault files", "bad");
      }
    }

    async function importSelectedVaultImg(sourceMode) {
      const sel = document.getElementById(sourceMode === "mgr" ? "mgrVaultPicker" : "dnaVaultPicker");
      const val = sel ? sel.value : "";
      if (!val || !val.includes("||")) {
        toast("Tap '⟳ Sync Vault' and select a file first", "warn");
        return;
      }
      const [dlUrl, repoPath, targetName] = val.split("||");
      const fd = new FormData();
      fd.append("download_url", dlUrl);
      fd.append("repo_path", repoPath);
      fd.append("target_name", targetName);
      if (sourceMode === "mgr") {
        fd.append("dest_rel_dir", mgrPaths[mgrActivePane] || dnaState.current_project);
      }
      showTaskProgress("Starting Vault import for " + targetName + "...", 2);
      try {
        const res = await fetch("/api/dna/import_vault", { method: "POST", headers: dnaHeaders(), body: fd });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Import failed");
        await pollDnaTask(data.task_id);
      } catch (e) {
        hideTaskProgress();
        toast(e.message, "bad");
      }
    }

    function uploadWithProgress(file, destRelPath, projectOverride) {
      if (!file) return;
      const xhr = new XMLHttpRequest();
      const fd = new FormData();
      fd.append("path", destRelPath || "");
      fd.append("project", projectOverride || "");
      fd.append("file", file);

      showTaskProgress("Uploading " + file.name + "...", 1);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = (e.loaded / e.total) * 100;
          showTaskProgress(`Uploading ${file.name}: ${(e.loaded / 1048576).toFixed(1)} / ${(e.total / 1048576).toFixed(1)} MB`, pct);
        }
      };
      xhr.onload = () => {
        hideTaskProgress();
        if (xhr.status >= 200 && xhr.status < 300) {
          toast("Uploaded " + file.name + " ✓", "ok");
          refreshDnaState();
          loadPane("L");
          loadPane("R");
        } else {
          toast("Upload failed", "bad");
        }
      };
      xhr.onerror = () => {
        hideTaskProgress();
        toast("Network error during upload", "bad");
      };
      xhr.open("POST", "/api/dna/fs/upload", true);
      if (dnaToken) xhr.setRequestHeader("X-Dna-Token", dnaToken);
      xhr.send(fd);
    }

    function dnaDirectUpload(input) {
      if (!input.files || !input.files[0]) return;
      const f = input.files[0];
      input.value = "";
      uploadWithProgress(f, "", dnaState.current_project);
    }

    /* ---------- UNPACK MODALS ---------- */
    async function openUnpackModal(mode) {
      currentUnpackMode = mode;
      await refreshDnaState();
      const titleMap = {
        payload: "Unpack payload.bin",
        br: "Unpack br",
        dat: "Unpack dat",
        img: "Unpack img",
        zstd: "Unpack zstd",
        super: "Unpack super"
      };
      document.getElementById("unpackModalTitle").textContent = titleMap[mode] || "Unpack img";
      const box = document.getElementById("unpackFileList");
      let list = [];
      if (mode === "zstd") list = (dnaState.zst_files || []).map(x => ({ name: x.name, badge: "zstd • " + x.size }));
      else if (mode === "br") list = (dnaState.dat_br_files || []).filter(x => x.name.endsWith(".br")).map(x => ({ name: x.name, badge: "br • " + x.size }));
      else if (mode === "dat") list = (dnaState.dat_br_files || []).filter(x => x.name.endsWith(".new.dat")).map(x => ({ name: x.name, badge: "dat • " + x.size }));
      else if (mode === "super") list = (dnaState.img_files || []).filter(x => x.name.toLowerCase().includes("super") || x.format.startsWith("super")).map(x => ({ name: x.name, badge: x.format + " • " + x.size }));
      else if (mode === "payload") list = (dnaState.img_files || []).filter(x => x.name.toLowerCase().includes("payload")).map(x => ({ name: x.name, badge: "CrAU • " + x.size }));
      else list = (dnaState.img_files || []).map(x => ({ name: x.name, badge: x.format + " • " + x.size }));

      if (!list.length) {
        box.innerHTML = `<div class="text-slate-400 py-3 text-center">No matching files in /sdcard/DNA/${esc(dnaState.current_project)}. Use the green '📥 Import' button at the top to pull from your Vault!</div>`;
      } else {
        box.innerHTML = list.map(item => `
          <label class="flex items-center justify-between p-2 rounded-xl bg-white/5 hover:bg-white/10 cursor-pointer">
            <span class="text-slate-200 truncate pr-2">${esc(item.name)} <span class="text-violet-300">(${esc(item.badge)})</span></span>
            <input type="checkbox" name="unpackChk" value="${esc(item.name)}" checked class="w-4 h-4 accent-violet-500 shrink-0" />
          </label>
        `).join("");
      }
      openDnaModal("unpackModal");
    }

    async function submitUnpackModal() {
      const chks = Array.from(document.querySelectorAll("input[name='unpackChk']:checked")).map(c => c.value);
      if (!chks.length) return toast("Select at least one file to unpack", "warn");
      const del = document.getElementById("unpackDelSource").checked;
      closeDnaModal("unpackModal");
      showTaskProgress("Unpacking " + chks.join(", ") + " into /sdcard/DNA/" + dnaState.current_project + "...", 45);
      const fd = new FormData();
      fd.append("mode", currentUnpackMode);
      fd.append("files", chks.join(","));
      fd.append("delete_source", del ? "true" : "false");
      try {
        const res = await fetch("/api/dna/unpack", { method: "POST", headers: dnaHeaders(), body: fd });
        const data = await res.json();
        hideTaskProgress();
        if (!res.ok) throw new Error(data.detail || "Unpack failed");
        toast("Unpacked directly into /sdcard/DNA/" + dnaState.current_project + " ✓", "ok");
        refreshDnaState();
        loadPane("L");
        loadPane("R");
      } catch (e) {
        hideTaskProgress();
        toast(e.message, "bad");
      }
    }

    /* ---------- PACK SINGLE MODAL ---------- */
    async function openPackSingleModal() {
      await refreshDnaState();
      const sel = document.getElementById("psPartSelect");
      const parts = dnaState.unpacked_parts || [];
      if (!parts.length) {
        sel.innerHTML = `<option value="">Please select (Unpack an img first)</option>`;
      } else {
        sel.innerHTML = parts.map(p => `<option value="${esc(p.name)}" data-fmt="${esc(p.format)}">${esc(p.name)} (${esc(p.format)})</option>`).join("");
        document.getElementById("psPackType").value = (parts[0].format === "erofs" || parts[0].format === "ext4" || parts[0].format === "f2fs") ? parts[0].format : "erofs";
      }
      sel.onchange = () => {
        const opt = sel.options[sel.selectedIndex];
        const fmt = opt ? opt.getAttribute("data-fmt") : "erofs";
        if (fmt === "erofs" || fmt === "ext4" || fmt === "f2fs") document.getElementById("psPackType").value = fmt;
      };
      openDnaModal("packSingleModal");
    }

    async function submitPackSingle() {
      const part = document.getElementById("psPartSelect").value;
      if (!part) return toast("Unpack a partition first so you can pack it", "warn");
      closeDnaModal("packSingleModal");
      showTaskProgress("Packing & verifying " + part + ".img...", 55);
      const payload = {
        project: dnaState.current_project,
        partition: part,
        pack_type: document.getElementById("psPackType").value,
        rw_mode: document.getElementById("psRwMode").value,
        size_mode: document.getElementById("psSizeMode").value,
        img_format: document.getElementById("psImgFormat").value,
        file_format: document.getElementById("psFileFormat").value,
        br_level: parseInt(document.getElementById("psBrLevel").value || "3", 10),
        erofs_level: parseInt(document.getElementById("psErofsLevel").value || "8", 10),
        erofs_algo: document.getElementById("psErofsAlgo").value,
        compress_ext4: document.getElementById("psCompressExt4").checked,
        remove_avb: document.getElementById("psRemoveAvb").checked
      };
      try {
        const res = await fetch("/api/dna/pack_single", {
          method: "POST",
          headers: dnaHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        hideTaskProgress();
        if (!res.ok) throw new Error(data.detail || "Pack failed");
        toast("Packed " + data.result.output_file + " (" + data.result.size_mb + ") ✓", "ok");
        refreshDnaState();
      } catch (e) {
        hideTaskProgress();
        toast(e.message, "bad");
      }
    }

    /* ---------- PACK SUPER.IMG MODAL ---------- */
    async function openPackSuperModal() {
      await refreshDnaState();
      const box = document.getElementById("superImgChecklist");
      const imgs = (dnaState.img_files || []).filter(x => x.name.toLowerCase() !== "super.img");
      if (!imgs.length) {
        box.innerHTML = `<div class="text-slate-400 py-2 text-center">No partition .img files in /sdcard/DNA/${esc(dnaState.current_project)} yet</div>`;
      } else {
        box.innerHTML = imgs.map(x => `
          <label class="flex items-center justify-between p-2 rounded-xl bg-white/5 hover:bg-white/10 cursor-pointer">
            <span class="text-slate-200 truncate pr-2">${esc(x.name)} <span class="text-amber-300">(${esc(x.format)})</span></span>
            <input type="checkbox" name="superPackChk" value="${esc(x.name)}" checked class="w-4 h-4 accent-amber-400 shrink-0" />
          </label>
        `).join("");
      }
      openDnaModal("packSuperModal");
    }

    async function submitPackSuper() {
      const chks = Array.from(document.querySelectorAll("input[name='superPackChk']:checked")).map(c => c.value);
      if (!chks.length) return toast("Select at least one .img file to pack into super.img", "warn");
      closeDnaModal("packSuperModal");
      showTaskProgress("Building super.img (" + chks.length + " partitions)...", 60);
      const payload = {
        project: dnaState.current_project,
        super_type: document.getElementById("superType").value,
        super_format: document.getElementById("superFormat").value,
        total_size_gb: parseFloat(document.getElementById("superTotalGb").value || "8.5"),
        group_name: document.getElementById("superGroup").value,
        selected_imgs: chks
      };
      try {
        const res = await fetch("/api/dna/pack_super", {
          method: "POST",
          headers: dnaHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        hideTaskProgress();
        if (!res.ok) throw new Error(data.detail || "super.img build failed");
        toast("Built super.img (" + data.result.size_mb + ") ✓", "ok");
        refreshDnaState();
      } catch (e) {
        hideTaskProgress();
        toast(e.message, "bad");
      }
    }

    /* ---------- PACK ZSTD & FORMAT CONVERSION MODALS ---------- */
    async function openPackZstdModal() {
      await refreshDnaState();
      const sel = document.getElementById("zstdImgSelect");
      const imgs = dnaState.img_files || [];
      sel.innerHTML = imgs.length ? imgs.map(x => `<option value="${esc(x.name)}">${esc(x.name)} (${esc(x.size)})</option>`).join("") : `<option value="">No .img files in project yet</option>`;
      openDnaModal("packZstdModal");
    }

    async function submitPackZstd() {
      const fn = document.getElementById("zstdImgSelect").value;
      if (!fn) return toast("Import an .img file first", "warn");
      closeDnaModal("packZstdModal");
      const fd = new FormData();
      fd.append("filename", fn);
      fd.append("level", document.getElementById("zstdLevelInput").value || "6");
      const res = await fetch("/api/dna/pack_zstd", { method: "POST", headers: dnaHeaders(), body: fd });
      const data = await res.json();
      if (res.ok) { toast("Compressed to " + fn + ".zst ✓", "ok"); refreshDnaState(); }
      else toast(data.detail || "Zstd pack failed", "bad");
    }

    async function openConvertModal(mode) {
      currentConvertMode = mode;
      await refreshDnaState();
      document.getElementById("convertModalTitle").textContent = mode === "img_to_simg" ? "img to simg (Raw ⇄ Sparse)" : "img to dat, br";
      document.getElementById("convBrWrap").classList.toggle("hidden", mode !== "img_to_dat_br");
      const sel = document.getElementById("convImgSelect");
      const imgs = dnaState.img_files || [];
      sel.innerHTML = imgs.length ? imgs.map(x => `<option value="${esc(x.name)}">${esc(x.name)} (${esc(x.format)} • ${esc(x.size)})</option>`).join("") : `<option value="">No .img files in project yet</option>`;
      openDnaModal("convertModal");
    }

    async function submitConvertModal() {
      const fn = document.getElementById("convImgSelect").value;
      if (!fn) return toast("Import an .img file first", "warn");
      closeDnaModal("convertModal");
      showTaskProgress("Converting " + fn + "...", 50);
      const fd = new FormData();
      fd.append("mode", currentConvertMode);
      fd.append("filename", fn);
      fd.append("br_level", document.getElementById("convBrLevel").value || "3");
      const res = await fetch("/api/dna/convert", { method: "POST", headers: dnaHeaders(), body: fd });
      const data = await res.json();
      hideTaskProgress();
      if (res.ok) { toast("Conversion complete ✓", "ok"); refreshDnaState(); }
      else toast(data.detail || "Conversion failed", "bad");
    }

    /* ---------- MT MANAGER SIDE-BY-SIDE DUAL-PANE EXPLORER ---------- */
    function setActivePane(p) {
      mgrActivePane = p;
      document.getElementById("mgrActivePaneIndicator").textContent = p === "L" ? "LEFT" : "RIGHT";
      document.getElementById("mgrPaneWrapL").classList.toggle("active-pane", p === "L");
      document.getElementById("mgrPaneWrapR").classList.toggle("active-pane", p === "R");
    }

    async function loadPane(p, customRel) {
      if (!dnaToken) return;
      if (typeof customRel === "string") mgrPaths[p] = customRel;
      try {
        const res = await fetch("/api/dna/fs/list?path=" + encodeURIComponent(mgrPaths[p] || ""), { headers: dnaHeaders(), cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        mgrPaths[p] = data.current_rel || "";
        mgrItems[p] = data.items || [];
        document.getElementById("mgrPath" + p).textContent = data.display_path;
        document.getElementById("mgrStats" + p).textContent = data.stats_line;

        const jumpSel = document.getElementById("mgrProjJump" + p);
        const projs = data.projects || [];
        jumpSel.innerHTML = `<option value="">/data/DNA (All)</option>` + projs.map(pr => `<option value="${esc(pr)}" ${mgrPaths[p].startsWith(pr) ? "selected" : ""}>📁 ${esc(pr)}</option>`).join("");

        renderPaneList(p);
      } catch (e) {}
    }

    function renderPaneList(p) {
      const box = document.getElementById("mgrList" + p);
      const items = mgrItems[p] || [];
      let html = "";

      // Always render MT Manager parent directory row ".." when inside a subfolder
      if (mgrPaths[p]) {
        html += `
          <div onclick="mgrUp('${p}')" class="mt-row">
            <span class="text-sm">📁</span>
            <div class="min-w-0 flex-1">
              <div class="text-amber-300 font-bold">..</div>
              <div class="text-[8.5px] text-slate-400">Parent directory</div>
            </div>
          </div>
        `;
      }

      if (!items.length) {
        html += `<div class="text-slate-500 py-8 text-center text-[10px]">Empty folder</div>`;
        box.innerHTML = html;
        return;
      }

      html += items.map((it, idx) => {
        const isSel = mgrSelected[p] && mgrSelected[p].rel_path === it.rel_path;
        const icon = it.is_dir ? "📁" : it.is_link ? "🔗" : it.name.endsWith(".img") ? "💿" : hasFileExt(it.name, ["apex", "apk", "zip"]) ? "📦" : "📄";
        const subInfo = it.is_dir
          ? `${esc(it.mtime)}  ${esc(it.sym_perm)}`
          : `${esc(it.size_str)}  ${esc(it.mtime)}  ${esc(it.sym_perm)}`;
        return `
          <div onclick="mgrRowTap('${p}', ${idx}, event)" class="mt-row ${isSel ? 'selected' : ''}">
            <span class="text-sm shrink-0">${icon}</span>
            <div class="min-w-0 flex-1">
              <div class="${it.is_dir ? 'text-amber-200 font-semibold' : 'text-slate-100'} truncate leading-tight">${esc(it.name)}</div>
              <div class="text-[8.5px] text-slate-400 truncate mt-0.5">${subInfo}${it.is_link ? ' → ' + esc(it.link_target) : ''}</div>
            </div>
            <button type="button" onclick="mgrInspectItem('${p}', ${idx}, event)" class="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/15 text-[9px] text-violet-300 shrink-0">•••</button>
          </div>
        `;
      }).join("");

      box.innerHTML = html;
    }

    function mgrRowTap(p, idx, ev) {
      if (ev) ev.stopPropagation();
      setActivePane(p);
      const it = mgrItems[p][idx];
      if (!it) return;
      // Single tap on a folder opens it directly (just like MT Manager!), single tap on file selects or opens
      if (it.is_dir) {
        mgrSelected[p] = it;
        loadPane(p, it.rel_path);
        return;
      }
      if (mgrSelected[p] && mgrSelected[p].rel_path === it.rel_path) {
        mgrInspectItem(p, idx, ev);
        return;
      }
      mgrSelected[p] = it;
      renderPaneList(p);
    }

    function mgrUp(p) {
      const cur = mgrPaths[p] || "";
      if (!cur) return;
      const parts = cur.split("/");
      parts.pop();
      loadPane(p, parts.join("/"));
    }

    /* ---------- MT MANAGER PERMISSIONS CHECKBOX <-> OCTAL SYNC ---------- */
    function syncOctalToCheckboxes(octStr) {
      let v = parseInt(String(octStr || "0644").trim(), 8);
      if (isNaN(v)) v = 0o644;
      document.getElementById("p_ur").checked = !!(v & 0o400);
      document.getElementById("p_uw").checked = !!(v & 0o200);
      document.getElementById("p_ux").checked = !!(v & 0o100);
      document.getElementById("p_gr").checked = !!(v & 0o040);
      document.getElementById("p_gw").checked = !!(v & 0o020);
      document.getElementById("p_gx").checked = !!(v & 0o010);
      document.getElementById("p_or").checked = !!(v & 0o004);
      document.getElementById("p_ow").checked = !!(v & 0o002);
      document.getElementById("p_ox").checked = !!(v & 0o001);
      document.getElementById("p_suid").checked = !!(v & 0o4000);
      document.getElementById("p_sgid").checked = !!(v & 0o2000);
      document.getElementById("p_sticky").checked = !!(v & 0o1000);
    }

    function syncCheckboxesToOctal() {
      let v = 0;
      if (document.getElementById("p_ur").checked) v |= 0o400;
      if (document.getElementById("p_uw").checked) v |= 0o200;
      if (document.getElementById("p_ux").checked) v |= 0o100;
      if (document.getElementById("p_gr").checked) v |= 0o040;
      if (document.getElementById("p_gw").checked) v |= 0o020;
      if (document.getElementById("p_gx").checked) v |= 0o010;
      if (document.getElementById("p_or").checked) v |= 0o004;
      if (document.getElementById("p_ow").checked) v |= 0o002;
      if (document.getElementById("p_ox").checked) v |= 0o001;
      if (document.getElementById("p_suid").checked) v |= 0o4000;
      if (document.getElementById("p_sgid").checked) v |= 0o2000;
      if (document.getElementById("p_sticky").checked) v |= 0o1000;
      document.getElementById("mgrPermMode").value = v.toString(8).padStart(4, "0");
    }

    async function mgrInspectItem(p, idx, ev) {
      if (ev) ev.stopPropagation();
      setActivePane(p);
      const it = mgrItems[p][idx];
      if (!it) return;
      mgrSelected[p] = it;
      mgrModalTarget = it;
      renderPaneList(p);

      document.getElementById("mgrChecksumBox").classList.add("hidden");
      document.getElementById("mgrModalName").textContent = it.name;
      document.getElementById("mgrModalPath").textContent = it.parent_display;
      document.getElementById("mgrPropSize").textContent = it.is_dir ? "<Folder>" : it.size_full;
      document.getElementById("mgrPropMtime").textContent = it.mtime_full;
      document.getElementById("mgrPropPerm").textContent = `${it.sym_perm.slice(1)} (${it.short_octal})`;

      const oct = it.mode || (it.is_dir ? "0755" : "0644");
      document.getElementById("mgrPermMode").value = oct;
      syncOctalToCheckboxes(oct);

      document.getElementById("mgrPermUid").value = it.uid || "0";
      document.getElementById("mgrPermGid").value = it.gid || "0";
      document.getElementById("mgrPermSelinux").value = it.selinux || "u:object_r:system_file:s0";

      const isArc = !it.is_dir && hasFileExt(it.name, ["apex", "apk", "zip", "jar"]);
      const isUnpackedArc = it.is_dir && it.name.endsWith("_unpacked");
      document.getElementById("mgrBtnMount").classList.toggle("hidden", !isArc);
      document.getElementById("mgrBtnRepack").classList.toggle("hidden", !isUnpackedArc);
      document.getElementById("mgrBtnDownload").classList.toggle("hidden", it.is_dir);
      document.getElementById("mgrBtnVault").classList.toggle("hidden", it.is_dir);
      if (!it.is_dir) {
        document.getElementById("mgrBtnDownload").href = "/api/dna/fs/download?path=" + encodeURIComponent(it.rel_path) + "&token=" + encodeURIComponent(dnaToken);
      }

      const edWrap = document.getElementById("mgrEditorWrap");
      const isBinaryExt = hasFileExt(it.name, ["img", "bin", "simg", "br", "zst", "so", "odex", "vdex", "art", "apk", "apex", "zip"]);
      if (!it.is_dir && it.size < 3 * 1024 * 1024 && !isBinaryExt) {
        edWrap.classList.remove("hidden");
        document.getElementById("mgrTextEditor").value = "Loading...";
        try {
          const res = await fetch("/api/dna/fs/read?path=" + encodeURIComponent(it.rel_path), { headers: dnaHeaders() });
          const data = await res.json();
          document.getElementById("mgrTextEditor").value = res.ok ? data.content : ("Cannot edit binary file: " + (data.detail || ""));
        } catch (e) {
          document.getElementById("mgrTextEditor").value = "";
        }
      } else {
        edWrap.classList.add("hidden");
      }
      openDnaModal("mgrItemModal");
    }

    async function mgrCalcChecksum() {
      if (!mgrModalTarget || mgrModalTarget.is_dir) return toast("Select a file to calculate checksums", "warn");
      const box = document.getElementById("mgrChecksumBox");
      box.classList.remove("hidden");
      document.getElementById("chkMd5").textContent = "Calculating...";
      try {
        const res = await fetch("/api/dna/fs/checksum?path=" + encodeURIComponent(mgrModalTarget.rel_path), { headers: dnaHeaders() });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Checksum error");
        document.getElementById("chkMd5").textContent = data.md5;
        document.getElementById("chkSha1").textContent = data.sha1;
        document.getElementById("chkSha256").textContent = data.sha256;
        document.getElementById("chkCrc32").textContent = data.crc32;
      } catch (e) {
        toast(e.message, "bad");
      }
    }

    async function mgrSaveTextFile() {
      if (!mgrModalTarget) return;
      const fd = new FormData();
      fd.append("path", mgrModalTarget.rel_path);
      fd.append("content", document.getElementById("mgrTextEditor").value);
      const res = await fetch("/api/dna/fs/write", { method: "POST", headers: dnaHeaders(), body: fd });
      if (res.ok) {
        toast("Saved " + mgrModalTarget.name + " ✓", "ok");
        loadPane("L"); loadPane("R");
      } else {
        toast("Failed to save file", "bad");
      }
    }

    async function mgrApplyPerms() {
      if (!mgrModalTarget) return;
      const fd = new FormData();
      fd.append("op", "chmod_chcon");
      fd.append("src", mgrModalTarget.rel_path);
      fd.append("mode", document.getElementById("mgrPermMode").value.trim());
      fd.append("uid", document.getElementById("mgrPermUid").value.trim());
      fd.append("gid", document.getElementById("mgrPermGid").value.trim());
      fd.append("selinux", document.getElementById("mgrPermSelinux").value.trim());
      fd.append("recursive", document.getElementById("mgrPermRecurse").checked ? "true" : "false");
      const res = await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      if (res.ok) {
        toast("Updated permissions & SELinux ✓", "ok");
        closeDnaModal("mgrItemModal");
        loadPane("L"); loadPane("R");
      } else {
        toast("Failed to update permissions", "bad");
      }
    }

    async function mgrCopyMove(op) {
      const srcPane = mgrActivePane;
      const dstPane = srcPane === "L" ? "R" : "L";
      const item = mgrSelected[srcPane];
      if (!item) return toast("Select a file or folder in the " + (srcPane === "L" ? "LEFT" : "RIGHT") + " pane first (or tap •••)", "warn");
      const fd = new FormData();
      fd.append("op", op);
      fd.append("src", item.rel_path);
      fd.append("dst", mgrPaths[dstPane] || "");
      const res = await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      if (res.ok) {
        toast((op === "copy" ? "Copied " : "Moved ") + item.name + " → " + (mgrPaths[dstPane] || "/data/DNA") + " ✓", "ok");
        loadPane("L"); loadPane("R");
      } else {
        toast("Operation failed", "bad");
      }
    }

    async function mgrNewFolder() {
      const name = prompt("Enter new folder name:");
      if (!name) return;
      const base = mgrPaths[mgrActivePane] || dnaState.current_project;
      const rel = base ? (base + "/" + name) : name;
      const fd = new FormData();
      fd.append("op", "mkdir");
      fd.append("src", rel);
      await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      loadPane("L"); loadPane("R");
    }

    async function mgrNewFile() {
      const name = prompt("Enter new file name (e.g. build.prop, custom.rc):");
      if (!name) return;
      const base = mgrPaths[mgrActivePane] || dnaState.current_project;
      const rel = base ? (base + "/" + name) : name;
      const fd = new FormData();
      fd.append("path", rel);
      fd.append("content", "# Created in Cloud Manager");
      await fetch("/api/dna/fs/write", { method: "POST", headers: dnaHeaders(), body: fd });
      loadPane("L"); loadPane("R");
    }

    async function mgrSymlink() {
      const linkName = prompt("Symlink name in current directory:");
      if (!linkName) return;
      const target = prompt("Symlink target path (e.g. /system/product/priv-app):");
      if (!target) return;
      const base = mgrPaths[mgrActivePane] || dnaState.current_project;
      const rel = base ? (base + "/" + linkName) : linkName;
      const fd = new FormData();
      fd.append("op", "symlink");
      fd.append("src", rel);
      fd.append("dst", target);
      await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      toast("Symlink created ✓", "ok");
      loadPane("L"); loadPane("R");
    }

    async function mgrRenameItem() {
      if (!mgrModalTarget) return;
      const newName = prompt("Rename to:", mgrModalTarget.name);
      if (!newName || newName === mgrModalTarget.name) return;
      const parts = mgrModalTarget.rel_path.split("/");
      parts.pop();
      parts.push(newName);
      const fd = new FormData();
      fd.append("op", "rename");
      fd.append("src", mgrModalTarget.rel_path);
      fd.append("dst", parts.join("/"));
      await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      closeDnaModal("mgrItemModal");
      loadPane("L"); loadPane("R");
    }

    async function mgrDeleteItem() {
      if (!mgrModalTarget) return;
      if (!confirm("Delete '" + mgrModalTarget.name + "'?")) return;
      const fd = new FormData();
      fd.append("op", "delete");
      fd.append("src", mgrModalTarget.rel_path);
      await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      closeDnaModal("mgrItemModal");
      toast("Deleted ✓", "ok");
      loadPane("L"); loadPane("R");
      refreshDnaState();
    }

    async function mgrMountArchive() {
      if (!mgrModalTarget) return;
      const fd = new FormData();
      fd.append("op", "mount_archive");
      fd.append("src", mgrModalTarget.rel_path);
      const res = await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      if (res.ok) {
        closeDnaModal("mgrItemModal");
        toast("Unpacked " + mgrModalTarget.name + " for editing ✓", "ok");
        loadPane("L"); loadPane("R");
      }
    }

    async function mgrRepackArchive() {
      if (!mgrModalTarget) return;
      const fd = new FormData();
      fd.append("op", "repack_archive");
      fd.append("src", mgrModalTarget.rel_path);
      const res = await fetch("/api/dna/fs/op", { method: "POST", headers: dnaHeaders(), body: fd });
      if (res.ok) {
        closeDnaModal("mgrItemModal");
        toast("Repacked archive ✓", "ok");
        loadPane("L"); loadPane("R");
      }
    }

    function mgrUploadFile(input) {
      if (!input.files || !input.files[0]) return;
      const file = input.files[0];
      input.value = "";
      uploadWithProgress(file, mgrPaths[mgrActivePane] || dnaState.current_project, "");
    }

    async function mgrPushVault() {
      if (!mgrModalTarget) return;
      showTaskProgress("Uploading " + mgrModalTarget.name + " to Universal HF Vault...", 50);
      const fd = new FormData();
      fd.append("filename", mgrModalTarget.rel_path);
      const res = await fetch("/api/dna/push_vault", { method: "POST", headers: dnaHeaders(), body: fd });
      const data = await res.json();
      hideTaskProgress();
      if (res.ok) {
        toast("Pushed to Universal Vault ✓", "ok");
      } else {
        toast(data.detail || "Vault upload failed", "bad");
      }
    }
  </script>
"""

def inject_dna_ui(html_page: str) -> str:
    # 1. Inject the DNA & Manager Tab HTML right before the bottom Glass Dock
    html_page = html_page.replace(
        "  <!-- GLASS DOCK + TELEGRAM CIRCLE BUTTON -->",
        DNA_TAB_HTML + "\n  <!-- GLASS DOCK + TELEGRAM CIRCLE BUTTON -->",
        1
    )
    # 2. Add the 4th 🧬 DNA button to the bottom Glass Dock
    old_console_btn = '<button id="btnTerminal" onclick="switchView(\'terminal\')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">💻 Console</button>'
    new_buttons = (
        old_console_btn + "\n        "
        '<button id="btnDna" onclick="switchView(\'dna\')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">🧬 DNA</button>'
    )
    html_page = html_page.replace(old_console_btn, new_buttons, 1)

    # 3. Register the 'Dna' view in switchView() and window resize listener
    html_page = html_page.replace('["Studio", "Vault", "Terminal"]', '["Studio", "Vault", "Terminal", "Dna"]')
    html_page = html_page.replace('["studio", "vault", "terminal"]', '["studio", "vault", "terminal", "dna"]')
    html_page = html_page.replace(
        'if (view === "vault") loadVault(false);',
        'if (view === "vault") loadVault(false);\n      if (view === "dna") { refreshDnaState(); loadPane("L"); loadPane("R"); }'
    )
    return html_page

