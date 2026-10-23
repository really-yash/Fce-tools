import os
import re
import time
import uuid
import json
import zlib
import shutil
import struct
import zipfile
import gc
import ctypes
import tempfile
import tarfile
import hashlib
import threading
import subprocess
import requests
import zstandard as zstd
from datetime import datetime
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Header, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional

try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False

router = APIRouter(prefix="/api/dna")

DNA_BASE_DIR = os.environ.get("DNA_BASE_DIR", "/tmp/sdcard_DNA")
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
ADMIN_PASS = "7352676143"

AUTH_LOCK = threading.Lock()
USERS_DB = {}          # u_low -> {"username", "pw_hash", "plain_pw", "ip", "banned", "created_at"}
BANNED_IPS = set()
SESSIONS = {}          # token -> u_low
USER_STATES = {}       # u_low -> {"current_project": str, "logs": list}
BG_TASKS = {}          # task_id -> {"state", "pct", "label", "error"}

HF_API_REF = None
DATASET_REPO_REF = ""
HF_TOKEN_REF = ""

# ---------------- USER AUTH & ADMIN BAN SYSTEM ---------------- #

def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "0.0.0.0"

def _hash_pw(username: str, password: str) -> str:
    salt = f"hyperflux_dna_salt::{username.strip().lower()}"
    return hashlib.sha256(f"{salt}::{password}".encode("utf-8")).hexdigest()

def _rebuild_ban_set():
    BANNED_IPS.clear()
    for u_obj in USERS_DB.values():
        if isinstance(u_obj, dict) and u_obj.get("banned") and u_obj.get("ip"):
            BANNED_IPS.add(u_obj["ip"])

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
    _rebuild_ban_set()

def _save_users_db():
    _rebuild_ban_set()
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
                    commit_message="Sync DNA users & bans DB"
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
        raise HTTPException(status_code=401, detail="Please Sign In first.")
    t = token.replace("Bearer ", "").strip()
    u_low = SESSIONS.get(t)
    if not u_low and t.startswith("u:"):
        parts = t.split(":")
        if len(parts) == 3:
            cand, sig = parts[1], parts[2]
            u_obj = USERS_DB.get(cand)
            if u_obj:
                expected = hashlib.sha256(f"{cand}::{u_obj['pw_hash']}::flux".encode()).hexdigest()[:24]
                if sig == expected:
                    SESSIONS[t] = cand
                    u_low = cand
    if not u_low:
        raise HTTPException(status_code=401, detail="Session expired. Please Sign In again.")
    if USERS_DB.get(u_low, {}).get("banned"):
        raise HTTPException(status_code=403, detail="BANNED: Your account has been banned by Admin.")
    return u_low

def make_user_token(u_low: str, pw_hash: str) -> str:
    sig = hashlib.sha256(f"{u_low}::{pw_hash}::flux".encode()).hexdigest()[:24]
    tok = f"u:{u_low}:{sig}"
    SESSIONS[tok] = u_low
    return tok

def get_user_root(username: str) -> str:
    u_clean = re.sub(r"[^a-zA-Z0-9_-]", "_", username.strip().lower())
    root = os.path.join(USERS_ROOT_DIR, u_clean)
    os.makedirs(root, exist_ok=True)
    if not os.listdir(root):
        dp = os.path.join(root, "Default_Project")
        os.makedirs(os.path.join(dp, "config"), exist_ok=True)
    return root

def get_proj_dir(username: str, proj: Optional[str] = None) -> str:
    ustate = get_user_state(username)
    u_root = get_user_root(username)
    raw_name = (proj if proj is not None else ustate["current_project"]).strip()
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name) or "Default_Project"
    ustate["current_project"] = name
    p = os.path.join(u_root, name)
    os.makedirs(os.path.join(p, "config"), exist_ok=True)
    return p

def dna_log(username: str, level: str, msg: str):
    ustate = get_user_state(username)
    ts = datetime.now().strftime("%H:%M:%S")
    ustate["logs"].append({"ts": ts, "level": level, "msg": msg})
    if len(ustate["logs"]) > 200:
        ustate["logs"] = ustate["logs"][-200:]

def safe_join(base: str, rel: str) -> str:
    rel_clean = (rel or "").lstrip("/\\")
    full = os.path.abspath(os.path.join(base, rel_clean))
    base_abs = os.path.abspath(base)
    if full != base_abs and not full.startswith(base_abs + os.sep):
        raise HTTPException(status_code=400, detail="Path traversal blocked.")
    return full

def create_bg_task(initial_label: str) -> str:
    if len(BG_TASKS) > 60:
        for k in [k for k, v in BG_TASKS.items() if v.get("state") != "running"][:30]:
            BG_TASKS.pop(k, None)
    tid = uuid.uuid4().hex[:10]
    BG_TASKS[tid] = {"state": "running", "pct": 2, "label": initial_label, "error": None}
    return tid

def set_bg_task(tid: str, pct: int, label: str = None):
    if tid in BG_TASKS:
        BG_TASKS[tid]["pct"] = max(1, min(99, int(pct)))
        if label:
            BG_TASKS[tid]["label"] = label

# ---------------- LOW-RAM / ATOMIC-WRITE / HF-SAVE HELPERS ---------------- #

PROC_START = datetime.now()
HEAVY = threading.Semaphore(1)          # only ONE heavy job at a time (512 MB RAM safe)
HF_UP_LOCK = threading.Lock()           # only ONE HF upload at a time
AUTO_HF = os.environ.get("DNA_AUTO_HF", "1") == "1"                    # auto-save packed outputs to HF dataset
FREE_AFTER_PUSH = os.environ.get("DNA_FREE_AFTER_PUSH", "0") == "1"    # delete local copy after HF save (optional)
ZERO_BLOCK = b"\x00" * (4 * MB)

def _read_first(paths):
    for p in paths:
        try:
            with open(p) as f:
                return f.read().strip()
        except Exception:
            pass
    return None

def mem_stats() -> dict:
    mb = lambda v: (round(int(v) / MB, 1) if v and v.isdigit() else v)
    ev = _read_first(["/sys/fs/cgroup/memory.events", "/sys/fs/cgroup/memory/memory.oom_control"]) or ""
    oom = [l for l in ev.splitlines() if l.split() and l.split()[0] == "oom_kill"]
    return {
        "ram_now_mb": mb(_read_first(["/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"])),
        "ram_peak_mb": mb(_read_first(["/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory/memory.max_usage_in_bytes"])),
        "ram_limit_mb": mb(_read_first(["/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"])),
        "oom_kills": oom[0] if oom else "unknown",
    }

def drop_tree_cache(path: str):
    """After a big extract: flush + release page-cache of every extracted file (keeps RAM peak low)."""
    try:
        os.sync()
    except Exception:
        pass
    for root, _d, files in os.walk(path):
        for fn in files:
            fp = os.path.join(root, fn)
            if not os.path.islink(fp):
                drop_cache(fp)

def free_ram():
    try:
        gc.collect()
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except Exception:
        pass

def safe_remove(p):
    try:
        if p and os.path.lexists(p):
            os.remove(p)
    except Exception:
        pass

def drop_cache(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    except Exception:
        pass

class Flusher:
    """Every 64 MB written: flush + fsync + drop page-cache so RAM never fills up."""
    def __init__(self, f, step=64 * MB):
        self.f, self.step, self.n = f, step, 0
    def add(self, k):
        self.n += k
        if self.n >= self.step:
            self.n = 0
            try:
                self.f.flush()
                os.fsync(self.f.fileno())
                os.posix_fadvise(self.f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            except Exception:
                pass

def copy_lowram(fin, fout, length=4 * MB):
    fl = Flusher(fout)
    while True:
        b = fin.read(length)
        if not b:
            break
        fout.write(b)
        fl.add(len(b))

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(4 * MB)
            if not b:
                break
            h.update(b)
        try:
            os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        except Exception:
            pass
    return h.hexdigest()

def run_quiet(cmd):
    """Run a tool without capturing its stdout in RAM. Returns (returncode, last 1.5KB of stderr)."""
    with tempfile.TemporaryFile() as ef:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=ef)
        sz = ef.seek(0, 2)
        ef.seek(max(0, sz - 1500))
        err = ef.read().decode("utf-8", "ignore")
    if r.returncode in (-9, 137):
        err = "KILLED BY OS: out of memory (try lz4 / lower compression level, or a smaller partition). " + err
    return r.returncode, err

def brotli_compress_file(src, dst, lvl):
    tmp = dst + ".part"
    safe_remove(tmp)
    try:
        if shutil.which("brotli"):
            rc, err = run_quiet(["brotli", f"-q{lvl}", "-f", "-o", tmp, src])
            if rc != 0:
                raise Exception(f"brotli failed: {err}")
        elif BROTLI_AVAILABLE:
            c = brotli.Compressor(quality=lvl)
            proc = getattr(c, "process", None) or c.compress
            with open(src, "rb") as fi, open(tmp, "wb") as fo:
                fl = Flusher(fo)
                while True:
                    b = fi.read(4 * MB)
                    if not b:
                        break
                    o = proc(b)
                    fo.write(o)
                    fl.add(len(o))
                fo.write(c.finish())
        else:
            raise Exception("brotli is not installed.")
        if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
            raise Exception("Brotli output is empty.")
        os.replace(tmp, dst)
    finally:
        safe_remove(tmp)
        free_ram()

def brotli_decompress_file(src, dst):
    tmp = dst + ".part"
    safe_remove(tmp)
    try:
        if shutil.which("brotli"):
            rc, err = run_quiet(["brotli", "-d", "-f", "-o", tmp, src])
            if rc != 0:
                raise Exception(f"brotli -d failed: {err}")
        elif BROTLI_AVAILABLE:
            d = brotli.Decompressor()
            proc = getattr(d, "process", None) or d.decompress
            with open(src, "rb") as fi, open(tmp, "wb") as fo:
                fl = Flusher(fo)
                while True:
                    b = fi.read(1 * MB)
                    if not b:
                        break
                    o = proc(b)
                    fo.write(o)
                    fl.add(len(o))
        else:
            raise Exception("brotli is not installed.")
        if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
            raise Exception("Brotli output is empty (corrupt .br?).")
        os.replace(tmp, dst)
    finally:
        safe_remove(tmp)
        free_ram()

# ---------------- PERSONAL HF "ROOM" (permanent home of every user's ROM; /tmp is only a scratch cache) ---------------- #
# HF layout:  rooms/<user>/<project>/trees/<folder>.tar.zst   (unpacked partitions + config, symlinks & modes kept)
#             rooms/<user>/<project>/files/<name>              (imgs, super.img, .br/.dat, ...)

ROOM_LOCK = threading.Lock()
ROOM_DIRTY = {}
ROOM_RESTORED = set()
ROOM_BOOTED = set()
RESTORE_IMGS = os.environ.get("DNA_RESTORE_IMGS", "0") == "1"

def _uclean(u: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", (u or "").strip().lower()) or "guest"

def room_enabled() -> bool:
    return bool(AUTO_HF and HF_API_REF and DATASET_REPO_REF and HF_TOKEN_REF)

def _rp(u, proj, kind, name):
    return f"rooms/{_uclean(u)}/{proj}/{kind}/{name}"

def room_push_file(u, proj_dir, rel):
    if not room_enabled():
        return
    fp = os.path.join(proj_dir, rel)
    proj = os.path.basename(proj_dir)
    if not os.path.isfile(fp) or fp.endswith(".part"):
        return

    def _w():
        with HF_UP_LOCK:
            try:
                if not os.path.isfile(fp):
                    return
                HF_API_REF.upload_file(path_or_fileobj=fp, path_in_repo=_rp(u, proj, "files", rel), repo_id=DATASET_REPO_REF,
                                       repo_type="dataset", commit_message=f"room {_uclean(u)}/{proj}: {rel}")
                dna_log(u, "SUCCESS", f"Saved '{rel}' to your HF room ✓")
                if FREE_AFTER_PUSH:
                    safe_remove(fp)
            except Exception as e:
                dna_log(u, "ERROR", f"HF room save failed for '{rel}': {e}")
            finally:
                drop_cache(fp)
                free_ram()
    threading.Thread(target=_w, daemon=True).start()

def hf_autosave(username: str, proj_dir: str, fname: str):
    room_push_file(username, proj_dir, fname)

def room_push_tree(u, proj_dir, top):
    if not room_enabled():
        return
    src = os.path.join(proj_dir, top)
    proj = os.path.basename(proj_dir)

    def _w():
        with HF_UP_LOCK:
            tmp = os.path.join(TASKS_TMP_DIR, f"room_{uuid.uuid4().hex[:8]}.tar.zst")
            try:
                if not os.path.isdir(src):
                    return
                with open(tmp, "wb") as fh:
                    with zstd.ZstdCompressor(level=3).stream_writer(fh) as zw:
                        with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                            tf.add(src, arcname=top)
                HF_API_REF.upload_file(path_or_fileobj=tmp, path_in_repo=_rp(u, proj, "trees", f"{top}.tar.zst"),
                                       repo_id=DATASET_REPO_REF, repo_type="dataset",
                                       commit_message=f"room {_uclean(u)}/{proj}: {top}")
                dna_log(u, "SUCCESS", f"Saved '{top}/' to your HF room ✓")
            except Exception as e:
                dna_log(u, "ERROR", f"HF room save failed for '{top}/': {e}")
            finally:
                safe_remove(tmp)
                free_ram()
    threading.Thread(target=_w, daemon=True).start()

def room_mark_dirty(u, proj_dir, top, delay=25):
    """Debounced: many quick edits -> ONE upload after 25 s of quiet."""
    if not room_enabled():
        return
    key = (_uclean(u), proj_dir, top)

    def _fire():
        with ROOM_LOCK:
            ROOM_DIRTY.pop(key, None)
        room_push_tree(u, proj_dir, top)
    with ROOM_LOCK:
        old = ROOM_DIRTY.pop(key, None)
        if old:
            old.cancel()
        t = threading.Timer(delay, _fire)
        t.daemon = True
        ROOM_DIRTY[key] = t
        t.start()

def room_delete(u, proj, kind=None, name=None, whole=False):
    if not room_enabled():
        return

    def _w():
        with HF_UP_LOCK:
            try:
                if whole:
                    HF_API_REF.delete_folder(path_in_repo=f"rooms/{_uclean(u)}/{proj}", repo_id=DATASET_REPO_REF, repo_type="dataset")
                else:
                    HF_API_REF.delete_file(path_in_repo=_rp(u, proj, kind, name), repo_id=DATASET_REPO_REF, repo_type="dataset")
            except Exception:
                pass
    threading.Thread(target=_w, daemon=True).start()

def room_note_change(u, u_root, rel, deleted_kind=None):
    """Called after any manager edit: keeps the HF room identical to the working copy."""
    parts = [p for p in (rel or "").replace("\\", "/").split("/") if p]
    if len(parts) < 2:
        return
    proj, top = parts[0], parts[1]
    proj_dir = os.path.join(u_root, proj)
    full = os.path.join(proj_dir, top)
    if len(parts) == 2:
        if deleted_kind == "dir" or (not os.path.lexists(full) and deleted_kind is None):
            room_delete(u, proj, "trees", top + ".tar.zst")
        elif deleted_kind == "file":
            room_delete(u, proj, "files", top)
        elif os.path.isdir(full):
            room_mark_dirty(u, proj_dir, top)
        elif os.path.isfile(full):
            room_push_file(u, proj_dir, top)
    elif os.path.isdir(full):
        room_mark_dirty(u, proj_dir, top)

def room_restore_tree(u, proj_dir, top):
    from huggingface_hub import hf_hub_download
    proj = os.path.basename(proj_dir)
    dst = os.path.join(proj_dir, top)
    work = os.path.join(proj_dir, f".restore_{top}")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=TASKS_TMP_DIR) as td:
        p = hf_hub_download(repo_id=DATASET_REPO_REF, filename=_rp(u, proj, "trees", f"{top}.tar.zst"),
                            repo_type="dataset", token=HF_TOKEN_REF, local_dir=td)
        with open(p, "rb") as fh:
            with zstd.ZstdDecompressor().stream_reader(fh) as zr:
                with tarfile.open(fileobj=zr, mode="r|") as tf:
                    for m in tf:
                        if m.name.startswith("/") or ".." in m.name.split("/"):
                            continue
                        if m.isdir():
                            m.mode |= 0o700
                        tf.extract(m, work)
        safe_remove(p)
    got = os.path.join(work, top)
    if not os.path.isdir(got):
        shutil.rmtree(work, ignore_errors=True)
        raise Exception(f"room archive for '{top}' was empty")
    if os.path.lexists(dst):
        shutil.rmtree(dst, ignore_errors=True)
    os.replace(got, dst)
    shutil.rmtree(work, ignore_errors=True)
    free_ram()

def room_bootstrap(u):
    """Once per server start: recreate the user's project folders from their HF room."""
    key = _uclean(u)
    if key in ROOM_BOOTED or not room_enabled():
        return
    ROOM_BOOTED.add(key)
    try:
        pre = f"rooms/{key}/"
        root = get_user_root(u)
        for f in HF_API_REF.list_repo_files(repo_id=DATASET_REPO_REF, repo_type="dataset"):
            if f.startswith(pre) and f.count("/") >= 4:
                os.makedirs(os.path.join(root, f[len(pre):].split("/")[0], "config"), exist_ok=True)
    except Exception:
        pass

def room_restore_async(u, proj_dir):
    proj = os.path.basename(proj_dir)
    key = (_uclean(u), proj)
    if key in ROOM_RESTORED or not room_enabled():
        return
    ROOM_RESTORED.add(key)

    def _job():
        try:
            from huggingface_hub import hf_hub_download
            files = HF_API_REF.list_repo_files(repo_id=DATASET_REPO_REF, repo_type="dataset")
            tpre = f"rooms/{key[0]}/{proj}/trees/"
            fpre = f"rooms/{key[0]}/{proj}/files/"
            tops = sorted([f[len(tpre):-8] for f in files if f.startswith(tpre) and f.endswith(".tar.zst")], key=lambda x: x != "config")
            for t in tops:
                d = os.path.join(proj_dir, t)
                if os.path.isdir(d) and os.listdir(d):
                    continue
                dna_log(u, "ROOM", f"Restoring '{t}/' from your HF room...")
                try:
                    room_restore_tree(u, proj_dir, t)
                    dna_log(u, "SUCCESS", f"Restored '{t}/' from your HF room ✓")
                except Exception as e:
                    dna_log(u, "ERROR", f"Restore of '{t}/' failed: {e}")
            if RESTORE_IMGS:
                for f in files:
                    if f.startswith(fpre):
                        rel = f[len(fpre):]
                        out = safe_join(proj_dir, rel)
                        if os.path.exists(out):
                            continue
                        dna_log(u, "ROOM", f"Restoring file '{rel}' from your HF room...")
                        os.makedirs(os.path.dirname(out), exist_ok=True)
                        with tempfile.TemporaryDirectory(dir=TASKS_TMP_DIR) as td:
                            p = hf_hub_download(repo_id=DATASET_REPO_REF, filename=f, repo_type="dataset", token=HF_TOKEN_REF, local_dir=td)
                            shutil.move(p, out + ".part")
                        os.replace(out + ".part", out)
                        dna_log(u, "SUCCESS", f"Restored '{rel}' ✓")
        except Exception as e:
            ROOM_RESTORED.discard(key)
            dna_log(u, "ERROR", f"Room restore failed: {e}")
    _spawn(_job, None, heavy=True)

def _spawn(fn, tid=None, heavy=True):
    """Run a worker thread: one heavy job at a time, always free RAM at the end, never leave a task stuck."""
    def _run():
        got = False
        try:
            if heavy:
                if not HEAVY.acquire(blocking=False):
                    if tid:
                        set_bg_task(tid, 1, "Waiting for previous job to finish (saves RAM)...")
                    HEAVY.acquire()
                got = True
            fn()
        except Exception as e:
            if tid in BG_TASKS:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})
        finally:
            if tid in BG_TASKS and BG_TASKS[tid].get("state") == "running":
                BG_TASKS[tid].update({"state": "error", "error": "Task ended unexpectedly."})
            if got:
                HEAVY.release()
            free_ram()
    threading.Thread(target=_run, daemon=True).start()

# ---------------- SUPER.IMG SELF-VERIFY (independent liblp-spec parser) ---------------- #

def copy_hash(fin, fout, length=4 * MB) -> str:
    h = hashlib.sha256()
    fl = Flusher(fout)
    while True:
        b = fin.read(length)
        if not b:
            break
        fout.write(b)
        h.update(b)
        fl.add(len(b))
    return h.hexdigest()

def fs_verify_image(path: str, ptype: str, username: str = ""):
    """Full filesystem check (not just the header). A failing image is NOT saved."""
    tool = {"ext4": ["e2fsck", "-fn", path], "erofs": ["fsck.erofs", path], "f2fs": ["fsck.f2fs", "-f", path]}.get(ptype)
    if not tool or not shutil.which(tool[0]):
        if username:
            dna_log(username, "WARN", f"{tool[0] if tool else ptype} not installed: filesystem NOT fully verified.")
        return
    rc, err = run_quiet(tool)
    if rc != 0:
        raise Exception(f"Anti-Corrupt Guard: {tool[0]} found problems (rc={rc}). Image not saved. {err[-250:].strip()}")
    if username:
        dna_log(username, "SUCCESS", f"{tool[0]} full filesystem check passed ✓")

def lp_lpdump_check(path: str):
    if shutil.which("lpdump"):
        rc, err = run_quiet(["lpdump", path])
        if rc != 0:
            raise Exception(f"lpdump rejected the super image: {err[-200:]}")

def lp_verify_raw_super(path: str, expect: list, total_bytes: int):
    """Re-reads a RAW super image: checks geometry/header/tables checksums, table layout,
    extent bounds & overlaps, then compares every partition's data hash with its source."""
    z32 = b"\x00" * 32
    with open(path, "rb") as f:
        f.seek(4096)
        g = f.read(52)
        magic, ssz, _ck, _maxsz, slots, lbs = struct.unpack("<II32sIII", g)
        if magic != LP_GEOMETRY_MAGIC or ssz != 52:
            raise Exception("Verify failed: bad LP geometry.")
        if hashlib.sha256(g[:8] + z32 + g[40:]).digest() != g[8:40]:
            raise Exception("Verify failed: geometry checksum mismatch.")
        f.seek(12288)
        h = f.read(256)
        hm, _maj, _min, hsz = struct.unpack_from("<IHHI", h, 0)
        if hm != LP_HEADER_MAGIC or hsz not in (128, 256):
            raise Exception("Verify failed: bad LP header.")
        h = h[:hsz]
        if hashlib.sha256(h[:12] + z32 + h[44:]).digest() != h[12:44]:
            raise Exception("Verify failed: header checksum mismatch.")
        tsz = struct.unpack_from("<I", h, 44)[0]
        f.seek(12288 + hsz)
        tables = f.read(tsz)
        if len(tables) != tsz or hashlib.sha256(tables).digest() != h[48:80]:
            raise Exception("Verify failed: tables checksum mismatch.")
        (p_off, p_n, p_sz, e_off, e_n, e_sz, g_off, g_n, g_sz, b_off, b_n, b_sz) = struct.unpack_from("<12I", h, 80)
        if (p_sz, e_sz, g_sz, b_sz) != (52, 24, 48, 64):
            raise Exception("Verify failed: wrong LP table entry sizes.")
        if b_n < 1:
            raise Exception("Verify failed: no block device in metadata.")
        first_sec, _al, _ao, dev_size = struct.unpack_from("<QIIQ", tables, b_off)
        if dev_size != total_bytes:
            raise Exception("Verify failed: block device size mismatch.")
        exts = []
        for i in range(e_n):
            n_sec, _tt, t_data, _ts = struct.unpack_from("<QIQI", tables, e_off + i * e_sz)
            if t_data < first_sec or (t_data + n_sec) * 512 > dev_size:
                raise Exception("Verify failed: extent outside super bounds.")
            exts.append((t_data, n_sec))
        for a in range(len(exts)):
            for b in range(a + 1, len(exts)):
                if exts[a][0] < exts[b][0] + exts[b][1] and exts[b][0] < exts[a][0] + exts[a][1]:
                    raise Exception("Verify failed: overlapping extents.")
        parts = {}
        for i in range(p_n):
            ent = tables[p_off + i * p_sz: p_off + (i + 1) * p_sz]
            name = ent[:36].split(b"\x00")[0].decode("utf-8", "ignore")
            _at, first_e, num_e, grp = struct.unpack_from("<IIII", ent, 36)
            if grp >= g_n or first_e + num_e > e_n:
                raise Exception(f"Verify failed: bad table indexes for '{name}'.")
            parts[name] = [exts[first_e + k] for k in range(num_e)]
        for name, size, want in expect:
            if name not in parts or not parts[name]:
                raise Exception(f"Verify failed: partition '{name}' missing in metadata.")
            if sum(n for _s, n in parts[name]) * 512 < size:
                raise Exception(f"Verify failed: partition '{name}' extent too small.")
            hh, left = hashlib.sha256(), size
            for s, n in parts[name]:
                f.seek(s * 512)
                take = min(left, n * 512)
                while take > 0:
                    b = f.read(min(take, 4 * MB))
                    if not b:
                        raise Exception(f"Verify failed: '{name}' data truncated.")
                    hh.update(b)
                    take -= len(b)
                    left -= len(b)
            if hh.hexdigest() != want:
                raise Exception(f"Verify failed: data of '{name}' does not match its source image.")
        try:
            os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        except Exception:
            pass
    free_ram()

# ---------------- PERMISSIONS OCTAL <-> SYMBOLIC HELPERS ---------------- #

def mode_octal_to_symbolic(oct_str: str, is_dir: bool = False, is_link: bool = False) -> str:
    prefix = "d" if is_dir else ("l" if is_link else "-")
    try:
        val = int(str(oct_str).strip(), 8)
    except Exception:
        val = 0o755 if is_dir else 0o644
    c = [
        "r" if (val & 0o400) else "-",
        "w" if (val & 0o200) else "-",
        ("s" if (val & 0o100) else "S") if (val & 0o4000) else ("x" if (val & 0o100) else "-"),
        "r" if (val & 0o040) else "-",
        "w" if (val & 0o020) else "-",
        ("s" if (val & 0o010) else "S") if (val & 0o2000) else ("x" if (val & 0o010) else "-"),
        "r" if (val & 0o004) else "-",
        "w" if (val & 0o002) else "-",
        ("t" if (val & 0o001) else "T") if (val & 0o1000) else ("x" if (val & 0o001) else "-"),
    ]
    return prefix + "".join(c)

def format_short_octal(oct_str: str) -> str:
    try:
        v = int(str(oct_str).strip(), 8)
        return f"{v:04o}" if v > 0o777 else f"{v:03o}"
    except Exception:
        return "644"

# ---------------- FILESYSTEM & IMAGE FORMAT DETECTOR ---------------- #

def is_sparse_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            b4 = f.read(4)
            return len(b4) == 4 and struct.unpack("<I", b4)[0] == SPARSE_MAGIC
    except Exception:
        return False

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

# ---------------- ZERO-COPY SPARSE <-> RAW CONVERTERS ---------------- #

def _py_sparse_to_raw(src_path: str, dst_path: str):
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        hdr = src.read(28)
        (_m, _maj, _min, fhs, chs, blk, tblks, tchunks, _crc) = struct.unpack("<IHHHHIIII", hdr)
        if fhs > 28:
            src.seek(fhs - 28, os.SEEK_CUR)
        dst.truncate(tblks * blk)
        fl = Flusher(dst)
        out_off = 0
        for _ in range(tchunks):
            ch = src.read(chs)
            if len(ch) < 12:
                raise Exception("Corrupt sparse image (truncated chunk header).")
            ctype, _r, csz, tsz = struct.unpack("<HHII", ch[:12])
            nbytes = csz * blk
            if ctype == 0xCAC1:
                dst.seek(out_off)
                left = nbytes
                while left > 0:
                    buf = src.read(min(left, 4 * MB))
                    if not buf:
                        raise Exception("Corrupt sparse image (truncated data).")
                    dst.write(buf)
                    left -= len(buf)
                    fl.add(len(buf))
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
                        fl.add(take)
            elif ctype == 0xCAC3:
                pass
            elif ctype == 0xCAC4:
                src.seek(max(0, tsz - chs), os.SEEK_CUR)
            else:
                raise Exception(f"Corrupt sparse image (unknown chunk 0x{ctype:04x}).")
            out_off += nbytes
        if out_off != tblks * blk:
            raise Exception("Corrupt sparse image (size mismatch).")

def sparse_to_raw(src_path: str, dst_path: str):
    """Sparse -> raw, written to .part then atomically renamed (never leaves a half-written image)."""
    tmp = dst_path + ".part"
    safe_remove(tmp)
    try:
        if not is_sparse_file(src_path):
            if os.path.abspath(src_path) == os.path.abspath(dst_path):
                return
            with open(src_path, "rb") as a, open(tmp, "wb") as b:
                copy_lowram(a, b)
        else:
            ok = False
            if shutil.which("simg2img"):
                rc, _e = run_quiet(["simg2img", src_path, tmp])
                ok = rc == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 0
            if not ok:
                _py_sparse_to_raw(src_path, tmp)
        os.replace(tmp, dst_path)
    finally:
        safe_remove(tmp)
        free_ram()

def raw_to_sparse(src_path: str, dst_path: str, block_size: int = 4096):
    tmp = dst_path + ".part"
    safe_remove(tmp)
    try:
        ok = False
        if shutil.which("img2simg"):
            rc, _e = run_quiet(["img2simg", src_path, tmp, str(block_size)])
            ok = rc == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 0
        if not ok:
            total_size = os.path.getsize(src_path)
            total_blocks = (total_size + block_size - 1) // block_size
            step = block_size * 1024
            chunk_meta = []
            with open(src_path, "rb") as src:
                b_idx = 0
                while b_idx < total_blocks:
                    buf = src.read(step)
                    if not buf:
                        break
                    n_blks = (len(buf) + block_size - 1) // block_size
                    chunk_meta.append((0xCAC3 if buf == ZERO_BLOCK[:len(buf)] else 0xCAC1, n_blks))
                    b_idx += n_blks
                try:
                    os.posix_fadvise(src.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                except Exception:
                    pass
            with open(src_path, "rb") as src, open(tmp, "wb") as dst:
                fl = Flusher(dst)
                dst.write(struct.pack("<IHHHHIIII", SPARSE_MAGIC, 1, 0, 28, 12, block_size, total_blocks, len(chunk_meta), 0))
                for ctype, n_blks in chunk_meta:
                    raw_bytes = n_blks * block_size
                    buf = src.read(raw_bytes)
                    if ctype == 0xCAC3:
                        dst.write(struct.pack("<HHII", 0xCAC3, 0, n_blks, 12))
                    else:
                        if len(buf) < raw_bytes:
                            buf += b"\x00" * (raw_bytes - len(buf))
                        dst.write(struct.pack("<HHII", 0xCAC1, 0, n_blks, 12 + raw_bytes))
                        dst.write(buf)
                        fl.add(len(buf))
                    del buf
        if not is_sparse_file(tmp):
            raise Exception("Sparse conversion produced an invalid file.")
        os.replace(tmp, dst_path)
    finally:
        safe_remove(tmp)
        free_ram()

# ---------------- SDAT2IMG & IMG2SDAT ---------------- #

def sdat2img_convert(transfer_path: str, dat_path: str, out_img: str):
    BLOCK_SIZE = 4096
    with open(transfer_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]
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
    del lines

    tmp = out_img + ".part"
    safe_remove(tmp)
    try:
        with open(dat_path, "rb") as dat, open(tmp, "wb") as out:
            out.truncate(max_block * BLOCK_SIZE)
            fl = Flusher(out)
            for pairs in commands:
                for s, e in pairs:
                    out.seek(s * BLOCK_SIZE)
                    left = (e - s) * BLOCK_SIZE
                    while left > 0:
                        chunk = dat.read(min(left, 4 * MB))
                        if not chunk:
                            raise Exception("Corrupt .new.dat (ended early).")
                        out.write(chunk)
                        left -= len(chunk)
                        fl.add(len(chunk))
        os.replace(tmp, out_img)
    finally:
        safe_remove(tmp)
        free_ram()

def img2sdat_convert(src_img: str, out_dir: str, prefix: str) -> tuple:
    need_tmp = is_sparse_file(src_img)
    raw_tmp = src_img + ".raw_tmp" if need_tmp else src_img
    dat_path = os.path.join(out_dir, f"{prefix}.new.dat")
    tl_path = os.path.join(out_dir, f"{prefix}.transfer.list")
    patch_path = os.path.join(out_dir, f"{prefix}.patch.dat")
    try:
        if need_tmp:
            sparse_to_raw(src_img, raw_tmp)
        src_use = raw_tmp if os.path.exists(raw_tmp) else src_img
        BLOCK_SIZE = 4096
        total_size = os.path.getsize(src_use)
        total_blocks = (total_size + BLOCK_SIZE - 1) // BLOCK_SIZE
        open(patch_path, "wb").close()

        new_ranges = []
        with open(src_use, "rb") as src, open(dat_path + ".part", "wb") as dat:
            fl = Flusher(dat)
            b = 0
            while b < total_blocks:
                chunk = src.read(BLOCK_SIZE * 512)
                if not chunk:
                    break
                if len(chunk) % BLOCK_SIZE != 0:
                    chunk += b"\x00" * (BLOCK_SIZE - (len(chunk) % BLOCK_SIZE))
                n = len(chunk) // BLOCK_SIZE
                if chunk != ZERO_BLOCK[:len(chunk)] if len(chunk) <= len(ZERO_BLOCK) else any(chunk):
                    dat.write(chunk)
                    fl.add(len(chunk))
                    if new_ranges and new_ranges[-1][1] == b:
                        new_ranges[-1] = (new_ranges[-1][0], b + n)
                    else:
                        new_ranges.append((b, b + n))
                b += n
            try:
                os.posix_fadvise(src.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            except Exception:
                pass
        os.replace(dat_path + ".part", dat_path)

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
        return dat_path, tl_path
    finally:
        safe_remove(dat_path + ".part")
        if need_tmp:
            safe_remove(raw_tmp)
        free_ram()

# ---------------- FS_CONFIG & FILE_CONTEXTS GENERATOR ---------------- #

def generate_fs_metadata(part_name: str, extract_dir: str, config_dir: str, detected_fmt: str = "erofs"):
    fs_cfg_path = os.path.join(config_dir, f"{part_name}_fs_config")
    fc_path = os.path.join(config_dir, f"{part_name}_file_contexts")
    info_path = os.path.join(config_dir, f"{part_name}_info.json")

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
    fs_lines = ["/ 0 0 0755", f"{part_name} 0 0 0755"]
    fc_lines = [f"/ {default_ctx}", f"/{part_name}(/.*)? {default_ctx}"]

    for root, dirs, files in os.walk(extract_dir):
        rel_root = os.path.relpath(root, extract_dir).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        for d in sorted(dirs):
            rp = f"{part_name}/{rel_root}/{d}".replace("//", "/") if rel_root else f"{part_name}/{d}"
            fs_lines.append(f"{rp} {' '.join(existing_cfg[rp])}" if rp in existing_cfg else f"{rp} 0 0 0755")
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
                    fs_lines.append(f"{rp} 0 0 0644 {os.readlink(full_p)}")
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

# ---------------- UNPACK PARTITION IMAGE (ZERO-COPY WHEN RAW) ---------------- #

def unpack_single_img_file(username: str, proj_dir: str, img_filename: str, delete_source: bool = False, tid: str = None) -> dict:
    src_path = safe_join(proj_dir, img_filename)
    if not os.path.isfile(src_path):
        raise Exception(f"File not found: {img_filename}")

    part_name = re.sub(r"\.(img|bin|simg)$", "", os.path.basename(img_filename), flags=re.I)
    part_name = re.sub(r"_(a|b)$", "", part_name)
    out_dir = os.path.join(proj_dir, part_name)
    config_dir = os.path.join(proj_dir, "config")
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(config_dir, exist_ok=True)

    orig_size = os.path.getsize(src_path)
    need_unsparse = is_sparse_file(src_path)
    raw_tmp = src_path + ".raw_unpack" if need_unsparse else src_path
    was_empty = not os.listdir(out_dir)

    try:
        if need_unsparse:
            if tid:
                set_bg_task(tid, 18, f"Unsparsing {img_filename} ({orig_size / MB:.1f} MB)...")
            sparse_to_raw(src_path, raw_tmp)
            free_ram()

        work_img = raw_tmp if os.path.exists(raw_tmp) else src_path
        fmt = detect_img_type(work_img)
        dna_log(username, "UNPACK", f"Auto-detected '{img_filename}' format: {fmt.upper()} ({orig_size / MB:.1f} MB)")
        if tid:
            set_bg_task(tid, 42, f"Extracting {fmt.upper()} filesystem tree for '{part_name}'...")

        attempts = []
        if fmt == "erofs" and shutil.which("fsck.erofs"):
            attempts.append(("fsck.erofs", ["fsck.erofs", f"--extract={out_dir}", "--overwrite", work_img], True))
        if fmt == "ext4" and shutil.which("debugfs"):
            attempts.append(("debugfs", ["debugfs", "-R", f"rdump / \"{out_dir}\"", work_img], True))
        if shutil.which("7z"):
            attempts.append(("7z", ["7z", "x", "-y", f"-o{out_dir}", work_img], False))

        extracted_ok, last_err = False, ""
        for tool, cmd, accept_partial in attempts:
            rc, err = run_quiet(cmd)
            has_files = bool(os.listdir(out_dir))
            if has_files and (rc == 0 or accept_partial):
                extracted_ok = True
                if rc != 0:
                    dna_log(username, "WARN", f"{tool} finished with warnings (rc={rc}): {err[-200:].strip()}")
                dna_log(username, "UNPACK", f"{tool} unpacked '{part_name}' directly into '{part_name}/'")
                break
            last_err = err
            if was_empty:
                shutil.rmtree(out_dir, ignore_errors=True)
                os.makedirs(out_dir, exist_ok=True)
            free_ram()

        if not extracted_ok:
            if was_empty:
                shutil.rmtree(out_dir, ignore_errors=True)
            raise Exception(f"Could not extract '{img_filename}' (format: {fmt}). {last_err[-250:].strip()}")
        drop_tree_cache(out_dir)
    finally:
        if need_unsparse:
            safe_remove(raw_tmp)
        drop_cache(src_path)
        free_ram()

    if tid:
        set_bg_task(tid, 85, f"Generating fs_config & file_contexts for '{part_name}'...")

    clean_fmt = fmt if fmt in ("erofs", "ext4", "f2fs") else "erofs"
    generate_fs_metadata(part_name, out_dir, config_dir, detected_fmt=clean_fmt)
    info_path = os.path.join(config_dir, f"{part_name}_info.json")
    with open(info_path, "w", encoding="utf-8") as f:
        json.dump({"part_name": part_name, "detected_format": clean_fmt, "orig_size": orig_size}, f, indent=2)

    if delete_source and os.path.exists(src_path):
        os.remove(src_path)
        dna_log(username, "UNPACK", f"Deleted source file '{img_filename}' after unpacking.")

    room_push_tree(username, proj_dir, part_name)
    room_push_tree(username, proj_dir, "config")
    free_ram()
    return {"partition": part_name, "format": fmt, "path": f"/sdcard/DNA/{os.path.basename(proj_dir)}/{part_name}"}

# ---------------- REMOVE AVB / ENCRYPTION FSTAB PATCHER ---------------- #

def patch_fstab_remove_avb_encryption(username: str, part_dir: str) -> int:
    patched_count = 0
    remove_flags = [
        r",?\bavb(?:=[^\s,]+)?", r",?\bavb_keys=[^\s,]+", r",?\bfileencryption=[^\s,]+",
        r",?\bforceencrypt=[^\s,]+", r",?\bforcefdeorfbe=[^\s,]+", r",?\binlinecrypt\b",
        r",?\bmetadata_encryption=[^\s,]+", r",?\bkeydirectory=[^\s,]+", r",?\bverity\b",
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

# ---------------- PACK SINGLE PARTITION ---------------- #

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

def _pack_single_inner(username: str, req: PackSingleRequest, tid: str = None) -> dict:
    proj_dir = get_proj_dir(username, req.project)
    part_name = re.sub(r"[^a-zA-Z0-9._-]", "", req.partition)
    part_dir = safe_join(proj_dir, part_name)
    if not os.path.isdir(part_dir):
        raise Exception(f"Unpacked partition folder '{part_name}' not found in project.")

    if tid:
        set_bg_task(tid, 15, f"Scanning fs_config & SELinux contexts for '{part_name}'...")

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
    if tid:
        set_bg_task(tid, 40, f"Building {ptype.upper()} image for '{part_name}'...")

    if ptype == "erofs":
        if not shutil.which("mkfs.erofs"):
            raise Exception("mkfs.erofs not found in container.")
        lvl = max(0, min(12, int(req.erofs_level)))
        algo = req.erofs_algo if req.erofs_algo in ("lz4hc", "lz4", "lzma", "deflate") else "lz4hc"
        z_arg = f"-z{algo},{lvl}" if algo in ("lz4hc", "lzma", "deflate") else f"-z{algo}"
        cmd = ["mkfs.erofs", z_arg, "--mount-point", f"/{part_name}", "--fs-config-file", fs_cfg, "--file-contexts", fc_file, out_img_raw, part_dir]
        rc, err = run_quiet(cmd)
        if rc != 0 or not os.path.exists(out_img_raw):
            safe_remove(out_img_raw)
            rc2, err2 = run_quiet(["mkfs.erofs", z_arg, "--mount-point", f"/{part_name}", out_img_raw, part_dir])
            if rc2 != 0 or not os.path.exists(out_img_raw):
                raise Exception(f"mkfs.erofs failed: {err2 or err}")

    elif ptype == "ext4":
        if not shutil.which("mke2fs"):
            raise Exception("mke2fs not found in container.")
        info_path = os.path.join(config_dir, f"{part_name}_info.json")
        orig_sz = 0
        if os.path.exists(info_path):
            try:
                with open(info_path) as jf:
                    orig_sz = int(json.load(jf).get("orig_size", 0))
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
        rc, err = run_quiet(cmd)
        if rc != 0 or not os.path.exists(out_img_raw):
            raise Exception(f"mke2fs failed: {err}")

        if req.compress_ext4 and shutil.which("resize2fs"):
            run_quiet(["e2fsck", "-f", "-y", out_img_raw])
            run_quiet(["resize2fs", "-M", out_img_raw])

    elif ptype == "f2fs":
        if not shutil.which("mkfs.f2fs"):
            raise Exception("mkfs.f2fs not installed.")
        used_sz = dir_size_bytes(part_dir)
        target_sz = max(64 * MB, int(used_sz * 1.35) + 48 * MB)
        with open(out_img_raw, "wb") as f:
            f.truncate((target_sz // 4096) * 4096)
        rc, err = run_quiet(["mkfs.f2fs", "-f", "-l", part_name, out_img_raw])
        if rc != 0:
            raise Exception(f"mkfs.f2fs failed: {err}")
        if shutil.which("sload.f2fs"):
            rc, err = run_quiet(["sload.f2fs", "-f", part_dir, "-t", f"/{part_name}", out_img_raw])
            if rc != 0:
                raise Exception(f"sload.f2fs failed: {err}")
    else:
        raise Exception(f"Unknown pack type '{req.pack_type}'.")
    free_ram()

    if not os.path.exists(out_img_raw) or os.path.getsize(out_img_raw) < 4096:
        raise Exception("Anti-Corrupt Guard: Packed image is empty or invalid.")
    chk = detect_img_type(out_img_raw)
    if chk != ptype:
        raise Exception(f"Anti-Corrupt Guard: packed image magic is '{chk}', expected '{ptype}'. Not saved.")

    if tid:
        set_bg_task(tid, 68, f"Checking every block of the {ptype.upper()} filesystem...")
    fs_verify_image(out_img_raw, ptype, username)
    free_ram()

    if req.img_format.lower() == "sparse":
        if tid:
            set_bg_task(tid, 75, f"Converting '{part_name}.img' to Android Sparse format...")
        raw_to_sparse(out_img_raw, out_img_final)
        os.remove(out_img_raw)
    else:
        os.replace(out_img_raw, out_img_final)

    output_file = f"{part_name}.img"
    extra_save = []

    if req.file_format.upper() in ("DAT", "BR"):
        if tid:
            set_bg_task(tid, 85, f"Converting '{part_name}.img' to {req.file_format.upper()}...")
        dat_p, _tl_p = img2sdat_convert(out_img_final, proj_dir, part_name)
        output_file = os.path.basename(dat_p)
        extra_save.append(f"{part_name}.transfer.list")
        if req.file_format.upper() == "BR":
            br_p = f"{dat_p}.br"
            brotli_compress_file(dat_p, br_p, max(0, min(11, int(req.br_level))))
            safe_remove(dat_p)  # intermediate .new.dat no longer needed -> saves disk
            output_file = os.path.basename(br_p)

    final_p = os.path.join(proj_dir, output_file)
    sz_mb = os.path.getsize(final_p) / MB if os.path.exists(final_p) else 0
    dna_log(username, "SUCCESS", f"Packed & verified '{output_file}' ({sz_mb:.2f} MB) in /sdcard/DNA/{os.path.basename(proj_dir)}")
    hf_autosave(username, proj_dir, output_file)
    room_push_tree(username, proj_dir, "config")
    for x in extra_save:
        hf_autosave(username, proj_dir, x)
    return {"output_file": output_file, "size_mb": f"{sz_mb:.2f} MB"}

def pack_single_partition_worker(username: str, req: PackSingleRequest, tid: str = None) -> dict:
    part = re.sub(r"[^a-zA-Z0-9._-]", "", req.partition)
    pdir = get_proj_dir(username, req.project)
    try:
        return _pack_single_inner(username, req, tid)
    except Exception:
        for suf in (".raw.img", ".img.part", ".new.dat.part"):
            safe_remove(os.path.join(pdir, part + suf))
        raise
    finally:
        free_ram()

# ---------------- PURE-PYTHON LPMAKE SUPER.IMG BUILDER ---------------- #

class PackSuperRequest(BaseModel):
    project: Optional[str] = None
    super_type: str = "a_only"
    super_format: str = "sparse"
    total_size_gb: float = 8.5
    group_name: str = "qti_dynamic_partitions"
    selected_imgs: List[str]

def _build_super_inner(username: str, req: PackSuperRequest, tid: str = None) -> dict:
    proj_dir = get_proj_dir(username, req.project)
    if not req.selected_imgs:
        raise Exception("Please select at least one .img file to pack into super.img.")

    total_bytes = int(float(req.total_size_gb) * (1024 ** 3))
    total_bytes = (total_bytes // 4096) * 4096
    raw_super = os.path.join(proj_dir, "super.raw.img")
    final_super = os.path.join(proj_dir, "super.img")

    part_entries = []
    expect = []
    data_cursor = 1024 * 1024

    with open(raw_super, "wb") as out:
        out.truncate(total_bytes)

        for idx_i, img_name in enumerate(req.selected_imgs, 1):
            src_p = safe_join(proj_dir, img_name)
            if not os.path.isfile(src_p):
                raise Exception(f"Selected image '{img_name}' does not exist.")
            base_stem = re.sub(r"\.img$", "", os.path.basename(img_name), flags=re.I)
            base_stem = re.sub(r"_(a|b)$", "", base_stem)
            p_name = base_stem if req.super_type == "a_only" else f"{base_stem}_a"

            if tid:
                set_bg_task(tid, int(10 + (idx_i / max(1, len(req.selected_imgs))) * 65), f"Writing '{p_name}' ({idx_i}/{len(req.selected_imgs)}) into super.img...")

            need_unsparse = is_sparse_file(src_p)
            tmp_raw = src_p + ".lp_raw" if need_unsparse else src_p
            if need_unsparse:
                sparse_to_raw(src_p, tmp_raw)
            use_p = tmp_raw if os.path.exists(tmp_raw) else src_p
            p_size = os.path.getsize(use_p)
            p_size_aligned = ((p_size + 4095) // 4096) * 4096

            if data_cursor + p_size_aligned > total_bytes - (2 * MB):
                if need_unsparse and os.path.exists(tmp_raw):
                    os.remove(tmp_raw)
                raise Exception(f"Total partition size exceeds super.img limit ({req.total_size_gb} GB).")

            out.seek(data_cursor)
            with open(use_p, "rb") as pf:
                src_hash = copy_hash(pf, out)
            free_ram()
            if need_unsparse and os.path.exists(tmp_raw):
                os.remove(tmp_raw)

            start_sector = data_cursor // 512
            num_sectors = (p_size + 511) // 512
            part_entries.append((p_name, start_sector, num_sectors))
            expect.append((p_name, p_size, src_hash))
            data_cursor += p_size_aligned

            if req.super_type in ("ab", "virtual_ab"):
                part_entries.append((f"{base_stem}_b", 0, 0))

        ab = req.super_type in ("ab", "virtual_ab")
        gmax = ((total_bytes - 4 * MB) // 2) // MB * MB if ab else total_bytes - (2 * MB)
        if ab and (data_cursor - 1024 * 1024) > gmax:
            raise Exception(f"Partitions ({(data_cursor - MB) / MB:.0f} MB) do not fit in one A/B slot group ({gmax / MB:.0f} MB). Increase super size.")
        geom_body = struct.pack("<II32sIII", LP_GEOMETRY_MAGIC, 52, b"\x00" * 32, 65536, 2 if req.super_type != "a_only" else 1, 4096)
        geom_crc = hashlib.sha256(geom_body).digest()
        geom = geom_body[:8] + geom_crc + geom_body[40:]
        geom_padded = geom.ljust(4096, b"\x00")

        p_table = bytearray()
        e_table = bytearray()
        extent_idx = 0
        for p_name, s_sec, n_sec in part_entries:
            name_b = p_name.encode("utf-8")[:36].ljust(36, b"\x00")
            p_attr = 3 if ab else 1                      # readonly (+ slot-suffixed on A/B)
            p_grp = (2 if p_name.endswith("_b") else 1) if ab else 1
            if n_sec > 0:
                p_table += name_b + struct.pack("<IIII", p_attr, extent_idx, 1, p_grp)
                e_table += struct.pack("<QIQI", n_sec, 0, s_sec, 0)
                extent_idx += 1
            else:
                p_table += name_b + struct.pack("<IIII", p_attr, 0, 0, p_grp)

        grp_default = b"default".ljust(36, b"\x00") + struct.pack("<IQ", 0, 0)
        gname = (req.group_name or "qti_dynamic_partitions").strip()
        if ab:   # real A/B phones: <group>_a and <group>_b, both flagged slot-suffixed
            grp_table = grp_default
            for suf in ("_a", "_b"):
                grp_table += (gname + suf).encode("utf-8")[:36].ljust(36, b"\x00") + struct.pack("<IQ", 1, gmax)
            g_count = 3
        else:
            grp_table = grp_default + gname.encode("utf-8")[:36].ljust(36, b"\x00") + struct.pack("<IQ", 0, gmax)
            g_count = 2
        bdev_table = struct.pack("<QIIQ36sI", 2048, 4096, 0, total_bytes, b"super".ljust(36, b"\x00"), 0)

        p_off = 0
        e_off = len(p_table)
        g_off = e_off + len(e_table)
        b_off = g_off + len(grp_table)
        tables_blob = bytes(p_table + e_table + grp_table + bdev_table)
        tables_sha = hashlib.sha256(tables_blob).digest()

        vab = req.super_type == "virtual_ab"
        header_size = 256 if vab else 128
        hdr_without_crc = (
            struct.pack("<IHHI", LP_HEADER_MAGIC, 10, 2 if vab else 0, header_size)
            + b"\x00" * 32
            + struct.pack("<I", len(tables_blob))
            + tables_sha
            + struct.pack("<12I", p_off, len(part_entries), 52, e_off, extent_idx, 24, g_off, g_count, 48, b_off, 1, 64)
            + ((struct.pack("<I", 1) + b"\x00" * 124) if vab else b"")   # header flags: VIRTUAL_AB_DEVICE
        )
        hdr_sha = hashlib.sha256(hdr_without_crc).digest()
        lp_header = hdr_without_crc[:12] + hdr_sha + hdr_without_crc[44:]

        out.seek(4096)
        out.write(geom_padded)
        out.seek(8192)
        out.write(geom_padded)
        out.seek(12288)
        out.write(lp_header + tables_blob)

    if tid:
        set_bg_task(tid, 80, "Verifying super.img metadata + partition data...")
    lp_verify_raw_super(raw_super, expect, total_bytes)
    lp_lpdump_check(raw_super)
    dna_log(username, "SUCCESS", "super.img verified: checksums, tables and every partition hash match.")

    if req.super_format.lower() == "sparse":
        if tid:
            set_bg_task(tid, 85, "Converting super.img to Android Sparse format...")
        raw_to_sparse(raw_super, final_super)
        os.remove(raw_super)
    else:
        os.replace(raw_super, final_super)

    sz_mb = os.path.getsize(final_super) / MB
    dna_log(username, "SUCCESS", f"Packed & verified super.img ({req.super_type}, {req.super_format}) → {sz_mb:.1f} MB!")
    return {"output_file": "super.img", "size_mb": f"{sz_mb:.1f} MB"}

def _raw_hash_size(path: str):
    if is_sparse_file(path):
        tmp = path + ".lp_raw"
        try:
            sparse_to_raw(path, tmp)
            return sha256_file(tmp), os.path.getsize(tmp)
        finally:
            safe_remove(tmp)
    return sha256_file(path), os.path.getsize(path)

def _build_super_lpmake(username: str, req: PackSuperRequest, tid: str = None) -> dict:
    proj_dir = get_proj_dir(username, req.project)
    total_bytes = (int(float(req.total_size_gb) * (1024 ** 3)) // 4096) * 4096
    raw_super = os.path.join(proj_dir, "super.raw.img")
    final_super = os.path.join(proj_dir, "super.img")
    ab = req.super_type in ("ab", "virtual_ab")
    grp = (req.group_name or "qti_dynamic_partitions").strip()
    gmax = ((total_bytes - 4 * MB) // (2 if ab else 1)) // MB * MB
    cmd = ["lpmake", "--metadata-size", "65536", "--metadata-slots", "2" if ab else "1",
           "--device", f"super:{total_bytes}", "--super-name", "super"]
    if ab:
        cmd += ["--auto-slot-suffixing", f"--group", f"{grp}_a:{gmax}", "--group", f"{grp}_b:{gmax}"]
    else:
        cmd += ["--group", f"{grp}:{gmax}"]
    if req.super_type == "virtual_ab":
        cmd += ["--virtual-ab"]
    expect = []
    for i, img in enumerate(req.selected_imgs, 1):
        src = safe_join(proj_dir, img)
        if not os.path.isfile(src):
            raise Exception(f"Selected image '{img}' does not exist.")
        if tid:
            set_bg_task(tid, int(5 + i / max(1, len(req.selected_imgs)) * 30), f"Hashing '{img}' for verification...")
        stem = re.sub(r"_(a|b)$", "", re.sub(r"\.img$", "", os.path.basename(img), flags=re.I))
        digest, size = _raw_hash_size(src)
        if ab:
            cmd += ["--partition", f"{stem}_a:readonly:{size}:{grp}_a", "--image", f"{stem}_a={src}",
                    "--partition", f"{stem}_b:readonly:0:{grp}_b"]
            expect.append((f"{stem}_a", size, digest))
        else:
            cmd += ["--partition", f"{stem}:readonly:{size}:{grp}", "--image", f"{stem}={src}"]
            expect.append((stem, size, digest))
    cmd += ["--output", raw_super]
    safe_remove(raw_super)
    if tid:
        set_bg_task(tid, 45, "Building super.img with real lpmake...")
    rc, err = run_quiet(cmd)
    if rc != 0 or not os.path.exists(raw_super):
        raise Exception(f"lpmake failed: {err[-300:]}")
    if tid:
        set_bg_task(tid, 75, "Verifying lpmake output...")
    lp_verify_raw_super(raw_super, expect, total_bytes)
    lp_lpdump_check(raw_super)
    if req.super_format.lower() == "sparse":
        raw_to_sparse(raw_super, final_super)
        os.remove(raw_super)
    else:
        os.replace(raw_super, final_super)
    sz_mb = os.path.getsize(final_super) / MB
    dna_log(username, "SUCCESS", f"super.img built by real lpmake & verified → {sz_mb:.1f} MB")
    return {"output_file": "super.img", "size_mb": f"{sz_mb:.1f} MB"}

def build_super_image(username: str, req: PackSuperRequest, tid: str = None) -> dict:
    pdir = get_proj_dir(username, req.project)
    try:
        res = None
        if shutil.which("lpmake"):
            try:
                res = _build_super_lpmake(username, req, tid)
            except Exception as e:
                safe_remove(os.path.join(pdir, "super.raw.img"))
                dna_log(username, "WARN", f"lpmake path failed ({e}); using built-in builder instead.")
        if res is None:
            res = _build_super_inner(username, req, tid)
        hf_autosave(username, pdir, "super.img")
        return res
    except Exception:
        safe_remove(os.path.join(pdir, "super.raw.img"))
        raise
    finally:
        for n in os.listdir(pdir):
            if n.endswith((".lp_raw", ".part")):
                safe_remove(os.path.join(pdir, n))
        free_ram()

# ---------------- SETUP & API ENDPOINTS ---------------- #

def setup_dna_manager(app, html_page: str, jobs_dict: dict, hf_api, dataset_repo: str, hf_token: str) -> str:
    global HF_API_REF, DATASET_REPO_REF, HF_TOKEN_REF
    HF_API_REF = hf_api
    DATASET_REPO_REF = dataset_repo
    HF_TOKEN_REF = hf_token

    threading.Thread(target=_load_users_db, daemon=True).start()
    from huggingface_hub import hf_hub_url

    @app.middleware("http")
    async def _ban_shield_middleware(request: Request, call_next):
        ip = _client_ip(request)
        path = request.url.path
        if ip in BANNED_IPS and not path.startswith("/api/dna/admin") and path != "/admin":
            return JSONResponse({"detail": "BANNED: Your IP address has been banned by Admin."}, status_code=403)
        return await call_next(request)

    def _current_user(x_dna_token: Optional[str]) -> str:
        return resolve_user_from_token(x_dna_token)

    # ---- AUTH ENDPOINTS ----
    @router.post("/auth/signup")
    def api_auth_signup(request: Request, username: str = Form(...), password: str = Form(...)):
        ip = _client_ip(request)
        if ip in BANNED_IPS:
            raise HTTPException(status_code=403, detail="Your IP address is banned.")
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
                "plain_pw": password,
                "ip": ip,
                "banned": False,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            _save_users_db()
        get_proj_dir(u_low, "Default_Project")
        tok = make_user_token(u_low, pw_hash)
        dna_log(u_low, "AUTH", f"Welcome @{u_raw}! Private workspace initialized.")
        return {"ok": True, "token": tok, "username": u_raw}

    @router.post("/auth/login")
    def api_auth_login(request: Request, username: str = Form(...), password: str = Form(...)):
        ip = _client_ip(request)
        if ip in BANNED_IPS:
            raise HTTPException(status_code=403, detail="Your IP address is banned.")
        u_raw = username.strip()
        u_low = u_raw.lower()
        user_obj = USERS_DB.get(u_low)
        if not user_obj or user_obj.get("pw_hash") != _hash_pw(u_low, password):
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        if user_obj.get("banned"):
            raise HTTPException(status_code=403, detail="Your account has been banned by Admin.")
        user_obj["ip"] = ip
        user_obj["plain_pw"] = password
        _save_users_db()
        get_proj_dir(u_low)
        tok = make_user_token(u_low, user_obj["pw_hash"])
        return {"ok": True, "token": tok, "username": user_obj["username"]}

    @router.get("/auth/me")
    def api_auth_me(request: Request, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        user_obj = USERS_DB.get(u_low, {"username": u_low})
        user_obj["ip"] = _client_ip(request)
        return {"ok": True, "username": user_obj.get("username", u_low)}

    # ---- ADMIN PANEL ENDPOINTS (Password: 7352676143) ----
    def _verify_admin(pw: str):
        if (pw or "").strip() != ADMIN_PASS:
            raise HTTPException(status_code=403, detail="Invalid Admin Password.")

    @router.post("/admin/list")
    def api_admin_list(admin_pass: str = Form(...)):
        _verify_admin(admin_pass)
        users_out = []
        for u_low, obj in sorted(USERS_DB.items()):
            u_root = os.path.join(USERS_ROOT_DIR, re.sub(r"[^a-zA-Z0-9_-]", "_", u_low))
            projs = sorted(os.listdir(u_root)) if os.path.exists(u_root) else []
            users_out.append({
                "u_low": u_low,
                "username": obj.get("username", u_low),
                "password": obj.get("plain_pw", "(hidden)"),
                "ip": obj.get("ip", "—"),
                "banned": bool(obj.get("banned", False)),
                "created_at": obj.get("created_at", "—"),
                "projects": projs
            })
        return {"ok": True, "users": users_out, "banned_ips": list(BANNED_IPS)}

    @router.post("/admin/action")
    def api_admin_action(admin_pass: str = Form(...), action: str = Form(...), target_user: str = Form(...)):
        _verify_admin(admin_pass)
        u_low = target_user.strip().lower()
        if u_low not in USERS_DB:
            raise HTTPException(status_code=404, detail="User not found.")
        with AUTH_LOCK:
            if action == "ban":
                USERS_DB[u_low]["banned"] = True
                for tok, u in list(SESSIONS.items()):
                    if u == u_low:
                        SESSIONS.pop(tok, None)
            elif action == "unban":
                USERS_DB[u_low]["banned"] = False
            elif action == "delete":
                USERS_DB.pop(u_low, None)
                u_root = os.path.join(USERS_ROOT_DIR, re.sub(r"[^a-zA-Z0-9_-]", "_", u_low))
                shutil.rmtree(u_root, ignore_errors=True)
            _save_users_db()
        return api_admin_list(admin_pass)

    # ---- UNIVERSAL VAULT FILE LISTER ----
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
                    repo_path = dl.split("/resolve/main/", 1)[1] if "/resolve/main/" in dl else ""
                    key = repo_path or dl
                    if key and key not in seen_paths:
                        seen_paths.add(key)
                        items.append({"label": f"{t} — {dev} [{ver}] ({sz})", "target": t, "repo_path": repo_path, "download_url": dl, "size": sz})
        except Exception:
            pass

        if hf_api and dataset_repo:
            try:
                for rf in hf_api.list_repo_files(repo_id=dataset_repo, repo_type="dataset"):
                    if rf in ("vault_index.json", "users_db.json", ".gitattributes") or rf.endswith("rom_info.json") or rf.startswith("rooms/"):
                        continue
                    if rf not in seen_paths:
                        seen_paths.add(rf)
                        base = os.path.basename(rf)
                        dl = hf_hub_url(repo_id=dataset_repo, filename=rf, repo_type="dataset")
                        items.append({"label": f"{base} — ({rf})", "target": base, "repo_path": rf, "download_url": dl, "size": "HF Vault"})
            except Exception:
                pass
        return {"items": items}

    @router.get("/task/{task_id}")
    def api_dna_task_status(task_id: str):
        t = BG_TASKS.get(task_id)
        if not t:
            raise HTTPException(status_code=404, detail="Task not found")
        return t

    def _dispatch_gh_worker(u_low: str, action: str, target_file: str, options: dict, label: str) -> str:
        gh_token = (os.environ.get("GH_DISPATCH_TOKEN") or "").strip()
        if gh_token.startswith("Github_pat_"):
            gh_token = "g" + gh_token[1:]
        if not gh_token:
            raise HTTPException(status_code=500, detail="Missing GH_DISPATCH_TOKEN in Render Environment.")

        ustate = get_user_state(u_low)
        proj = ustate["current_project"]
        url = "https://api.github.com/repos/really-yash/Fce-tools/actions/workflows/worker.yml/dispatches"
        headers = {
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {
            "ref": "main",
            "inputs": {
                "action": action,
                "username": _uclean(u_low),
                "project": proj,
                "target_file": target_file,
                "options": json.dumps(options)
            }
        }
        res = requests.post(url, headers=headers, json=payload, timeout=15)
        if res.status_code != 204:
            raise HTTPException(status_code=500, detail=f"GitHub dispatch failed ({res.status_code}): {res.text}")

        tid = create_bg_task(f"[GitHub 7GB Worker] {label}")
        dna_log(u_low, "WORKER", f"Dispatched '{action}' for '{target_file}' to GitHub 7GB Server ✓")

        def _poll_gh():
            time.sleep(5)
            runs_url = "https://api.github.com/repos/really-yash/Fce-tools/actions/workflows/worker.yml/runs?per_page=1"
            for step in range(1, 360):
                try:
                    r = requests.get(runs_url, headers=headers, timeout=10)
                    if r.status_code == 200:
                        runs = r.json().get("workflow_runs", [])
                        if runs:
                            latest = runs[0]
                            st = latest.get("status")
                            conc = latest.get("conclusion")
                            if st in ("queued", "waiting", "pending"):
                                set_bg_task(tid, 15, f"[GitHub 7GB] Queued: {label}...")
                            elif st == "in_progress":
                                pct = min(92, 25 + step * 2)
                                set_bg_task(tid, pct, f"[GitHub 7GB] Running: {label}...")
                            elif st == "completed":
                                if conc == "success":
                                    BG_TASKS[tid].update({"pct": 100, "label": f"Completed on GitHub: {label} ✓", "state": "done"})
                                    dna_log(u_low, "SUCCESS", f"GitHub 7GB Worker finished: {label} ✓")
                                else:
                                    BG_TASKS[tid].update({"state": "error", "error": f"GitHub Worker failed ({conc}). Check GitHub Actions logs."})
                                    dna_log(u_low, "ERROR", f"GitHub Worker failed ({conc}) for {label}")
                                return
                except Exception:
                    pass
                time.sleep(4)
            BG_TASKS[tid].update({"state": "error", "error": "Worker timed out in HUD (check GitHub Actions tab)."})

        threading.Thread(target=_poll_gh, daemon=True).start()
        return tid

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
        if project:
            get_proj_dir(u_low, project)
        safe_name = os.path.basename(target_name.strip())
        tid = _dispatch_gh_worker(
            u_low, "import_vault", safe_name,
            {"download_url": download_url, "repo_path": repo_path, "dest_rel_dir": dest_rel_dir},
            f"Importing {safe_name}"
        )
        return {"ok": True, "task_id": tid}

    @router.get("/state")
    def api_dna_state(project: Optional[str] = None, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        ustate = get_user_state(u_low)
        u_root = get_user_root(u_low)
        room_bootstrap(u_low)
        proj_dir = get_proj_dir(u_low, project)
        proj_name = ustate["current_project"]
        projects = sorted([d for d in os.listdir(u_root) if os.path.isdir(os.path.join(u_root, d))])

        img_files, unpacked_parts, zst_files, dat_br_files = [], [], [], []
        seen_files, seen_parts = set(), set()

        # 1. Read files & unpacked trees directly from Hugging Face Room (Zero RAM used on Render!)
        if room_enabled():
            try:
                u_key = _uclean(u_low)
                fpre = f"rooms/{u_key}/{proj_name}/files/"
                tpre = f"rooms/{u_key}/{proj_name}/trees/"
                for rf in HF_API_REF.list_repo_files(repo_id=DATASET_REPO_REF, repo_type="dataset"):
                    if rf.startswith(fpre):
                        fn = rf[len(fpre):]
                        if "/" not in fn and fn not in seen_files:
                            seen_files.add(fn)
                            low = fn.lower()
                            if low.endswith((".img", ".bin", ".simg")):
                                img_files.append({"name": fn, "format": "cloud", "size": "HF Room"})
                            elif low.endswith(".zst"):
                                zst_files.append({"name": fn, "size": "HF Room"})
                            elif low.endswith((".br", ".new.dat", ".transfer.list")):
                                dat_br_files.append({"name": fn, "size": "HF Room"})
                    elif rf.startswith(tpre) and rf.endswith(".tar.zst"):
                        tname = rf[len(tpre):-8]
                        if tname != "config" and tname not in seen_parts:
                            seen_parts.add(tname)
                            unpacked_parts.append({"name": tname, "format": "erofs"})
            except Exception:
                pass

        # 2. Also include any local files in proj_dir
        for entry in sorted(os.listdir(proj_dir)):
            full = os.path.join(proj_dir, entry)
            if os.path.isfile(full) and entry not in seen_files:
                low = entry.lower()
                sz = f"{os.path.getsize(full) / MB:.2f} MB"
                if low.endswith((".img", ".bin", ".simg")):
                    img_files.append({"name": entry, "format": detect_img_type(full), "size": sz})
                elif low.endswith(".zst"):
                    zst_files.append({"name": entry, "size": sz})
                elif low.endswith((".br", ".new.dat", ".transfer.list")):
                    dat_br_files.append({"name": entry, "size": sz})
            elif os.path.isdir(full) and entry != "config" and not entry.startswith(".restore_") and entry not in seen_parts:
                unpacked_parts.append({"name": entry, "format": "erofs"})

        return {
            "username": USERS_DB.get(u_low, {}).get("username", u_low),
            "current_project": proj_name,
            "project_path": f"/sdcard/DNA/{proj_name}",
            "projects": projects,
            "img_files": img_files,
            "unpacked_parts": unpacked_parts,
            "zst_files": zst_files,
            "dat_br_files": dat_br_files,
            "logs": ustate["logs"][-80:]
        }

    @router.post("/unpack")
    def api_dna_unpack(
        mode: str = Form(...),
        files: str = Form(""),
        delete_source: bool = Form(False),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = _current_user(x_dna_token)
        selected = [x.strip() for x in files.split(",") if x.strip()]
        if not selected and mode not in ("super", "payload"):
            raise HTTPException(status_code=400, detail="Please select at least one file.")
        target = ",".join(selected) if selected else ("super.img" if mode == "super" else "payload.bin")
        tid = _dispatch_gh_worker(u_low, "unpack", target, {"mode": mode, "delete_source": delete_source}, f"Unpack ({mode}) {target}")
        return {"ok": True, "task_id": tid}

    @router.post("/pack_single")
    def api_dna_pack_single(req: PackSingleRequest, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        tid = _dispatch_gh_worker(u_low, "pack_single", req.partition, req.dict(), f"Pack {req.partition} ({req.pack_type})")
        return {"ok": True, "task_id": tid}

    @router.post("/pack_zstd")
    def api_dna_pack_zstd(filename: str = Form(...), level: int = Form(6), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        tid = _dispatch_gh_worker(u_low, "pack_zstd", filename, {"level": level}, f"Pack zstd {filename}")
        return {"ok": True, "task_id": tid}

    @router.post("/pack_super")
    def api_dna_pack_super(req: PackSuperRequest, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        tid = _dispatch_gh_worker(u_low, "pack_super", "super.img", req.dict(), "Build super.img")
        return {"ok": True, "task_id": tid}

    @router.post("/convert")
    def api_dna_convert(mode: str = Form(...), filename: str = Form(...), br_level: int = Form(3), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        tid = _dispatch_gh_worker(u_low, "convert", filename, {"mode": mode, "br_level": br_level}, f"Convert {filename} ({mode})")
        return {"ok": True, "task_id": tid}

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
        if "rooms/" in (repo_path + download_url) and f"rooms/{_uclean(u_low)}/" not in (repo_path + download_url):
            raise HTTPException(status_code=403, detail="That room belongs to another user.")
        u_root = get_user_root(u_low)
        proj_dir = get_proj_dir(u_low, project)
        safe_name = os.path.basename(target_name.strip())
        if dest_rel_dir.strip():
            target_folder = safe_join(u_root, dest_rel_dir.strip())
            os.makedirs(target_folder, exist_ok=True)
            out_p = safe_join(target_folder, safe_name)
        else:
            out_p = safe_join(proj_dir, safe_name)

        task_id = create_bg_task(f"Connecting to HF Vault for '{safe_name}'...")

        def _worker():
            t0 = time.time()
            try:
                url = download_url.strip() or hf_hub_url(repo_id=dataset_repo, filename=repo_path.strip(), repo_type="dataset")
                headers = {"User-Agent": "Mozilla/5.0"}
                if hf_token:
                    headers["Authorization"] = f"Bearer {hf_token}"
                with requests.get(url, headers=headers, stream=True, allow_redirects=True, timeout=60) as r:
                    r.raise_for_status()
                    total = int(r.headers.get("Content-Length", 0) or 0)
                    done = 0
                    with open(out_p + ".part", "wb") as f:
                        fl = Flusher(f)
                        for chunk in r.iter_content(chunk_size=1 * MB):
                            if not chunk:
                                continue
                            f.write(chunk)
                            fl.add(len(chunk))
                            done += len(chunk)
                            el = max(0.05, time.time() - t0)
                            spd = f"{(done / MB) / el:.1f} MB/s"
                            pct = min(99, int(done * 100 / total)) if total > 0 else min(95, int((done / MB) % 95))
                            set_bg_task(task_id, pct, f"Importing {safe_name}: {done / MB:.1f}" + (f" / {total / MB:.1f} MB ({spd})" if total else f" MB ({spd})"))
                if total > 0 and done < total:
                    raise Exception(f"Download incomplete ({done} of {total} bytes). Try again.")
                os.replace(out_p + ".part", out_p)
                free_ram()
                sz_mb = os.path.getsize(out_p) / MB
                BG_TASKS[task_id].update({"pct": 100, "label": f"Imported {safe_name} ({sz_mb:.2f} MB) ✓", "state": "done"})
                dna_log(u_low, "SUCCESS", f"Imported '{safe_name}' ({sz_mb:.2f} MB) from HF Vault!")
            except Exception as e:
                safe_remove(out_p + ".part")
                BG_TASKS[task_id].update({"state": "error", "error": str(e)})
                dna_log(u_low, "ERROR", f"Vault import failed for '{safe_name}': {e}")

        _spawn(_worker, task_id, heavy=False)
        return {"ok": True, "task_id": task_id}

    @router.get("/state")
    def api_dna_state(project: Optional[str] = None, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        if re.sub(r"[^a-zA-Z0-9_-]", "_", u_low.strip().lower()) not in USER_STATES:
            try:
                made = datetime.strptime(USERS_DB.get(u_low, {}).get("created_at", ""), "%Y-%m-%d %H:%M")
                if made < PROC_START:
                    dna_log(u_low, "WARN", f"Server restarted at {PROC_START.strftime('%H:%M:%S')} - temporary storage was wiped. Restoring your files from your private HF room now (see log).")
            except Exception:
                pass
        ustate = get_user_state(u_low)
        u_root = get_user_root(u_low)
        room_bootstrap(u_low)
        proj_dir = get_proj_dir(u_low, project)
        room_restore_async(u_low, proj_dir)
        projects = sorted([d for d in os.listdir(u_root) if os.path.isdir(os.path.join(u_root, d))])

        img_files, unpacked_parts, zst_files, dat_br_files = [], [], [], []
        for entry in sorted(os.listdir(proj_dir)):
            full = os.path.join(proj_dir, entry)
            if os.path.isfile(full):
                low = entry.lower()
                sz = f"{os.path.getsize(full) / MB:.2f} MB"
                if low.endswith((".img", ".bin", ".simg")):
                    img_files.append({"name": entry, "format": detect_img_type(full), "size": sz})
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
            room_delete(u_low, ustate["current_project"], whole=True)
            shutil.rmtree(p, ignore_errors=True)
            get_proj_dir(u_low, ustate["current_project"])
            dna_log(u_low, "PROJECT", f"Cleared project '/sdcard/DNA/{ustate['current_project']}'")
        elif action == "delete":
            target = name or ustate["current_project"]
            p = os.path.join(u_root, re.sub(r"[^a-zA-Z0-9._-]", "_", target))
            room_delete(u_low, re.sub(r"[^a-zA-Z0-9._-]", "_", target), whole=True)
            shutil.rmtree(p, ignore_errors=True)
            ustate["current_project"] = "Default_Project"
            get_proj_dir(u_low, "Default_Project")
            dna_log(u_low, "PROJECT", f"Deleted project '{target}'.")
        return api_dna_state(None, x_dna_token)

    @router.post("/push_vault")
    def api_push_to_vault(filename: str = Form(...), device_name: str = Form("DNA Ported Image"), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        if not hf_token:
            raise HTTPException(status_code=500, detail="Missing HF_TOKEN.")
        u_root = get_user_root(u_low)
        fp = safe_join(u_root, filename)
        if not os.path.isfile(fp):
            fp = safe_join(get_proj_dir(u_low), filename)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")

        ustate = get_user_state(u_low)
        base_fn = os.path.basename(fp)
        tid = create_bg_task(f"Uploading '{base_fn}' to Universal HF Vault...")

        def _worker():
            try:
                set_bg_task(tid, 35, f"Uploading '{base_fn}' ({os.path.getsize(fp)/MB:.1f} MB) to Hugging Face...")
                repo_path = f"dna_ported/{u_low}/{ustate['current_project']}/{base_fn}"
                hf_api.upload_file(path_or_fileobj=fp, path_in_repo=repo_path, repo_id=dataset_repo, repo_type="dataset")
                dl_url = hf_hub_url(repo_id=dataset_repo, filename=repo_path, repo_type="dataset")
                set_bg_task(tid, 85, "Updating Universal Vault index...")
                try:
                    from app import update_vault_index
                    sz_mb = os.path.getsize(fp) / MB
                    sha = sha256_file(fp)
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
                BG_TASKS[tid].update({"pct": 100, "label": f"Pushed '{base_fn}' to Universal Vault ✓", "state": "done"})
                dna_log(u_low, "SUCCESS", f"Pushed '{base_fn}' to Universal HF Vault → {dl_url}")
            except Exception as e:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})
                dna_log(u_low, "ERROR", f"Vault push failed: {e}")

        _spawn(_worker, tid, heavy=False)
        return {"ok": True, "task_id": tid}

    def _unpack_super_internal(u_low: str, proj_dir: str, super_filename: str, delete_source: bool = False, tid: str = None):
        from app import parse_lp, ExpandedReader, Stream, extract_from_super
        src_p = safe_join(proj_dir, super_filename)
        if not os.path.isfile(src_p):
            raise Exception(f"'{super_filename}' not found in project.")
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

        active_parts = [pname for pname, exts in parts.items() if sum(e[1] for e in exts) > 0 and not pname.endswith("_b")]
        tmp_id = "dna_super"
        jobs_dict[tmp_id] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
        for idx_p, pname in enumerate(active_parts, 1):
            clean_out = re.sub(r"_a$", "", pname) + ".img"
            if tid:
                set_bg_task(tid, int(10 + (idx_p / max(1, len(active_parts))) * 85), f"Unpacking '{clean_out}' ({idx_p}/{len(active_parts)}) from {super_filename}...")
            out_p = os.path.join(proj_dir, clean_out)
            tmp_p = out_p + ".part"
            safe_remove(tmp_p)
            try:
                with open(src_p, "rb") as fp:
                    extract_from_super(tmp_id, Stream(fp, seek_ok=True), pname, tmp_p, os.path.getsize(src_p), super_filename)
                if not os.path.exists(tmp_p) or os.path.getsize(tmp_p) == 0:
                    raise Exception(f"'{clean_out}' came out empty.")
                os.replace(tmp_p, out_p)
            except Exception:
                safe_remove(tmp_p)
                raise
            dna_log(u_low, "UNPACK", f"Extracted '{clean_out}' from {super_filename}")
            hf_autosave(u_low, proj_dir, clean_out)
            drop_cache(out_p)
            free_ram()

        jobs_dict.pop(tmp_id, None)
        del head, parts
        free_ram()
        if delete_source and os.path.exists(src_p):
            os.remove(src_p)

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
        if not selected and mode not in ("super", "payload"):
            raise HTTPException(status_code=400, detail="Please select at least one file.")

        tid = create_bg_task(f"Starting unpack ({mode})...")

        def _worker():
            try:
                if mode == "img":
                    for i, fn in enumerate(selected, 1):
                        set_bg_task(tid, int((i - 0.8) / len(selected) * 90), f"Unpacking {fn} ({i}/{len(selected)})...")
                        fmt = detect_img_type(safe_join(proj_dir, fn))
                        if fmt.startswith("super"):
                            _unpack_super_internal(u_low, proj_dir, fn, delete_source, tid)
                        else:
                            unpack_single_img_file(u_low, proj_dir, fn, delete_source, tid)
                        free_ram()
                elif mode == "super":
                    _unpack_super_internal(u_low, proj_dir, selected[0] if selected else "super.img", delete_source, tid)
                elif mode == "zstd":
                    for fn in selected:
                        set_bg_task(tid, 40, f"Decompressing zstd '{fn}'...")
                        src = safe_join(proj_dir, fn)
                        out_name = re.sub(r"\.zst$", "", fn, flags=re.I)
                        if out_name == fn:
                            out_name += ".img"
                        dst = safe_join(proj_dir, out_name)
                        with open(src, "rb") as fin, open(dst + ".part", "wb") as fout:
                            zstd.ZstdDecompressor().copy_stream(fin, fout, read_size=1 * MB, write_size=1 * MB)
                        os.replace(dst + ".part", dst)
                        free_ram()
                        if delete_source:
                            os.remove(src)
                        dna_log(u_low, "SUCCESS", f"Unpacked zstd '{fn}' → '{out_name}'")
                elif mode == "br":
                    for fn in selected:
                        set_bg_task(tid, 40, f"Decompressing brotli '{fn}'...")
                        src = safe_join(proj_dir, fn)
                        out_name = re.sub(r"\.br$", "", fn, flags=re.I)
                        dst = safe_join(proj_dir, out_name)
                        brotli_decompress_file(src, dst)
                        if delete_source:
                            os.remove(src)
                        dna_log(u_low, "SUCCESS", f"Unpacked brotli '{fn}' → '{out_name}'")
                elif mode == "dat":
                    for fn in selected:
                        set_bg_task(tid, 45, f"Converting '{fn}' to raw .img...")
                        dat_p = safe_join(proj_dir, fn)
                        prefix = re.sub(r"\.new\.dat$", "", fn, flags=re.I)
                        tl_p = safe_join(proj_dir, f"{prefix}.transfer.list")
                        if not os.path.exists(tl_p):
                            raise Exception(f"Missing {prefix}.transfer.list in project.")
                        sdat2img_convert(tl_p, dat_p, safe_join(proj_dir, f"{prefix}.img"))
                        dna_log(u_low, "SUCCESS", f"Converted '{fn}' → '{prefix}.img'")
                elif mode == "payload":
                    from app import extract_from_payload, Stream
                    target_pl = selected[0] if selected else "payload.bin"
                    pl_path = safe_join(proj_dir, target_pl)
                    parts_list = ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "system", "vendor", "product", "system_ext", "odm")
                    got = 0
                    tmp_id = "dna_pl"
                    for idx_p, p_to_ext in enumerate(parts_list, 1):
                        set_bg_task(tid, int(idx_p / len(parts_list) * 90), f"Scanning payload.bin for '{p_to_ext}'...")
                        out_p = os.path.join(proj_dir, f"{p_to_ext}.img")
                        tmp_p = out_p + ".part"
                        safe_remove(tmp_p)
                        try:
                            jobs_dict[tmp_id] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
                            with open(pl_path, "rb") as fp:
                                extract_from_payload(tmp_id, Stream(fp, seek_ok=True), p_to_ext, tmp_p)
                            if os.path.exists(tmp_p) and os.path.getsize(tmp_p) > 0:
                                os.replace(tmp_p, out_p)
                                got += 1
                                dna_log(u_low, "SUCCESS", f"Extracted '{p_to_ext}.img' from payload.bin")
                                hf_autosave(u_low, proj_dir, f"{p_to_ext}.img")
                            else:
                                safe_remove(tmp_p)
                                dna_log(u_low, "WARN", f"'{p_to_ext}' not present in payload.bin")
                        except Exception as e:
                            safe_remove(tmp_p)
                            dna_log(u_low, "WARN", f"'{p_to_ext}' skipped: {e}")
                        jobs_dict.pop(tmp_id, None)
                        free_ram()
                    if got == 0:
                        raise Exception("No partitions could be extracted from payload.bin (file corrupt or unsupported).")
                BG_TASKS[tid].update({"pct": 100, "label": f"Unpack ({mode}) complete ✓", "state": "done"})
            except Exception as e:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})
                dna_log(u_low, "ERROR", f"Unpack error: {e}")

        _spawn(_worker, tid, heavy=True)
        return {"ok": True, "task_id": tid}

    @router.post("/pack_single")
    def api_dna_pack_single(req: PackSingleRequest, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        tid = create_bg_task(f"Packing '{req.partition}' ({req.pack_type.upper()})...")

        def _worker():
            try:
                res = pack_single_partition_worker(u_low, req, tid)
                BG_TASKS[tid].update({"pct": 100, "label": f"Packed {res['output_file']} ({res['size_mb']}) ✓", "state": "done"})
            except Exception as e:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})
                dna_log(u_low, "ERROR", f"Pack error: {e}")

        _spawn(_worker, tid, heavy=True)
        return {"ok": True, "task_id": tid}

    @router.post("/pack_zstd")
    def api_dna_pack_zstd(filename: str = Form(...), level: int = Form(6), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        proj_dir = get_proj_dir(u_low)
        tid = create_bg_task(f"Compressing '{filename}' to .zst...")

        def _worker():
            try:
                src = safe_join(proj_dir, filename)
                dst = safe_join(proj_dir, f"{filename}.zst")
                set_bg_task(tid, 45, f"Compressing {filename} (level {level})...")
                with open(src, "rb") as fin, open(dst + ".part", "wb") as fout:
                    zstd.ZstdCompressor(level=max(1, min(19, int(level)))).copy_stream(fin, fout, read_size=1 * MB, write_size=1 * MB)
                os.replace(dst + ".part", dst)
                sz = os.path.getsize(dst) / MB
                BG_TASKS[tid].update({"pct": 100, "label": f"Packed {filename}.zst ({sz:.2f} MB) ✓", "state": "done"})
                dna_log(u_low, "SUCCESS", f"Packed '{filename}.zst' ({sz:.2f} MB)")
                hf_autosave(u_low, proj_dir, f"{filename}.zst")
            except Exception as e:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})

        _spawn(_worker, tid, heavy=True)
        return {"ok": True, "task_id": tid}

    @router.post("/pack_super")
    def api_dna_pack_super(req: PackSuperRequest, x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        tid = create_bg_task("Building super.img...")

        def _worker():
            try:
                res = build_super_image(u_low, req, tid)
                BG_TASKS[tid].update({"pct": 100, "label": f"Built super.img ({res['size_mb']}) ✓", "state": "done"})
            except Exception as e:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})
                dna_log(u_low, "ERROR", f"super.img build error: {e}")

        _spawn(_worker, tid, heavy=True)
        return {"ok": True, "task_id": tid}

    @router.post("/convert")
    def api_dna_convert(mode: str = Form(...), filename: str = Form(...), br_level: int = Form(3), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        proj_dir = get_proj_dir(u_low)
        src = safe_join(proj_dir, filename)
        if not os.path.isfile(src):
            raise HTTPException(status_code=404, detail="Source image not found.")
        stem = re.sub(r"\.(img|simg)$", "", filename, flags=re.I)
        tid = create_bg_task(f"Converting '{filename}' ({mode})...")

        def _worker():
            try:
                if mode == "img_to_simg":
                    if is_sparse_file(src):
                        out_name = f"{stem}_raw.img"
                        set_bg_task(tid, 45, f"Converting Sparse '{filename}' → Raw '{out_name}'...")
                        sparse_to_raw(src, safe_join(proj_dir, out_name))
                        dna_log(u_low, "SUCCESS", f"Converted Sparse '{filename}' → Raw '{out_name}'")
                    else:
                        out_name = f"{stem}_sparse.img"
                        set_bg_task(tid, 45, f"Converting Raw '{filename}' → Sparse '{out_name}'...")
                        raw_to_sparse(src, safe_join(proj_dir, out_name))
                        dna_log(u_low, "SUCCESS", f"Converted Raw '{filename}' → Android Sparse '{out_name}'")
                    BG_TASKS[tid].update({"pct": 100, "label": f"Created {out_name} ✓", "state": "done"})
                elif mode == "img_to_dat_br":
                    set_bg_task(tid, 35, f"Converting '{filename}' → '{stem}.new.dat'...")
                    dat_p, _tl_p = img2sdat_convert(src, proj_dir, stem)
                    br_p = f"{dat_p}.br"
                    lvl = max(0, min(11, int(br_level)))
                    set_bg_task(tid, 70, f"Compressing '{stem}.new.dat.br' (level {lvl})...")
                    brotli_compress_file(dat_p, br_p, lvl)
                    safe_remove(dat_p)
                    hf_autosave(u_low, proj_dir, f"{stem}.new.dat.br")
                    hf_autosave(u_low, proj_dir, f"{stem}.transfer.list")
                    dna_log(u_low, "SUCCESS", f"Converted '{filename}' → '{stem}.new.dat.br'")
                    BG_TASKS[tid].update({"pct": 100, "label": f"Created {stem}.new.dat.br ✓", "state": "done"})
            except Exception as e:
                BG_TASKS[tid].update({"state": "error", "error": str(e)})
                dna_log(u_low, "ERROR", f"Conversion failed: {e}")

        _spawn(_worker, tid, heavy=True)
        return {"ok": True, "task_id": tid}

    # ---------------- MT MANAGER DUAL-PANE ENDPOINTS ---------------- #

    def _load_fs_maps_for_dir(u_root: str, target_dir: str):
        rel = os.path.relpath(target_dir, u_root).replace("\\", "/")
        parts = [] if rel == "." else rel.split("/")
        fs_map, fc_map = {}, {}
        proj_dir, top_part = None, ""
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
                            fc_map[sp[0].lstrip("/").replace("\\", "")] = sp[1]
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
        items, dir_count, file_count = [], 0, 0

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
            rel_in_proj = os.path.relpath(full, proj_dir).replace("\\", "/") if proj_dir else ""
            default_mode = "0755" if is_dir else ("0600" if name == "build.prop" else "0644")
            meta = fs_map.get(rel_in_proj, {"uid": "0", "gid": "0", "mode": default_mode})
            ctx = fc_map.get(rel_in_proj, f"u:object_r:{top_part or 'system'}_file:s0")

            short_oct = format_short_octal(meta["mode"])
            sym_perm = mode_octal_to_symbolic(meta["mode"], is_dir=is_dir, is_link=is_link)
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
                "mtime": mtime_dt.strftime("%y-%m-%d %H:%M"),
                "mtime_full": mtime_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "mode": meta["mode"],
                "short_octal": short_oct,
                "sym_perm": sym_perm,
                "uid": meta["uid"],
                "gid": meta["gid"],
                "selinux": ctx
            })

        total_disk, _used, free_disk = shutil.disk_usage(u_root)
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
        fp = safe_join(get_user_root(u_low), path)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")
        md5_h, sha1_h, sha256_h, crc_v = hashlib.md5(), hashlib.sha1(), hashlib.sha256(), 0
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
        fp = safe_join(get_user_root(u_low), path)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")
        if os.path.getsize(fp) > 4 * MB:
            raise HTTPException(status_code=400, detail="File is larger than 4 MB (binary).")
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            return {"path": path, "content": f.read()}

    @router.post("/fs/write")
    def api_fs_write(path: str = Form(...), content: str = Form(...), x_dna_token: Optional[str] = Header(None)):
        u_low = _current_user(x_dna_token)
        fp = safe_join(get_user_root(u_low), path)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(content)
        dna_log(u_low, "MANAGER", f"Saved modified file '{path}'")
        room_note_change(u_low, get_user_root(u_low), path)
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
        was_dir = os.path.isdir(src_full) and not os.path.islink(src_full)

        if op == "copy":
            target = os.path.join(dst_full, os.path.basename(src_full)) if os.path.isdir(dst_full) else dst_full
            if os.path.abspath(src_full) == os.path.abspath(target):
                target += "_copy"
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

                norm_mode = "0" + mode.strip() if len(mode.strip()) == 3 else mode.strip()
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
                dna_log(u_low, "MANAGER", f"Unpacked archive '{src}'")
            else:
                raise HTTPException(status_code=400, detail="Not a valid ZIP/APEX/APK archive.")
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
        try:
            if op == "delete":
                room_note_change(u_low, u_root, src, "dir" if was_dir else "file")
            elif op in ("move", "rename"):
                room_note_change(u_low, u_root, src, "dir" if was_dir else "file")
                room_note_change(u_low, u_root, os.path.relpath(target if op == "move" else dst_full, u_root))
            elif op == "copy":
                room_note_change(u_low, u_root, os.path.relpath(target, u_root))
            elif op == "chmod_chcon":
                room_note_change(u_low, u_root, src)
                room_note_change(u_low, u_root, src.replace("\\", "/").split("/")[0] + "/config/x")
            else:
                room_note_change(u_low, u_root, src)
        except Exception:
            pass
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
        target_dir = get_proj_dir(u_low, project.strip()) if project.strip() else (safe_join(u_root, path) if path.strip() else get_proj_dir(u_low))
        os.makedirs(target_dir, exist_ok=True)
        out_p = safe_join(target_dir, os.path.basename(file.filename))
        try:
            with open(out_p + ".part", "wb") as f:
                fl = Flusher(f)
                while chunk := await file.read(1 * MB):
                    f.write(chunk)
                    fl.add(len(chunk))
            os.replace(out_p + ".part", out_p)
        finally:
            safe_remove(out_p + ".part")
            free_ram()
        sz_mb = os.path.getsize(out_p) / MB
        dna_log(u_low, "UPLOAD", f"Uploaded '{file.filename}' ({sz_mb:.2f} MB)")
        room_note_change(u_low, u_root, os.path.relpath(out_p, u_root))
        return {"ok": True, "filename": file.filename, "size_mb": f"{sz_mb:.2f} MB"}

    @router.get("/fs/download")
    def api_fs_download(path: str, token: str = ""):
        u_low = resolve_user_from_token(token)
        fp = safe_join(get_user_root(u_low), path)
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="File not found.")
        return FileResponse(fp, filename=os.path.basename(fp))

    @router.get("/tools")
    def api_dna_tools():
        names = ["mkfs.erofs", "fsck.erofs", "mke2fs", "e2fsck", "resize2fs", "debugfs", "mkfs.f2fs", "fsck.f2fs",
                 "sload.f2fs", "simg2img", "img2simg", "lpmake", "lpdump", "lpunpack", "brotli", "7z"]
        return {"tools": {n: bool(shutil.which(n)) for n in names}, "brotli_python": BROTLI_AVAILABLE,
                "auto_hf_save": AUTO_HF, "restore_imgs_on_start": RESTORE_IMGS, "base_dir": DNA_BASE_DIR,
                "server_started": PROC_START.strftime("%Y-%m-%d %H:%M:%S"),
                "uptime_s": int((datetime.now() - PROC_START).total_seconds()), "memory": mem_stats()}

    @router.post("/dispatch_worker")
    def api_dispatch_worker(
        target_file: str = Form(...),
        action: str = Form("unpack_img"),
        project: str = Form("Default_Project"),
        x_dna_token: Optional[str] = Header(None)
    ):
        u_low = resolve_user_from_token(x_dna_token)
        gh_token = os.environ.get("GH_DISPATCH_TOKEN")
        if not gh_token:
            raise HTTPException(status_code=500, detail="Missing GH_DISPATCH_TOKEN in Render environment.")

        url = "https://api.github.com/repos/really-yash/Fce-tools/actions/workflows/worker.yml/dispatches"
        headers = {
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {
            "ref": "main",
            "inputs": {
                "action": action,
                "project": project,
                "target_file": target_file
            }
        }
        
        res = requests.post(url, headers=headers, json=payload, timeout=15)
        if res.status_code != 204:
            raise HTTPException(
                status_code=500, 
                detail=f"GitHub dispatch failed ({res.status_code}): {res.text}"
            )

        dna_log(u_low, "WORKER", f"Dispatched 7GB RAM runner on GitHub for '{target_file}' ✓")
        return {
            "ok": True, 
            "message": f"Successfully launched heavy compute runner for {target_file}. Check your GitHub Actions tab!"
        }

    app.include_router(router)
    return inject_dna_ui(html_page)



# ---------------- UI INJECTOR (MT DUAL-PANE + AUTH + ADMIN + LIVE TASK HUD) ---------------- #

DNA_TAB_HTML = r"""
  <style>
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
    .mt-pane.active-pane { background: rgba(139, 92, 246, 0.07); }
    .mt-pane-left { border-right: 1.5px solid rgba(255,255,255,0.14); }
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
    <div id="tabDna" class="hidden space-y-3.5">

      <!-- AUTHENTICATION GATE -->
      <div id="dnaAuthCard" class="glass rounded-3xl p-5 space-y-4 border border-violet-500/40">
        <div class="flex items-center justify-between">
          <div>
            <span class="mono text-[10px] uppercase text-amber-300 font-bold block">🔒 Private ROM Porting Workspace</span>
            <h3 class="text-base font-bold text-white mt-0.5">Sign In or Create Account</h3>
          </div>
          <button type="button" onclick="openDnaModal('adminModal')" class="mono text-[10px] px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-300 border border-rose-400/30">🛡️ Admin</button>
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
            <button type="button" onclick="dnaAuthSubmit('login')" class="btn rip py-3 rounded-2xl font-bold text-xs text-slate-950 bg-gradient-to-r from-violet-400 to-amber-300">🔑 Sign In</button>
          </div>
        </div>
      </div>

      <!-- AUTHENTICATED WORKSPACE -->
      <div id="dnaMainWorkspace" class="hidden space-y-3.5">
        <div class="glass rounded-3xl p-3.5 space-y-3">
          <div class="flex items-center justify-between gap-2 px-1">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="mono text-[10px] uppercase text-emerald-300 font-bold" id="dnaUserBadge">@user</span>
                <button type="button" onclick="dnaLogout()" class="mono text-[10px] text-rose-300 underline">Sign Out</button>
                <button type="button" onclick="openDnaModal('adminModal')" class="mono text-[10px] text-amber-300 underline">🛡️ Admin</button>
              </div>
              <span id="dnaProjPathLabel" class="mono text-xs font-bold text-white truncate block">Current project: /sdcard/DNA/Default_Project</span>
            </div>
            <button type="button" onclick="openDnaModal('projectModal')" class="btn rip px-3 py-1.5 rounded-xl bg-violet-500/20 text-violet-300 border border-violet-400/30 mono text-[10px] font-bold shrink-0">
              📁 Project Menu
            </button>
          </div>

          <div class="grid grid-cols-2 gap-2 bg-black/40 p-1.5 rounded-2xl border border-white/10">
            <button type="button" id="subBtnDna" onclick="switchDnaSub('dna')" class="chip-btn active py-2.5 rounded-xl mono text-xs font-bold">🧬 DNA (Unpack / Pack)</button>
            <button type="button" id="subBtnManager" onclick="switchDnaSub('manager')" class="chip-btn py-2.5 rounded-xl mono text-xs font-bold text-slate-300">🗂️ Manager (Dual-Pane Root)</button>
          </div>
        </div>

        <!-- LIVE PROGRESS BAR HUD -->
        <div id="dnaTaskHud" class="hidden glass rounded-2xl p-3.5 space-y-2 border border-amber-400/40">
          <div class="flex items-center justify-between mono text-xs">
            <span id="dnaTaskLabel" class="text-amber-200 font-semibold truncate pr-2">Working...</span>
            <span id="dnaTaskPct" class="text-white font-bold">0%</span>
          </div>
          <div class="bar"><div id="dnaTaskBar" class="bar-fill c-amber" style="width:0%"></div></div>
        </div>

        <!-- SECTION A: 🧬 DNA -->
        <div id="dnaSubSection" class="space-y-4">
          <div class="glass rounded-3xl p-4 space-y-2.5">
            <div class="flex items-center justify-between">
              <span class="mono text-[10px] uppercase text-emerald-300 font-bold">⚡ Pull Partition / ROM Image from Vault into /sdcard/DNA</span>
              <button type="button" onclick="loadVaultIntoDnaPicker(true)" class="mono text-[10px] text-amber-300 underline">⟳ Sync Vault</button>
            </div>
            <div class="flex gap-2">
              <select id="dnaVaultPicker" class="cyber-input flex-1 px-3 py-2 rounded-xl text-xs mono text-white min-w-0">
                <option value="">Loading Vault files...</option>
              </select>
              <button type="button" onclick="importSelectedVaultImg('')" class="btn rip px-4 py-2 rounded-xl bg-emerald-500/25 border border-emerald-400/40 text-emerald-300 mono text-xs font-bold shrink-0">📥 Import</button>
            </div>
            <div class="flex items-center justify-between pt-1">
              <span class="mono text-[10px] text-slate-400">Or upload a local .img / .br / .dat / .zst file:</span>
              <label class="btn rip px-3 py-1 rounded-xl bg-violet-500/20 border border-violet-400/30 text-violet-200 mono text-[10px] font-bold cursor-pointer">
                ⬆ Upload File <input type="file" class="hidden" onchange="dnaDirectUpload(this)" />
              </label>
            </div>
          </div>

                    <!-- UNPACK MENU -->
          <div class="glass rounded-3xl p-5 space-y-3">
            <h3 class="text-sm font-bold text-violet-300 brand-font tracking-wide">Unpack Menu</h3>
            <div class="divide-y divide-white/10 mono text-xs">
              <button type="button" onclick="openUnpackModal('payload')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Unpack payload.bin</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openUnpackModal('br')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Unpack br</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openUnpackModal('dat')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Unpack dat</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openUnpackModal('img')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Unpack img</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openUnpackModal('zstd')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Unpack zstd</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openUnpackModal('super')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Unpack super</span><span class="text-slate-500">&gt;</span></button>
              
              <!-- ADD THIS NEW BUTTON HERE -->
              <button type="button" onclick="dispatchHeavyWorker()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition text-amber-300 font-bold">
                <span>⚡ Unpack with 7GB Cloud Worker (GitHub)</span>
                <span class="text-slate-500">&gt;</span>
              </button>
            </div>
          </div>

          <!-- PACK MENU -->
          <div class="glass rounded-3xl p-5 space-y-3">
            <h3 class="text-sm font-bold text-amber-300 brand-font tracking-wide">Pack Menu</h3>
            <div class="divide-y divide-white/10 mono text-xs">
              <button type="button" onclick="openPackSingleModal()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Pack a single partition</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openPackZstdModal()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Pack zstd</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openPackSuperModal()" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>Pack super.img</span><span class="text-slate-500">&gt;</span></button>
            </div>
          </div>

          <!-- FORMAT CONVERSION -->
          <div class="glass rounded-3xl p-5 space-y-3">
            <h3 class="text-sm font-bold text-emerald-300 brand-font tracking-wide">Format Conversion</h3>
            <div class="divide-y divide-white/10 mono text-xs">
              <button type="button" onclick="openConvertModal('img_to_simg')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>img to simg</span><span class="text-slate-500">&gt;</span></button>
              <button type="button" onclick="openConvertModal('img_to_dat_br')" class="w-full py-3 flex items-center justify-between text-left hover:text-amber-300 transition"><span>img to dat, br</span><span class="text-slate-500">&gt;</span></button>
            </div>
          </div>

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

        <!-- SECTION B: 🗂️ MANAGER (MT DUAL-PANE ROOT EXPLORER) -->
        <div id="managerSubSection" class="hidden space-y-3">
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

            <div class="flex items-center gap-1.5 pt-0.5">
              <select id="mgrVaultPicker" class="cyber-input flex-1 px-2.5 py-1.5 rounded-xl text-[10px] mono text-white min-w-0">
                <option value="">Import from HF Vault into active pane...</option>
              </select>
              <button type="button" onclick="importSelectedVaultImg('mgr')" class="btn rip px-2.5 py-1.5 rounded-xl bg-emerald-500/20 border border-emerald-400/30 text-emerald-300 mono text-[10px] font-bold shrink-0">📥 Pull Here</button>
            </div>

            <div class="text-[10px] mono text-slate-400 flex justify-between px-0.5">
              <span>Active Pane: <strong id="mgrActivePaneIndicator" class="text-amber-300">LEFT</strong></span>
              <span>Tap folder to open • Tap ••• for Properties/Editor</span>
            </div>
          </div>

          <div class="mt-dual-grid">
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

  <!-- ================= MODALS ================= -->

  <!-- ADMIN PANEL MODAL -->
  <div id="adminModal" class="hidden fixed inset-0 z-[90] bg-black/85 backdrop-filter backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
    <div class="glass rounded-3xl p-5 w-full max-w-md space-y-3 border border-rose-500/40 my-auto max-h-[90vh] overflow-y-auto">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-bold text-rose-300 mono">🛡️ Admin Control Panel (Users, IPs &amp; Bans)</h3>
        <button type="button" onclick="closeDnaModal('adminModal')" class="px-2.5 py-1 rounded-lg bg-white/10 text-xs mono">✕</button>
      </div>
      <div class="flex gap-2">
        <input id="adminPassInput" type="password" placeholder="Enter Admin Password" class="cyber-input flex-1 px-3 py-2 rounded-xl text-xs mono text-white" />
        <button type="button" onclick="loadAdminUsers()" class="btn rip px-4 py-2 rounded-xl bg-rose-500 text-white mono text-xs font-bold">Unlock</button>
      </div>
      <div id="adminUsersList" class="space-y-2 max-h-80 overflow-y-auto mono text-[10.5px]"></div>
    </div>
  </div>

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

  <!-- 3. PACK SINGLE MODAL -->
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
      <div class="grid grid-cols-2 gap-2.5 items-center">
        <label class="text-[11px] text-slate-300">Read/Write permission</label>
        <select id="psRwMode" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
          <option value="rw">Read/Write---rw</option>
          <option value="ro">Read Only---ro</option>
        </select>
      </div>
      <div class="grid grid-cols-2 gap-2.5 items-center">
        <label class="text-[11px] text-slate-300">Size</label>
        <select id="psSizeMode" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
          <option value="auto">Auto</option>
          <option value="orig">Original size</option>
        </select>
      </div>
      <div class="grid grid-cols-2 gap-2.5 items-center">
        <label class="text-[11px] text-slate-300">img format</label>
        <select id="psImgFormat" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
          <option value="raw">Raw</option>
          <option value="sparse">Sparse</option>
        </select>
      </div>
      <div class="grid grid-cols-2 gap-2.5 items-center">
        <label class="text-[11px] text-slate-300">File format</label>
        <select id="psFileFormat" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
          <option value="IMG">IMG</option>
          <option value="DAT">DAT</option>
          <option value="BR">BR</option>
        </select>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-[11px] text-slate-300">br compression</span>
        <div class="flex items-center gap-2">
          <button type="button" onclick="stepVal('psBrLevel', -1, 0, 11)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">-</button>
          <input id="psBrLevel" type="number" value="3" min="0" max="11" class="cyber-input w-12 text-center py-1 rounded-lg mono text-xs text-white" />
          <button type="button" onclick="stepVal('psBrLevel', 1, 0, 11)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">+</button>
        </div>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-[11px] text-slate-300">Erofs(f2fs) compression</span>
        <div class="flex items-center gap-2">
          <button type="button" onclick="stepVal('psErofsLevel', -1, 0, 12)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">-</button>
          <input id="psErofsLevel" type="number" value="8" min="0" max="12" class="cyber-input w-12 text-center py-1 rounded-lg mono text-xs text-white" />
          <button type="button" onclick="stepVal('psErofsLevel', 1, 0, 12)" class="chip-btn w-7 h-7 rounded-lg mono text-xs">+</button>
        </div>
      </div>
      <div class="grid grid-cols-2 gap-2.5 items-center">
        <label class="text-[11px] text-slate-300">Type</label>
        <select id="psErofsAlgo" class="cyber-input px-3 py-1.5 rounded-xl text-xs mono text-white">
          <option value="lz4hc">lz4hc</option>
          <option value="lz4">lz4</option>
          <option value="lzma">lzma</option>
          <option value="deflate">deflate</option>
        </select>
      </div>
      <label class="flex items-center justify-between text-xs text-slate-200 bg-black/40 p-2.5 rounded-xl border border-white/5">
        <span>Compress ext4 img space</span>
        <input id="psCompressExt4" type="checkbox" class="w-4 h-4 accent-violet-500" />
      </label>
      <label class="flex items-center justify-between text-xs text-slate-200 bg-black/40 p-2.5 rounded-xl border border-white/5">
        <span>Remove avb data encryption</span>
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
      <div class="grid grid-cols-2 gap-2 items-center">
        <label class="text-xs text-slate-300">Total super.img (GB)</label>
        <input id="superTotalGb" type="number" step="0.1" value="8.5" class="cyber-input px-3 py-2 rounded-xl text-xs mono text-white" />
      </div>
      <div class="grid grid-cols-2 gap-2 items-center">
        <label class="text-xs text-slate-300">Partition group</label>
        <select id="superGroup" class="cyber-input px-3 py-2 rounded-xl text-xs mono text-white">
          <option value="qti_dynamic_partitions">qti_dynamic_partitions</option>
          <option value="mtk_dynamic_partitions">mtk_dynamic_partitions</option>
        </select>
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

      <div class="bg-black/35 p-3 rounded-xl space-y-1 mono text-[11px] border border-white/10">
        <div><span class="text-slate-400">Size: </span><span id="mgrPropSize" class="text-slate-100">0 B</span></div>
        <div><span class="text-slate-400">Modified: </span><span id="mgrPropMtime" class="text-slate-100">—</span></div>
        <div><span class="text-slate-400">Permission: </span><span id="mgrPropPerm" class="text-amber-300 font-bold">rwxr-xr-x (755)</span></div>
        <div class="flex gap-1.5 flex-wrap pt-1">
          <button type="button" onclick="mgrCalcChecksum()" class="mt-btn-gray">CHECKSUM</button>
          <button type="button" onclick="mgrRenameItem()" class="mt-btn-gray">RENAME</button>
                    <button type="button" onclick="mgrDeleteItem()" class="mt-btn-gray text-rose-300">DELETE</button>
          <a id="mgrBtnDownload" href="#" target="_blank" class="mt-btn-gray text-emerald-300">DOWNLOAD</a>
          <button type="button" id="mgrBtnVault" onclick="mgrPushVault()" class="mt-btn-gray text-sky-300">PUSH VAULT</button>
        </div>
        <div class="flex gap-1.5 pt-1">
          <button type="button" id="mgrBtnMount" onclick="mgrMountArchive()" class="hidden mt-btn-gray text-violet-300">UNPACK APEX/APK/ZIP</button>
          <button type="button" id="mgrBtnRepack" onclick="mgrRepackArchive()" class="hidden mt-btn-gray text-amber-300">REPACK ARCHIVE</button>
        </div>
      </div>

      <!-- Checksum Results Box -->
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

    async function dispatchHeavyWorker() {
  const file = prompt("Enter the exact partition filename in your project to unpack (e.g., system_ext.img):");
  if (!file) return;

  showTaskProgress("Dispatching 7GB GitHub worker for " + file + "...", 15);
  const fd = new FormData();
  fd.append("target_file", file.trim());
  fd.append("action", "unpack_img");
  fd.append("project", dnaState.current_project || "Default_Project");

  try {
    const res = await fetch("/api/dna/dispatch_worker", {
      method: "POST",
      headers: dnaHeaders(),
      body: fd
    });
    const data = await res.json();
    hideTaskProgress();
    if (!res.ok) throw new Error(data.detail || "Dispatch failed");
    toast(data.message, "ok");
    refreshDnaState();
  } catch (e) {
    hideTaskProgress();
    toast(e.message, "bad");
  }
}


    /* ---------- AUTH & ADMIN ---------- */
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

    async function loadAdminUsers() {
      const pw = document.getElementById("adminPassInput").value.trim();
      const box = document.getElementById("adminUsersList");
      if (!pw) return toast("Enter Admin Password", "warn");
      const fd = new FormData();
      fd.append("admin_pass", pw);
      try {
        const res = await fetch("/api/dna/admin/list", { method: "POST", body: fd });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Unauthorized");
        const users = data.users || [];
        if (!users.length) {
          box.innerHTML = `<div class="text-slate-400 py-3 text-center">No registered users yet.</div>`;
          return;
        }
        box.innerHTML = users.map(u => `
          <div class="p-3 rounded-2xl bg-black/50 border border-white/10 space-y-1.5">
            <div class="flex items-center justify-between">
              <span class="font-bold text-white">@${esc(u.username)} ${u.banned ? '<span class="text-rose-400">[BANNED]</span>' : ''}</span>
              <span class="text-[9px] text-slate-400">${esc(u.created_at)}</span>
            </div>
            <div class="text-[10px] text-slate-300">Pass: <span class="text-amber-300">${esc(u.password)}</span> • IP: <span class="text-sky-300">${esc(u.ip)}</span></div>
            <div class="text-[9.5px] text-violet-300 truncate">Projects: ${esc((u.projects || []).join(", ") || "None")}</div>
            <div class="flex gap-1.5 pt-1">
              <button type="button" onclick="adminUserAction('${esc(u.u_low)}', '${u.banned ? 'unban' : 'ban'}')" class="px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 text-[10px] font-bold">${u.banned ? 'Unban' : 'Ban User'}</button>
              <button type="button" onclick="adminUserAction('${esc(u.u_low)}', 'delete')" class="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 text-[10px] font-bold">Delete</button>
            </div>
          </div>
        `).join("");
      } catch (e) {
        toast(e.message, "bad");
      }
    }

    async function adminUserAction(targetUser, action) {
      const pw = document.getElementById("adminPassInput").value.trim();
      const fd = new FormData();
      fd.append("admin_pass", pw);
      fd.append("action", action);
      fd.append("target_user", targetUser);
      const res = await fetch("/api/dna/admin/action", { method: "POST", body: fd });
      if (res.ok) {
        toast("Admin action '" + action + "' applied ✓", "ok");
        loadAdminUsers();
      } else {
        toast("Action failed", "bad");
      }
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

    /* ---------- PROGRESS BAR HUD FOR ALL BACKGROUND TASKS ---------- */
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
      if (!taskId) return;
      while (true) {
        try {
          const res = await fetch("/api/dna/task/" + taskId, { cache: "no-store" });
          if (!res.ok) break;
          const t = await res.json();
          showTaskProgress(t.label || "Working...", t.pct || 0);
          if (t.state === "done") {
            toast(t.label || "Completed ✓", "ok");
            hideTaskProgress();
            refreshDnaState();
            loadPane("L");
            loadPane("R");
            break;
          }
          if (t.state === "error") {
            toast(t.error || "Task failed", "bad");
            hideTaskProgress();
            refreshDnaState();
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
      showTaskProgress("Unpacking " + chks.join(", ") + "...", 5);
      const fd = new FormData();
      fd.append("mode", currentUnpackMode);
      fd.append("files", chks.join(","));
      fd.append("delete_source", del ? "true" : "false");
      try {
        const res = await fetch("/api/dna/unpack", { method: "POST", headers: dnaHeaders(), body: fd });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Unpack failed");
        await pollDnaTask(data.task_id);
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
      showTaskProgress("Packing " + part + "...", 5);
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
        if (!res.ok) throw new Error(data.detail || "Pack failed");
        await pollDnaTask(data.task_id);
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
      showTaskProgress("Building super.img...", 5);
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
        if (!res.ok) throw new Error(data.detail || "super.img build failed");
        await pollDnaTask(data.task_id);
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
      showTaskProgress("Compressing " + fn + " to .zst...", 10);
      const fd = new FormData();
      fd.append("filename", fn);
      fd.append("level", document.getElementById("zstdLevelInput").value || "6");
      const res = await fetch("/api/dna/pack_zstd", { method: "POST", headers: dnaHeaders(), body: fd });
      const data = await res.json();
      if (res.ok) await pollDnaTask(data.task_id);
      else { hideTaskProgress(); toast(data.detail || "Zstd pack failed", "bad"); }
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
      showTaskProgress("Converting " + fn + "...", 10);
      const fd = new FormData();
      fd.append("mode", currentConvertMode);
      fd.append("filename", fn);
      fd.append("br_level", document.getElementById("convBrLevel").value || "3");
      const res = await fetch("/api/dna/convert", { method: "POST", headers: dnaHeaders(), body: fd });
      const data = await res.json();
      if (res.ok) await pollDnaTask(data.task_id);
      else { hideTaskProgress(); toast(data.detail || "Conversion failed", "bad"); }
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
      closeDnaModal("mgrItemModal");
      showTaskProgress("Uploading " + mgrModalTarget.name + " to Universal HF Vault...", 10);
      const fd = new FormData();
      fd.append("filename", mgrModalTarget.rel_path);
      const res = await fetch("/api/dna/push_vault", { method: "POST", headers: dnaHeaders(), body: fd });
      const data = await res.json();
      if (res.ok) {
        await pollDnaTask(data.task_id);
      } else {
        hideTaskProgress();
        toast(data.detail || "Vault upload failed", "bad");
      }
    }
  </script>
"""

def inject_dna_ui(html_page: str) -> str:
    html_page = html_page.replace(
        "  <!-- GLASS DOCK + TELEGRAM CIRCLE BUTTON -->",
        DNA_TAB_HTML + "\n  <!-- GLASS DOCK + TELEGRAM CIRCLE BUTTON -->",
        1
    )
    old_console_btn = '<button id="btnTerminal" onclick="switchView(\'terminal\')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">💻 Console</button>'
    new_buttons = (
        old_console_btn + "\n        "
        '<button id="btnDna" onclick="switchView(\'dna\')" class="dock-btn flex-1 py-2.5 rounded-[20px] text-xs text-slate-300">🧬 DNA</button>'
    )
    html_page = html_page.replace(old_console_btn, new_buttons, 1)

    html_page = html_page.replace('["Studio", "Vault", "Terminal"]', '["Studio", "Vault", "Terminal", "Dna"]')
    html_page = html_page.replace('["studio", "vault", "terminal"]', '["studio", "vault", "terminal", "dna"]')
    html_page = html_page.replace(
        'if (view === "vault") loadVault(false);',
        'if (view === "vault") loadVault(false);\n      if (view === "dna") { refreshDnaState(); loadPane("L"); loadPane("R"); }'
    )
    return html_page

