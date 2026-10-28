import os, re, sys, json, base64, shutil, tarfile, tempfile, traceback, subprocess, requests
from datetime import datetime
from urllib.parse import urlparse
import zstandard as zstd
from huggingface_hub import HfApi, hf_hub_download, hf_hub_url

os.environ["DNA_AUTO_HF"] = "0"
import dna_manager

ACTION = os.environ.get("TASK_ACTION", "").strip()
USER = re.sub(r"[^a-zA-Z0-9_-]", "_", os.environ.get("TASK_USER", "guest").strip().lower()) or "guest"
PROJECT = os.environ.get("TASK_PROJECT", "Default_Project").strip()
TARGET_FILE = os.environ.get("TASK_FILE", "").strip()
OPTIONS = json.loads(os.environ.get("TASK_OPTIONS", "{}") or "{}")
DELETE_SOURCE = bool(OPTIONS.get("delete_source", False))

_hf_b64 = str(OPTIONS.pop("hf_b64", "")).strip()
_fallback_tok = base64.b64decode(_hf_b64).decode("utf-8", "ignore").strip() if _hf_b64 else ""
HF_TOKEN = (os.environ.get("HF_TOKEN", "").strip() or _fallback_tok)
REPO = (os.environ.get("DATASET_REPO", "").strip() or str(OPTIONS.pop("dataset_repo", "")).strip())
OPTIONS.pop("dataset_repo", None)

if not HF_TOKEN or not REPO:
    sys.exit("[✗] Missing HF_TOKEN or DATASET_REPO.")

api = HfApi(token=HF_TOKEN)
PROJ_DIR = dna_manager.get_proj_dir(USER, PROJECT)
CONFIG_DIR = os.path.join(PROJ_DIR, "config")
os.makedirs(CONFIG_DIR, exist_ok=True)
SCRATCH = tempfile.mkdtemp(prefix="gh_scratch_")
TEXT_EXTS = (".prop", ".rc", ".xml", ".conf", ".cfg", ".sh", ".json", ".txt", ".default", ".fstab", ".ini", ".mk", ".cil", ".te")

def room(kind, name):
    return f"rooms/{USER}/{PROJECT}/{kind}/{name}"

def pull_config_from_hf():
    try:
        dl = hf_hub_download(repo_id=REPO, filename=room("trees", "config.tar.zst"), repo_type="dataset", token=HF_TOKEN, local_dir=SCRATCH, force_download=True)
        with open(dl, "rb") as fh:
            with zstd.ZstdDecompressor().stream_reader(fh) as zr:
                with tarfile.open(fileobj=zr, mode="r|") as tf:
                    for m in tf:
                        if m.name.startswith("/") or ".." in m.name.split("/"):
                            continue
                        if m.isdir():
                            m.mode |= 0o700
                        tf.extract(m, PROJ_DIR)
        os.remove(dl)
    except Exception:
        pass

def _read_room_meta():
    mp = os.path.join(CONFIG_DIR, "_room_meta.json")
    if os.path.exists(mp):
        try:
            with open(mp, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"files": {}, "trees": {}, "deleted_root": []}

def _write_room_meta(data):
    with open(os.path.join(CONFIG_DIR, "_room_meta.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def update_room_meta(fname: str, filepath: str, fmt_override: str = None):
    data = _read_room_meta()
    if os.path.isfile(filepath):
        data.setdefault("files", {})[fname] = {
            "size": os.path.getsize(filepath),
            "format": fmt_override or dna_manager.detect_img_type(filepath),
            "mtime": datetime.now().strftime("%y-%m-%d %H:%M"),
            "mtime_full": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    if fname in data.get("deleted_root", []):
        data["deleted_root"].remove(fname)
    _write_room_meta(data)

def remove_from_room_meta(fname: str, is_tree: bool = False):
    data = _read_room_meta()
    data.get("trees" if is_tree else "files", {}).pop(fname, None)
    if fname not in data.setdefault("deleted_root", []):
        data["deleted_root"].append(fname)
    _write_room_meta(data)

def build_partition_manifest(part_name: str, part_dir: str, detected_fmt: str):
    manifest = []
    texts_base = os.path.join(CONFIG_DIR, "_texts", part_name)
    shutil.rmtree(texts_base, ignore_errors=True)
    os.makedirs(texts_base, exist_ok=True)
    now_s = datetime.now().strftime("%y-%m-%d %H:%M")
    now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for root, dirs, files in os.walk(part_dir):
        rel_root = os.path.relpath(root, part_dir).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        for d in sorted(dirs):
            full_d = os.path.join(root, d)
            rel_p = f"{rel_root}/{d}" if rel_root else d
            is_lnk = os.path.islink(full_d)
            manifest.append({
                "rel": rel_p, "name": d, "parent": rel_root,
                "is_dir": not is_lnk, "is_link": is_lnk,
                "link_target": os.readlink(full_d) if is_lnk else "",
                "size": 0, "mtime": now_s, "mtime_full": now_full
            })
        for fn in sorted(files):
            full_f = os.path.join(root, fn)
            rel_p = f"{rel_root}/{fn}" if rel_root else fn
            is_lnk = os.path.islink(full_f)
            sz = 0 if is_lnk else (os.path.getsize(full_f) if os.path.exists(full_f) else 0)
            manifest.append({
                "rel": rel_p, "name": fn, "parent": rel_root,
                "is_dir": False, "is_link": is_lnk,
                "link_target": os.readlink(full_f) if is_lnk else "",
                "size": sz, "mtime": now_s, "mtime_full": now_full
            })
            low = fn.lower()
            if not is_lnk and sz <= 256 * 1024 and (low.endswith(TEXT_EXTS) or "fstab" in low or "build.prop" in low):
                dst_t = os.path.join(texts_base, rel_p)
                os.makedirs(os.path.dirname(dst_t), exist_ok=True)
                try:
                    shutil.copy2(full_f, dst_t)
                except Exception:
                    pass

    with open(os.path.join(CONFIG_DIR, f"{part_name}_manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"partition": part_name, "format": detected_fmt, "mtime": now_s, "items": manifest}, f)

    ops_path = os.path.join(CONFIG_DIR, f"{part_name}_ops.json")
    if os.path.exists(ops_path):
        os.remove(ops_path)

    data = _read_room_meta()
    data.setdefault("trees", {})[part_name] = {"format": detected_fmt, "mtime": now_s, "mtime_full": now_full, "count": len(manifest)}
    if part_name in data.get("deleted_root", []):
        data["deleted_root"].remove(part_name)
    _write_room_meta(data)

def apply_overlay_and_ops(part_name: str):
    part_dir = os.path.join(PROJ_DIR, part_name)
    texts_base = os.path.join(CONFIG_DIR, "_texts", part_name)
    if os.path.isdir(texts_base):
        for r, _ds, fs in os.walk(texts_base):
            for fn in fs:
                src_f = os.path.join(r, fn)
                rel = os.path.relpath(src_f, texts_base)
                dst_f = os.path.join(part_dir, rel)
                os.makedirs(os.path.dirname(dst_f), exist_ok=True)
                shutil.copy2(src_f, dst_f)

    ops_path = os.path.join(CONFIG_DIR, f"{part_name}_ops.json")
    if os.path.exists(ops_path):
        try:
            ops = json.load(open(ops_path, "r", encoding="utf-8"))
            for op in ops.get("history", []):
                kind, src_rel, dst_rel = op.get("op"), op.get("src", ""), op.get("dst", "")
                s_full = os.path.join(PROJ_DIR, src_rel) if src_rel else ""
                d_full = os.path.join(PROJ_DIR, dst_rel) if dst_rel else ""
                if kind == "delete" and s_full:
                    shutil.rmtree(s_full, ignore_errors=True) if (os.path.isdir(s_full) and not os.path.islink(s_full)) else (os.remove(s_full) if os.path.lexists(s_full) else None)
                elif kind == "mkdir" and s_full:
                    os.makedirs(s_full, exist_ok=True)
                elif kind in ("rename", "move") and s_full and d_full and os.path.lexists(s_full):
                    os.makedirs(os.path.dirname(d_full), exist_ok=True)
                    shutil.move(s_full, d_full)
                elif kind == "copy" and s_full and d_full and os.path.lexists(s_full):
                    os.makedirs(os.path.dirname(d_full), exist_ok=True)
                    shutil.copytree(s_full, d_full, symlinks=True, dirs_exist_ok=True) if (os.path.isdir(s_full) and not os.path.islink(s_full)) else shutil.copy2(s_full, d_full, follow_symlinks=False)
                elif kind == "symlink" and s_full and dst_rel:
                    os.makedirs(os.path.dirname(s_full), exist_ok=True)
                    if os.path.lexists(s_full):
                        os.remove(s_full)
                    os.symlink(dst_rel, s_full)
        except Exception as e:
            print(f"[!] Warning applying ops: {e}")

def pull_file_from_hf(fname: str) -> str:
    local_p = os.path.join(PROJ_DIR, fname)
    if os.path.exists(local_p):
        return local_p
    os.makedirs(os.path.dirname(local_p), exist_ok=True)
    meta_info = _read_room_meta().get("files", {}).get(fname, {})
    cand_paths = []
    if meta_info.get("repo_path"):
        cand_paths.append(meta_info["repo_path"])
    cand_paths.extend([room("files", fname), fname])
    for repo_path in cand_paths:
        try:
            dl = hf_hub_download(repo_id=REPO, filename=repo_path, repo_type="dataset", token=HF_TOKEN, local_dir=SCRATCH)
            shutil.move(dl, local_p)
            return local_p
        except Exception:
            continue
    dl_url = meta_info.get("download_url", "").strip()
    if dl_url:
        headers = {"User-Agent": "Mozilla/5.0"}
        if (urlparse(dl_url).hostname or "").endswith("huggingface.co"):
            headers["Authorization"] = f"Bearer {HF_TOKEN}"
        with requests.get(dl_url, headers=headers, stream=True, allow_redirects=True, timeout=120) as r:
            r.raise_for_status()
            with open(local_p + ".part", "wb") as f:
                for chunk in r.iter_content(chunk_size=8 * 1024 * 1024):
                    if chunk:
                        f.write(chunk)
        os.replace(local_p + ".part", local_p)
        return local_p
    raise Exception(f"Could not find '{fname}' in your HF room or Vault.")

def pull_tree_from_hf(part_name: str):
    pull_config_from_hf()
    dl = hf_hub_download(repo_id=REPO, filename=room("trees", f"{part_name}.tar.zst"), repo_type="dataset", token=HF_TOKEN, local_dir=SCRATCH)
    with open(dl, "rb") as fh:
        with zstd.ZstdDecompressor().stream_reader(fh) as zr:
            with tarfile.open(fileobj=zr, mode="r|") as tf:
                for m in tf:
                    if m.name.startswith("/") or ".." in m.name.split("/"):
                        continue
                    if m.isdir():
                        m.mode |= 0o700
                    tf.extract(m, PROJ_DIR)
    os.remove(dl)
    apply_overlay_and_ops(part_name)

def push_file_to_hf(fname: str, remove_after: bool = False):
    fp = os.path.join(PROJ_DIR, fname)
    if not os.path.isfile(fp):
        return
    update_room_meta(fname, fp)
    api.upload_file(path_or_fileobj=fp, path_in_repo=room("files", fname), repo_id=REPO, repo_type="dataset", commit_message=f"worker {USER}/{PROJECT}: {fname}")
    if remove_after:
        os.remove(fp)

def push_tree_to_hf(top: str):
    src = os.path.join(PROJ_DIR, top)
    if not os.path.isdir(src):
        return
    arc = os.path.join(SCRATCH, f"{top}.tar.zst")
    with open(arc, "wb") as fh:
        with zstd.ZstdCompressor(level=3).stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                tf.add(src, arcname=top)
    api.upload_file(path_or_fileobj=arc, path_in_repo=room("trees", f"{top}.tar.zst"), repo_id=REPO, repo_type="dataset", commit_message=f"worker {USER}/{PROJECT}: {top}/")
    os.remove(arc)

def delete_from_room(fname: str):
    try:
        remove_from_room_meta(fname, is_tree=False)
        api.delete_file(path_in_repo=room("files", fname), repo_id=REPO, repo_type="dataset")
    except Exception:
        pass

def robust_unpack_img(fn: str) -> dict:
    src_path = os.path.join(PROJ_DIR, fn)
    try:
        res = dna_manager.unpack_single_img_file(USER, PROJ_DIR, fn, delete_source=False)
    except Exception as first_err:
        part_name = re.sub(r"_(a|b)$", "", re.sub(r"\.(img|bin|simg)$", "", os.path.basename(fn), flags=re.I))
        out_dir = os.path.join(PROJ_DIR, part_name)
        os.makedirs(out_dir, exist_ok=True)
        need_unsparse = dna_manager.is_sparse_file(src_path)
        raw_img = src_path + ".raw_loop" if need_unsparse else src_path
        if need_unsparse:
            dna_manager.sparse_to_raw(src_path, raw_img)
        fmt = dna_manager.detect_img_type(raw_img)
        mnt_dir = tempfile.mkdtemp(prefix="loop_mnt_")
        try:
            if fmt == "erofs" and shutil.which("fsck.erofs"):
                subprocess.run(["fsck.erofs", f"--extract={out_dir}", raw_img], check=False)
            if not os.listdir(out_dir):
                subprocess.run(["sudo", "mount", "-o", "loop,ro", raw_img, mnt_dir], check=True)
                subprocess.run(["sudo", "cp", "-a", mnt_dir + "/.", out_dir + "/"], check=True)
                subprocess.run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", out_dir], check=True)
        finally:
            subprocess.run(["sudo", "umount", "-l", mnt_dir], check=False)
            shutil.rmtree(mnt_dir, ignore_errors=True)
            if need_unsparse and os.path.exists(raw_img):
                os.remove(raw_img)
        if not os.listdir(out_dir):
            raise first_err
        clean_fmt = fmt if fmt in ("erofs", "ext4", "f2fs") else "erofs"
        dna_manager.generate_fs_metadata(part_name, out_dir, CONFIG_DIR, detected_fmt=clean_fmt)
        with open(os.path.join(CONFIG_DIR, f"{part_name}_info.json"), "w", encoding="utf-8") as f:
            json.dump({"part_name": part_name, "detected_format": clean_fmt, "orig_size": os.path.getsize(src_path)}, f, indent=2)
        res = {"partition": part_name, "format": clean_fmt}

    build_partition_manifest(res["partition"], os.path.join(PROJ_DIR, res["partition"]), res.get("format", "erofs"))
    return res

def unpack_super(fn: str):
    from app import parse_lp, ExpandedReader, Stream, extract_from_super, JOBS
    src_p = pull_file_from_hf(fn)
    with open(src_p, "rb") as fp:
        reader = ExpandedReader(Stream(fp, seek_ok=True), os.path.getsize(src_p))
        head = bytearray(dna_manager.HEAD_BYTES)
        for off, d in reader.pieces():
            if off < dna_manager.HEAD_BYTES:
                n = min(len(d), dna_manager.HEAD_BYTES - off)
                head[off:off + n] = d[:n]
            if off + len(d) >= dna_manager.HEAD_BYTES:
                break
        parts = parse_lp(bytes(head))
    active = [p for p, exts in parts.items() if sum(e[1] for e in exts) > 0 and not p.endswith("_b")]
    for pname in active:
        clean_out = re.sub(r"_a$", "", pname) + ".img"
        out_p = os.path.join(PROJ_DIR, clean_out)
        tmp_p = out_p + ".part"
        JOBS["gh_super"] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
        with open(src_p, "rb") as fp:
            extract_from_super("gh_super", Stream(fp, seek_ok=True), pname, tmp_p, os.path.getsize(src_p), fn)
        os.replace(tmp_p, out_p)
        push_file_to_hf(clean_out, remove_after=True)
        JOBS.pop("gh_super", None)
    if DELETE_SOURCE:
        delete_from_room(fn)

def unpack_payload(fn: str):
    from app import extract_from_payload, Stream, JOBS
    pl_path = pull_file_from_hf(fn)
    got = 0
    for p in ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "system", "vendor", "product", "system_ext", "odm", "vendor_dlkm", "odm_dlkm", "mi_ext"):
        out_p = os.path.join(PROJ_DIR, f"{p}.img")
        tmp_p = out_p + ".part"
        try:
            JOBS["gh_pl"] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
            with open(pl_path, "rb") as fp:
                extract_from_payload("gh_pl", Stream(fp, seek_ok=True), p, tmp_p)
            if os.path.exists(tmp_p) and os.path.getsize(tmp_p) > 0:
                os.replace(tmp_p, out_p)
                push_file_to_hf(f"{p}.img", remove_after=True)
                got += 1
        except Exception:
            pass
        finally:
            JOBS.pop("gh_pl", None)
            if os.path.exists(tmp_p):
                os.remove(tmp_p)
    if got == 0:
        raise Exception("No partitions extracted from payload.bin.")
    if DELETE_SOURCE:
        delete_from_room(fn)

def main():
    pull_config_from_hf()
    if ACTION == "import_vault":
        dl_url = OPTIONS.get("download_url", "").strip()
        repo_path = OPTIONS.get("repo_path", "").strip()
        url = dl_url or hf_hub_url(repo_id=REPO, filename=repo_path, repo_type="dataset")
        name = os.path.basename(TARGET_FILE)
        out_p = os.path.join(PROJ_DIR, name)
        headers = {"User-Agent": "Mozilla/5.0"}
        if (urlparse(url).hostname or "").endswith("huggingface.co"):
            headers["Authorization"] = f"Bearer {HF_TOKEN}"
        with requests.get(url, headers=headers, stream=True, allow_redirects=True, timeout=120) as r:
            r.raise_for_status()
            with open(out_p + ".part", "wb") as f:
                for chunk in r.iter_content(chunk_size=8 * 1024 * 1024):
                    if chunk:
                        f.write(chunk)
        os.replace(out_p + ".part", out_p)
        push_file_to_hf(name, remove_after=True)
        push_tree_to_hf("config")

    elif ACTION == "unpack":
        mode = OPTIONS.get("mode", "img")
        files = [x.strip() for x in TARGET_FILE.split(",") if x.strip()]
        if mode == "super":
            for fn in (files or ["super.img"]):
                unpack_super(fn)
        elif mode == "payload":
            for fn in (files or ["payload.bin"]):
                unpack_payload(fn)
        else:
            for fn in files:
                src = pull_file_from_hf(fn)
                det = dna_manager.detect_img_type(src)
                if mode == "img" and det.startswith("super"):
                    unpack_super(fn)
                elif mode == "img" and (det == "payload" or fn.lower() == "payload.bin"):
                    unpack_payload(fn)
                elif mode == "img":
                    res = robust_unpack_img(fn)
                    push_tree_to_hf(res["partition"])
                    shutil.rmtree(os.path.join(PROJ_DIR, res["partition"]), ignore_errors=True)
                    if os.path.exists(src):
                        os.remove(src)
                    if DELETE_SOURCE:
                        delete_from_room(fn)
                elif mode == "zstd":
                    out_name = re.sub(r"\.zst$", "", fn, flags=re.I)
                    if out_name == fn:
                        out_name += ".img"
                    dst = os.path.join(PROJ_DIR, out_name)
                    with open(src, "rb") as fin, open(dst + ".part", "wb") as fout:
                        zstd.ZstdDecompressor().copy_stream(fin, fout)
                    os.replace(dst + ".part", dst)
                    push_file_to_hf(out_name, remove_after=True)
                    if DELETE_SOURCE:
                        delete_from_room(fn)
                elif mode == "br":
                    out_name = re.sub(r"\.br$", "", fn, flags=re.I)
                    dna_manager.brotli_decompress_file(src, os.path.join(PROJ_DIR, out_name))
                    push_file_to_hf(out_name, remove_after=True)
                    if DELETE_SOURCE:
                        delete_from_room(fn)
                elif mode == "dat":
                    prefix = re.sub(r"\.new\.dat$", "", fn, flags=re.I)
                    tl = pull_file_from_hf(f"{prefix}.transfer.list")
                    dna_manager.sdat2img_convert(tl, src, os.path.join(PROJ_DIR, f"{prefix}.img"))
                    push_file_to_hf(f"{prefix}.img", remove_after=True)
                    if DELETE_SOURCE:
                        delete_from_room(fn)
        push_tree_to_hf("config")

    elif ACTION == "pack_single":
        pull_tree_from_hf(TARGET_FILE)
        req = dna_manager.PackSingleRequest(**OPTIONS)
        res = dna_manager.pack_single_partition_worker(USER, req)
        push_file_to_hf(res["output_file"], remove_after=True)
        if os.path.exists(os.path.join(PROJ_DIR, f"{TARGET_FILE}.transfer.list")):
            push_file_to_hf(f"{TARGET_FILE}.transfer.list", remove_after=True)
        push_tree_to_hf("config")

    elif ACTION == "pack_zstd":
        src = pull_file_from_hf(TARGET_FILE)
        lvl = max(1, min(19, int(OPTIONS.get("level", 6))))
        out_name = f"{TARGET_FILE}.zst"
        dst = os.path.join(PROJ_DIR, out_name)
        with open(src, "rb") as fin, open(dst + ".part", "wb") as fout:
            zstd.ZstdCompressor(level=lvl).copy_stream(fin, fout)
        os.replace(dst + ".part", dst)
        push_file_to_hf(out_name, remove_after=True)
        push_tree_to_hf("config")

    elif ACTION == "pack_super":
        req = dna_manager.PackSuperRequest(**OPTIONS)
        for img in req.selected_imgs:
            pull_file_from_hf(img)
        res = dna_manager.build_super_image(USER, req)
        push_file_to_hf(res["output_file"], remove_after=True)
        push_tree_to_hf("config")

    elif ACTION == "convert":
        src = pull_file_from_hf(TARGET_FILE)
        mode = OPTIONS.get("mode", "img_to_simg")
        br_level = int(OPTIONS.get("br_level", 3))
        stem = re.sub(r"\.(img|simg)$", "", TARGET_FILE, flags=re.I)
        if mode == "img_to_simg":
            out_name = f"{stem}_raw.img" if dna_manager.is_sparse_file(src) else f"{stem}_sparse.img"
            (dna_manager.sparse_to_raw if dna_manager.is_sparse_file(src) else dna_manager.raw_to_sparse)(src, os.path.join(PROJ_DIR, out_name))
            push_file_to_hf(out_name, remove_after=True)
        elif mode == "img_to_dat_br":
            dat_p, _tl = dna_manager.img2sdat_convert(src, PROJ_DIR, stem)
            br_p = f"{dat_p}.br"
            dna_manager.brotli_compress_file(dat_p, br_p, br_level)
            os.remove(dat_p)
            push_file_to_hf(f"{stem}.new.dat.br", remove_after=True)
            push_file_to_hf(f"{stem}.transfer.list", remove_after=True)
        push_tree_to_hf("config")

    elif ACTION == "studio_extract":
        # Studio download+extract of a big partition: runs here (7 GB RAM) instead of on the 512 MB Render server
        os.environ["DATASET_REPO"] = REPO
        os.environ["HF_TOKEN"] = HF_TOKEN
        job_id = OPTIONS["job_id"]
        import app as flux
        flux.DATASET_REPO, flux.HF_TOKEN = REPO, HF_TOKEN
        flux.hf_api = HfApi(token=HF_TOKEN)
        flux.JOBS[job_id] = flux.make_job(OPTIONS["target"])
        try:
            flux.run_extraction_worker(job_id, OPTIONS["rom_url"], OPTIONS["target"], OPTIONS["user_meta"])
        finally:
            _j = flux.JOBS[job_id]
            _out = {"state": _j.get("state"), "result": _j.get("result"), "error": _j.get("error"), "logs": _j.get("logs", [])[-80:]}
            _p = os.path.join(SCRATCH, f"{job_id}.json")
            with open(_p, "w", encoding="utf-8") as _f:
                json.dump(_out, _f)
            api.upload_file(path_or_fileobj=_p, path_in_repo=f"studio_jobs/{job_id}.json", repo_id=REPO, repo_type="dataset",
                            commit_message=f"studio job {job_id}")
        if flux.JOBS[job_id].get("state") != "done":
            raise Exception(flux.JOBS[job_id].get("error") or "Studio extraction failed")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
    finally:
        shutil.rmtree(SCRATCH, ignore_errors=True)
