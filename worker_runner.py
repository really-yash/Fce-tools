import os
import re
import sys
import json
import shutil
import tarfile
import tempfile
import traceback
import requests
from urllib.parse import urlparse
import zstandard as zstd
from huggingface_hub import HfApi, hf_hub_download, hf_hub_url

os.environ["DNA_AUTO_HF"] = "0"  # this worker uploads to HF itself
import dna_manager

ACTION = os.environ.get("TASK_ACTION", "").strip()
USER = re.sub(r"[^a-zA-Z0-9_-]", "_", os.environ.get("TASK_USER", "guest").strip().lower()) or "guest"
PROJECT = os.environ.get("TASK_PROJECT", "Default_Project").strip()
TARGET_FILE = os.environ.get("TASK_FILE", "").strip()
OPTIONS = json.loads(os.environ.get("TASK_OPTIONS", "{}") or "{}")
DELETE_SOURCE = bool(OPTIONS.get("delete_source", False))

HF_TOKEN = os.environ.get("HF_TOKEN", "").strip()
REPO = (os.environ.get("DATASET_REPO", "").strip() or str(OPTIONS.pop("dataset_repo", "")).strip())
OPTIONS.pop("dataset_repo", None)
if not HF_TOKEN:
    sys.exit("[✗] GitHub secret HF_TOKEN is EMPTY. Add it in the repo: Settings > Secrets and variables > Actions > New repository secret (name: HF_TOKEN, value: your Hugging Face WRITE token).")
if not REPO:
    sys.exit("[✗] Dataset repo is unknown. Add secret DATASET_REPO (e.g. Yash10101/xiaomi-firmware-cache) or set DATASET_REPO on Render.")

api = HfApi(token=HF_TOKEN)
PROJ_DIR = dna_manager.get_proj_dir(USER, PROJECT)
SCRATCH = tempfile.mkdtemp(prefix="gh_scratch_")


def room(kind, name):
    return f"rooms/{USER}/{PROJECT}/{kind}/{name}"


def pull_file_from_hf(fname: str) -> str:
    local_p = os.path.join(PROJ_DIR, fname)
    if os.path.exists(local_p):
        return local_p
    os.makedirs(os.path.dirname(local_p), exist_ok=True)
    for repo_path in [room("files", fname), fname]:
        try:
            dl = hf_hub_download(repo_id=REPO, filename=repo_path, repo_type="dataset", token=HF_TOKEN, local_dir=SCRATCH)
        except Exception:
            continue
        shutil.move(dl, local_p)
        return local_p
    raise Exception(f"Could not find '{fname}' in your HF room or the Vault. Upload/import it first.")


def pull_tree_from_hf(part_name: str):
    for t in ["config", part_name]:
        try:
            dl = hf_hub_download(repo_id=REPO, filename=room("trees", f"{t}.tar.zst"), repo_type="dataset", token=HF_TOKEN, local_dir=SCRATCH)
        except Exception as e:
            if t == part_name:
                raise Exception(f"Unpacked folder '{part_name}' is not in your HF room. Unpack it first. ({e})")
            continue
        print(f"[*] Restoring '{t}/' from HF room...")
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


def push_file_to_hf(fname: str, remove_after: bool = False):
    fp = os.path.join(PROJ_DIR, fname)
    if not os.path.isfile(fp):
        return
    print(f"[*] Uploading '{fname}' to HF room...")
    api.upload_file(path_or_fileobj=fp, path_in_repo=room("files", fname), repo_id=REPO, repo_type="dataset",
                    commit_message=f"worker {USER}/{PROJECT}: {fname}")
    if remove_after:
        os.remove(fp)


def push_tree_to_hf(top: str):
    src = os.path.join(PROJ_DIR, top)
    if not os.path.isdir(src):
        return
    arc = os.path.join(SCRATCH, f"{top}.tar.zst")
    print(f"[*] Compressing & uploading folder '{top}/' to HF room...")
    with open(arc, "wb") as fh:
        with zstd.ZstdCompressor(level=3).stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                tf.add(src, arcname=top)
    api.upload_file(path_or_fileobj=arc, path_in_repo=room("trees", f"{top}.tar.zst"), repo_id=REPO, repo_type="dataset",
                    commit_message=f"worker {USER}/{PROJECT}: {top}/")
    os.remove(arc)


def delete_from_room(fname: str):
    try:
        api.delete_file(path_in_repo=room("files", fname), repo_id=REPO, repo_type="dataset")
        print(f"[*] Removed source '{fname}' from HF room.")
    except Exception:
        pass


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
    if not active:
        raise Exception(f"No partitions found inside '{fn}' (not a valid super image?).")
    tmp_id = "gh_super"
    got = 0
    for i, pname in enumerate(active, 1):
        clean_out = re.sub(r"_a$", "", pname) + ".img"
        out_p = os.path.join(PROJ_DIR, clean_out)
        tmp_p = out_p + ".part"
        print(f"[*] ({i}/{len(active)}) Extracting '{clean_out}' from {fn}...")
        JOBS[tmp_id] = {"cancel": False, "logs": [], "search_progress": 0, "cont_progress": 0, "ext_progress": 0, "fin_progress": 0, "chunks_verified": 0}
        with open(src_p, "rb") as fp:
            extract_from_super(tmp_id, Stream(fp, seek_ok=True), pname, tmp_p, os.path.getsize(src_p), fn)
        if not os.path.exists(tmp_p) or os.path.getsize(tmp_p) == 0:
            raise Exception(f"'{clean_out}' came out empty.")
        os.replace(tmp_p, out_p)
        push_file_to_hf(clean_out, remove_after=True)
        JOBS.pop(tmp_id, None)
        got += 1
    if DELETE_SOURCE:
        delete_from_room(fn)
    print(f"[✓] Extracted {got} partitions from {fn}")


def unpack_payload(fn: str):
    from app import extract_from_payload, Stream, JOBS
    pl_path = pull_file_from_hf(fn)
    got = 0
    for p in ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "system", "vendor", "product", "system_ext", "odm"):
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
                print(f"[✓] {p}.img")
            else:
                print(f"[-] '{p}' not in payload.bin")
        except Exception as e:
            print(f"[-] '{p}' skipped: {e}")
        finally:
            JOBS.pop("gh_pl", None)
            if os.path.exists(tmp_p):
                os.remove(tmp_p)
    if got == 0:
        raise Exception("No partitions could be extracted from payload.bin.")
    if DELETE_SOURCE:
        delete_from_room(fn)


def main():
    print(f"[*] GitHub Worker: action={ACTION} user={USER} project={PROJECT} target={TARGET_FILE}")

    if ACTION == "import_vault":
        dl_url = OPTIONS.get("download_url", "").strip()
        repo_path = OPTIONS.get("repo_path", "").strip()
        if "rooms/" in (dl_url + repo_path) and f"rooms/{USER}/" not in (dl_url + repo_path):
            raise Exception("That room belongs to another user.")
        url = dl_url or hf_hub_url(repo_id=REPO, filename=repo_path, repo_type="dataset")
        name = os.path.basename(TARGET_FILE)
        out_p = os.path.join(PROJ_DIR, name)
        headers = {"User-Agent": "Mozilla/5.0"}
        if (urlparse(url).hostname or "").endswith("huggingface.co"):
            headers["Authorization"] = f"Bearer {HF_TOKEN}"   # never send the HF token to other sites
        with requests.get(url, headers=headers, stream=True, allow_redirects=True, timeout=120) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            with open(out_p + ".part", "wb") as f:
                for chunk in r.iter_content(chunk_size=4 * 1024 * 1024):
                    if chunk:
                        f.write(chunk)
                        done += len(chunk)
        if total and done < total:
            raise Exception(f"Download incomplete ({done} of {total} bytes).")
        os.replace(out_p + ".part", out_p)
        push_file_to_hf(name, remove_after=True)

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
                if mode == "img":
                    res = dna_manager.unpack_single_img_file(USER, PROJ_DIR, fn, delete_source=False)
                    push_tree_to_hf(res["partition"])
                    push_tree_to_hf("config")
                    shutil.rmtree(os.path.join(PROJ_DIR, res["partition"]), ignore_errors=True)
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
                else:
                    raise Exception(f"Unknown unpack mode '{mode}'.")

    elif ACTION == "pack_single":
        pull_tree_from_hf(TARGET_FILE)
        req = dna_manager.PackSingleRequest(**OPTIONS)
        res = dna_manager.pack_single_partition_worker(USER, req)
        push_file_to_hf(res["output_file"], remove_after=True)
        if os.path.exists(os.path.join(PROJ_DIR, f"{TARGET_FILE}.transfer.list")):
            push_file_to_hf(f"{TARGET_FILE}.transfer.list")
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

    elif ACTION == "pack_super":
        req = dna_manager.PackSuperRequest(**OPTIONS)
        for img in req.selected_imgs:
            pull_file_from_hf(img)
        res = dna_manager.build_super_image(USER, req)
        push_file_to_hf(res["output_file"], remove_after=True)

    elif ACTION == "convert":
        src = pull_file_from_hf(TARGET_FILE)
        mode = OPTIONS.get("mode", "img_to_simg")
        br_level = int(OPTIONS.get("br_level", 3))
        stem = re.sub(r"\.(img|simg)$", "", TARGET_FILE, flags=re.I)
        if mode == "img_to_simg":
            if dna_manager.is_sparse_file(src):
                out_name = f"{stem}_raw.img"
                dna_manager.sparse_to_raw(src, os.path.join(PROJ_DIR, out_name))
            else:
                out_name = f"{stem}_sparse.img"
                dna_manager.raw_to_sparse(src, os.path.join(PROJ_DIR, out_name))
            push_file_to_hf(out_name, remove_after=True)
        elif mode == "img_to_dat_br":
            dat_p, _tl = dna_manager.img2sdat_convert(src, PROJ_DIR, stem)
            br_p = f"{dat_p}.br"
            dna_manager.brotli_compress_file(dat_p, br_p, br_level)
            os.remove(dat_p)
            push_file_to_hf(f"{stem}.new.dat.br", remove_after=True)
            push_file_to_hf(f"{stem}.transfer.list", remove_after=True)
        else:
            raise Exception(f"Unknown convert mode '{mode}'.")
    else:
        raise Exception(f"Unknown action '{ACTION}'.")

    print("[✓] GitHub 7GB Worker completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        print(f"[✗] FAILED: {e}")
        sys.exit(1)
    finally:
        shutil.rmtree(SCRATCH, ignore_errors=True)
