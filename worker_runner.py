import os
import re
import json
import shutil
import tarfile
import requests
import zstandard as zstd
from huggingface_hub import HfApi, hf_hub_download, hf_hub_url

os.environ["DNA_AUTO_HF"] = "0"  # Worker handles uploads directly
import dna_manager

HF_TOKEN = os.environ["HF_TOKEN"].strip()
REPO = os.environ["DATASET_REPO"].strip()
ACTION = os.environ.get("TASK_ACTION", "").strip()
USER = re.sub(r"[^a-zA-Z0-9_-]", "_", os.environ.get("TASK_USER", "guest").strip().lower()) or "guest"
PROJECT = os.environ.get("TASK_PROJECT", "Default_Project").strip()
TARGET_FILE = os.environ.get("TASK_FILE", "").strip()
OPTIONS = json.loads(os.environ.get("TASK_OPTIONS", "{}") or "{}")

api = HfApi(token=HF_TOKEN)
PROJ_DIR = dna_manager.get_proj_dir(USER, PROJECT)

def pull_file_from_hf(fname: str) -> str:
    local_p = os.path.join(PROJ_DIR, fname)
    if os.path.exists(local_p):
        return local_p
    os.makedirs(os.path.dirname(local_p), exist_ok=True)
    for repo_path in [f"rooms/{USER}/{PROJECT}/files/{fname}", fname]:
        try:
            dl = hf_hub_download(repo_id=REPO, filename=repo_path, repo_type="dataset", token=HF_TOKEN)
            shutil.copy2(dl, local_p)
            return local_p
        except Exception:
            pass
    raise Exception(f"Could not find '{fname}' in your Hugging Face Room or Vault.")

def pull_tree_from_hf(part_name: str):
    for t in ["config", part_name]:
        try:
            dl = hf_hub_download(
                repo_id=REPO,
                filename=f"rooms/{USER}/{PROJECT}/trees/{t}.tar.zst",
                repo_type="dataset",
                token=HF_TOKEN
            )
            with open(dl, "rb") as fh:
                with zstd.ZstdDecompressor().stream_reader(fh) as zr:
                    with tarfile.open(fileobj=zr, mode="r|") as tf:
                        tf.extractall(PROJ_DIR)
        except Exception as e:
            if t == part_name:
                raise Exception(f"Could not pull unpacked folder '{part_name}' from HF: {e}")

def push_file_to_hf(fname: str):
    fp = os.path.join(PROJ_DIR, fname)
    if os.path.isfile(fp):
        print(f"[*] Uploading file '{fname}' to HF room...")
        api.upload_file(
            path_or_fileobj=fp,
            path_in_repo=f"rooms/{USER}/{PROJECT}/files/{fname}",
            repo_id=REPO,
            repo_type="dataset"
        )

def push_tree_to_hf(top: str):
    src = os.path.join(PROJ_DIR, top)
    if not os.path.isdir(src):
        return
    tmp_arc = f"/tmp/{top}.tar.zst"
    print(f"[*] Compressing & uploading folder '{top}/' to HF room...")
    with open(tmp_arc, "wb") as fh:
        with zstd.ZstdCompressor(level=3).stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                tf.add(src, arcname=top)
    api.upload_file(
        path_or_fileobj=tmp_arc,
        path_in_repo=f"rooms/{USER}/{PROJECT}/trees/{top}.tar.zst",
        repo_id=REPO,
        repo_type="dataset"
    )
    os.remove(tmp_arc)

print(f"[*] Starting GitHub Worker: action={ACTION} | user={USER} | project={PROJECT} | target={TARGET_FILE}")

if ACTION == "import_vault":
    dl_url = OPTIONS.get("download_url", "").strip()
    repo_path = OPTIONS.get("repo_path", "").strip()
    url = dl_url or hf_hub_url(repo_id=REPO, filename=repo_path, repo_type="dataset")
    out_p = os.path.join(PROJ_DIR, os.path.basename(TARGET_FILE))
    headers = {"User-Agent": "Mozilla/5.0", "Authorization": f"Bearer {HF_TOKEN}"}
    with requests.get(url, headers=headers, stream=True, allow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with open(out_p, "wb") as f:
            for chunk in r.iter_content(chunk_size=4 * 1024 * 1024):
                if chunk:
                    f.write(chunk)
    push_file_to_hf(os.path.basename(TARGET_FILE))

elif ACTION == "unpack":
    mode = OPTIONS.get("mode", "img")
    files = [x.strip() for x in TARGET_FILE.split(",") if x.strip()]
    for fn in files:
        pull_file_from_hf(fn)
        if mode == "img":
            res = dna_manager.unpack_single_img_file(USER, PROJ_DIR, fn, delete_source=False)
            push_tree_to_hf(res["partition"])
            push_tree_to_hf("config")
        elif mode == "zstd":
            src = os.path.join(PROJ_DIR, fn)
            out_name = re.sub(r"\.zst$", "", fn, flags=re.I)
            if out_name == fn:
                out_name += ".img"
            dst = os.path.join(PROJ_DIR, out_name)
            with open(src, "rb") as fin, open(dst, "wb") as fout:
                zstd.ZstdDecompressor().copy_stream(fin, fout)
            push_file_to_hf(out_name)
        elif mode == "br":
            src = os.path.join(PROJ_DIR, fn)
            out_name = re.sub(r"\.br$", "", fn, flags=re.I)
            dna_manager.brotli_decompress_file(src, os.path.join(PROJ_DIR, out_name))
            push_file_to_hf(out_name)
        elif mode == "dat":
            prefix = re.sub(r"\.new\.dat$", "", fn, flags=re.I)
            pull_file_from_hf(f"{prefix}.transfer.list")
            dna_manager.sdat2img_convert(
                os.path.join(PROJ_DIR, f"{prefix}.transfer.list"),
                os.path.join(PROJ_DIR, fn),
                os.path.join(PROJ_DIR, f"{prefix}.img")
            )
            push_file_to_hf(f"{prefix}.img")

elif ACTION == "pack_single":
    pull_tree_from_hf(TARGET_FILE)
    req = dna_manager.PackSingleRequest(**OPTIONS)
    res = dna_manager.pack_single_partition_worker(USER, req)
    push_file_to_hf(res["output_file"])
    push_tree_to_hf("config")

elif ACTION == "pack_zstd":
    pull_file_from_hf(TARGET_FILE)
    lvl = int(OPTIONS.get("level", 6))
    src = os.path.join(PROJ_DIR, TARGET_FILE)
    out_name = f"{TARGET_FILE}.zst"
    with open(src, "rb") as fin, open(os.path.join(PROJ_DIR, out_name), "wb") as fout:
        zstd.ZstdCompressor(level=max(1, min(19, lvl))).copy_stream(fin, fout)
    push_file_to_hf(out_name)

elif ACTION == "pack_super":
    req = dna_manager.PackSuperRequest(**OPTIONS)
    for img in req.selected_imgs:
        pull_file_from_hf(img)
    res = dna_manager.build_super_image(USER, req)
    push_file_to_hf(res["output_file"])

elif ACTION == "convert":
    pull_file_from_hf(TARGET_FILE)
    mode = OPTIONS.get("mode", "img_to_simg")
    br_level = int(OPTIONS.get("br_level", 3))
    src = os.path.join(PROJ_DIR, TARGET_FILE)
    stem = re.sub(r"\.(img|simg)$", "", TARGET_FILE, flags=re.I)
    if mode == "img_to_simg":
        if dna_manager.is_sparse_file(src):
            out_name = f"{stem}_raw.img"
            dna_manager.sparse_to_raw(src, os.path.join(PROJ_DIR, out_name))
        else:
            out_name = f"{stem}_sparse.img"
            dna_manager.raw_to_sparse(src, os.path.join(PROJ_DIR, out_name))
        push_file_to_hf(out_name)
    elif mode == "img_to_dat_br":
        dat_p, tl_p = dna_manager.img2sdat_convert(src, PROJ_DIR, stem)
        br_p = f"{dat_p}.br"
        dna_manager.brotli_compress_file(dat_p, br_p, br_level)
        push_file_to_hf(f"{stem}.new.dat.br")
        push_file_to_hf(f"{stem}.transfer.list")

print("[✓] GitHub 7GB Worker completed successfully!")
