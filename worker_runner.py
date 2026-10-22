import os
import json
import shutil
import tarfile
import zstandard as zstd
from huggingface_hub import HfApi, hf_hub_download

api = HfApi(token=os.environ["HF_TOKEN"])
repo = os.environ["DATASET_REPO"]
action = os.environ.get("TASK_ACTION", "unpack_img")
project = os.environ.get("TASK_PROJECT", "Default_Project")
target_file = os.environ.get("TASK_FILE", "")
options = os.environ.get("TASK_OPTIONS", "{}")

WORK_DIR = f"/tmp/worker/{project}"
os.makedirs(f"{WORK_DIR}/config", exist_ok=True)

# 1. Pull target image from Hugging Face Vault/Room
print(f"[*] Downloading {target_file} from Hugging Face...")
local_img = safe_target = os.path.join(WORK_DIR, target_file)

try:
    downloaded = hf_hub_download(
        repo_id=repo,
        filename=f"rooms/guest/{project}/files/{target_file}",
        repo_type="dataset",
        token=os.environ["HF_TOKEN"],
        local_dir=WORK_DIR
    )
except Exception:
    # Fallback to direct vault root if not in room
    downloaded = hf_hub_download(
        repo_id=repo,
        filename=target_file,
        repo_type="dataset",
        token=os.environ["HF_TOKEN"],
        local_dir=WORK_DIR
    )

if os.path.exists(downloaded) and downloaded != local_img:
    shutil.move(downloaded, local_img)

# 2. Execute unpack via dna_manager functions
import dna_manager

print(f"[*] Executing {action} on {target_file} with 7GB RAM runner...")
if action == "unpack_img":
    res = dna_manager.unpack_single_img_file("guest", WORK_DIR, target_file, delete_source=False)
    part_name = res["partition"]
    
    # Compress unpacked tree into tar.zst and upload
    archive_path = f"/tmp/{part_name}.tar.zst"
    with open(archive_path, "wb") as fh:
        with zstd.ZstdCompressor(level=3).stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                tf.add(os.path.join(WORK_DIR, part_name), arcname=part_name)

    print(f"[*] Uploading extracted tree {part_name}.tar.zst to Hugging Face...")
    api.upload_file(
        path_or_fileobj=archive_path,
        path_in_repo=f"rooms/guest/{project}/trees/{part_name}.tar.zst",
        repo_id=repo,
        repo_type="dataset"
    )

    # Sync config folder metadata
    cfg_archive = "/tmp/config.tar.zst"
    with open(cfg_archive, "wb") as fh:
        with zstd.ZstdCompressor(level=3).stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                tf.add(os.path.join(WORK_DIR, "config"), arcname="config")
    api.upload_file(
        path_or_fileobj=cfg_archive,
        path_in_repo=f"rooms/guest/{project}/trees/config.tar.zst",
        repo_id=repo,
        repo_type="dataset"
    )

print("[✓] Task complete. Artifacts saved to Hugging Face.")
