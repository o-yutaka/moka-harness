#!/usr/bin/env python3
"""Qwen-Image-2.1 (uncensored, Q4_K_M GGUF) on Modal — permanent replacement
for the Colab deployment. Same code as the Colab notebook: AndreRese/NewGwen2.1
pinned at eb1c934, ComfyUI + leejet GGUF loader via setup_colab.sh, models from
the hl091 mirror into a persistent Modal Volume.

Deploy:  modal deploy modal_app.py
Models:  modal run modal_app.py::download_models   (once, ~14.6 GB)
URL:     https://<workspace>--qwen-image-21-serve.modal.run  (fixed)
"""
import subprocess
from pathlib import Path

import modal

APP_NAME = "qwen-image-21"
REPO_URL = "https://github.com/AndreRese/NewGwen2.1"
PINNED_COMMIT = "eb1c9342dd8fb689e088b5f27897983193c2f1fe"
MIRROR = "hl091/Qwen-Image-2.1-Uncensored-Quantized"
WORK = "/opt/qwen21"
MODELS_ROOT = "/models"

# (hf path, dest relative to ComfyUI/models, min bytes)
MODEL_FILES = [
    ("qwen-image-2.1-UC-Q4_K_M.gguf",
     "diffusion_models/qwen-image-2.1-UC-Q4_K_M.gguf", 4_000_000_000),
    ("text_encoders/qwen3vl_8b_int8_convrot.safetensors",
     "text_encoders/qwen3vl_8b_int8_convrot.safetensors", 8_500_000_000),
    ("vae/qwen_image_2.1_vae_bf16.safetensors",
     "vae/qwen_image_2.1_vae_bf16.safetensors", 500_000_000),
    ("qwen-image-2.1-uncensored-lora.safetensors",
     "loras/qwen-image-2.1-uncensored-lora.safetensors", 30_000_000),
]

app = modal.App(APP_NAME)
volume = modal.Volume.from_name("qwen-models", create_if_missing=True)

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git", "curl", "build-essential")
    .run_commands(
        f"git clone {REPO_URL} {WORK}",
        f"cd {WORK} && git checkout -q {PINNED_COMMIT}",
        # setup_colab.sh: clones pinned ComfyUI + leejet GGUF node, pip-installs
        # ComfyUI requirements (pulls CUDA torch), GGUF reqs, colab reqs (gradio).
        # Its apt step is best-effort by design; the trailing torch check prints
        # gpu NONE at build time, which is fine.
        f"cd {WORK} && bash setup_colab.sh",
        # Gradio binds 127.0.0.1 upstream; Modal's web proxy needs 0.0.0.0.
        f"sed -i 's/server_name=\"127.0.0.1\"/server_name=\"0.0.0.0\"/' {WORK}/app_gradio.py",
        f"grep -n 'server_name' {WORK}/app_gradio.py",
    )
)


@app.function(image=image, volumes={MODELS_ROOT: volume}, timeout=60 * 60)
def download_models():
    """Fetch the 4 model files from the HF mirror into the volume (idempotent)."""
    from huggingface_hub import hf_hub_download

    for hf_path, dest_rel, min_bytes in MODEL_FILES:
        dest = Path(MODELS_ROOT) / dest_rel
        if dest.exists() and dest.stat().st_size > min_bytes:
            print(f"SKIP ok: {dest_rel} {dest.stat().st_size/1e9:.2f} GB")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        got = hf_hub_download(MIRROR, hf_path, local_dir="/tmp/hf_dl")
        subprocess.run(["cp", got, str(dest)], check=True)
        size = dest.stat().st_size
        assert size > min_bytes, f"TOO SMALL ({size} B): {dest_rel}"
        print(f"OK: {dest_rel} {size/1e9:.2f} GB")
        volume.commit()
    print("MODELS DONE")


def _link_models():
    """Symlink the volume's model tree into ComfyUI's models dir."""
    import os

    for _, dest_rel, _ in MODEL_FILES:
        src = Path(MODELS_ROOT) / dest_rel
        dst = Path(WORK) / "ComfyUI" / "models" / dest_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.is_symlink() or dst.exists():
            if dst.is_symlink() and os.readlink(dst) == str(src):
                continue
            dst.unlink()
        dst.symlink_to(src)
        print("linked", dst, "->", src)


@app.function(
    image=image,
    gpu="T4",
    volumes={MODELS_ROOT: volume},
    timeout=60 * 60,
    scaledown_window=60 * 15,
    memory=16384,
    cpu=4.0,
)
@modal.web_server(7860, startup_timeout=900)
def serve():
    _link_models()
    subprocess.Popen(
        ["python", "-u", "app_gradio.py", "--no-share", "--lowvram"],
        cwd=WORK,
    )


@app.local_entrypoint()
def main():
    download_models.remote()
    print("models ready; now run: modal deploy modal_app.py")
