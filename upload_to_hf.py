import os
from huggingface_hub import HfApi

# Your HF Write Token (set HF_TOKEN environment variable or pass here)
HF_TOKEN = os.environ.get("HF_TOKEN", "")
REPO_ID = "teem5002/threat-detection-backend"

api = HfApi(token=HF_TOKEN)

print("[*] Uploading project files to Hugging Face Space...")
api.upload_folder(
    folder_path=".",
    repo_id=REPO_ID,
    repo_type="space",
    ignore_patterns=[
        "venv/*",
        "__pycache__/*",
        "*.pyc",
        "upload_to_hf.py",
        ".git/*",
        "Dockerfile*"
    ]
)
print("[+] Upload complete! Building Space now.")