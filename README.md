# 🛡️ Multi-Vector Threat Detection Engine & Visual Dashboard

An advanced, real-time cyber threat detection engine and interactive dashboard combining deep learning visual binary triage (ResNet-50 CNN + Grad-CAM heatmaps) with media forensics and steganography analysis.

![Screenshot](images/Screenshot%202026-07-28%20164916.png)

---

## 🚀 Key Features

### 1. Vector A: Visual Binary Executable Triage
- **Spatial Byte Projection (Nataraj Mapping)**: Converts raw binary bytes into gray-scale and spatial matrices for computer vision analysis.
- **Deep Learning Classification (ResNet-50)**: Classifies binaries into 25 known malware families (e.g., Ramnit, Lollipop, Kelihos, Vundo, Simda, etc.) or flags anomalies.
- **Explainable AI (Grad-CAM)**: Visualizes exact neural attention regions highlighting which byte structures and packed sections triggered the threat detection.
- **Authenticode Verification**: Validates embedded PE digital signatures (`IMAGE_DIRECTORY_ENTRY_SECURITY`) to avoid false positives on legitimate software.

### 2. Vector B: Media Forensics & Steganography Detection
- **Shannon Entropy Analysis**: Computes pixel channel entropy to expose hidden high-entropy payloads or encrypted blobs.
- **LSB Payload Extraction**: Extracts and decrypts Least Significant Bit strings to detect embedded command-and-control (C2) scripts and reverse shells.
- **Magic Byte & Extension Spoofing Detection**: Verifies true file formats versus extensions to stop double-extension and spoofed file tricks.

### 3. Modern Cyber Command UI
- Real-time drag-and-drop file inspection.
- Batch triage table for multi-file incident response.
- Audio alert synthesizer, cyber decrypt animations, and Grad-CAM visual overlays.

---

## 🛠️ Tech Stack

- **Backend**: FastAPI, Uvicorn, PyTorch, Torchvision, Pillow, NumPy, Matplotlib
- **Frontend**: Responsive Single-Page Cyber UI with Tailwind CSS and Canvas effects
- **Deployment**: Local Uvicorn server / Hugging Face Spaces with Gradio integration

---

## 📦 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/doog-listener/threat-detection-ui.git
cd threat-detection-ui
```

### 2. Create and Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
```

### 4. Run the Engine
```bash
uvicorn main:app --reload --port 8000
```
Open your browser and navigate to:
- **Interactive UI**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **API Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧪 Testing with Controlled Artifacts

Generate sample clean and malicious test files:
```bash
python create_test_samples.py
```
This produces:
- `clean_reference.png`: Low entropy, benign baseline image.
- `malicious_stego.png`: High entropy carrier containing an embedded C2 reverse shell payload in LSB.
- `malicious_simulated.exe`: Synthetic packed PE binary with UPX signatures for model activation.

---

## 📄 License

MIT License. Designed for defense, research, and educational analysis.
