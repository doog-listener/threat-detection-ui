import os
import uvicorn
import spaces
import gradio as gr
from main import app as fastapi_app

# Required by Hugging Face ZeroGPU to pass the startup health check
@spaces.GPU
def gpu_keepalive():
    return True

# Minimal interface to satisfy the Hugging Face Space runtime
with gr.Blocks(title="Threat Detection API") as demo:
    gr.Markdown("## 🛡️ Multi-Vector Threat Detection Engine API")
    gr.Markdown("FastAPI backend is active. Interactive Swagger docs: [/docs](/docs)")

# Mount Gradio dashboard to the FastAPI backend
app = gr.mount_gradio_app(fastapi_app, demo, path="/gradio")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port)