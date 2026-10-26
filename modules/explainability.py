import io
import base64
import torch
import torch.nn.functional as F
import numpy as np
import matplotlib
import matplotlib.cm as cm
from PIL import Image

class NativeGradCAM:
    def __init__(self, model, target_layer):
        self.model = model
        self.target_layer = target_layer
        self.gradients = None
        self.activations = None
        
        # Register hooks and SAVE their handles
        self.forward_handle = self.target_layer.register_forward_hook(self._save_activation)
        self.backward_handle = self.target_layer.register_full_backward_hook(self._save_gradient)

    def _save_activation(self, module, input, output):
        self.activations = output.detach()

    def _save_gradient(self, module, grad_input, grad_output):
        self.gradients = grad_output[0].detach()

    def generate(self, input_tensor, target_class: int):
        self.model.zero_grad()
        output = self.model(input_tensor)
        
        # Backpropagate target class score
        score = output[0, target_class]
        score.backward(retain_graph=True)
        
        # Compute channel-wise mean gradients
        weights = torch.mean(self.gradients, dim=(2, 3), keepdim=True)
        cam = torch.sum(weights * self.activations, dim=1, keepdim=True)
        
        # Apply ReLU to keep positive influence
        cam = F.relu(cam)
        
        # Resize activation map to input dimensions (224x224)
        cam = F.interpolate(cam, size=(224, 224), mode='bilinear', align_corners=False)
        cam_np = cam.squeeze().cpu().numpy()
        
        # Normalize activation map between 0 and 1
        cam_min, cam_max = cam_np.min(), cam_np.max()
        if cam_max > cam_min:
            cam_np = (cam_np - cam_min) / (cam_max - cam_min)
        else:
            cam_np = np.zeros_like(cam_np)
            
        return cam_np

    def remove_hooks(self):
        """CRITICAL: Removes hooks to prevent RAM leaks and server crashes."""
        self.forward_handle.remove()
        self.backward_handle.remove()

def generate_gradcam_base64(classifier, input_tensor, pred_idx: int, pil_image: Image.Image) -> str:
    grad_cam = NativeGradCAM(model=classifier.model, target_layer=classifier.model.layer4[-1])
    
    try:
        cam_map = grad_cam.generate(input_tensor, pred_idx)
    finally:
        # Guarantee hooks are removed even if an error occurs during generation
        grad_cam.remove_hooks()
    
    # Overlay heatmap onto the original image
    img_resized = pil_image.resize((224, 224)).convert('RGB')
    img_np = np.array(img_resized, dtype=np.float32) / 255.0
    
    try:
        cmap = matplotlib.colormaps['jet']
    except Exception:
        cmap = cm.get_cmap('jet')
        
    heatmap = cmap(cam_map)[:, :, :3]
    overlay = 0.5 * img_np + 0.5 * heatmap
    overlay = np.clip(overlay, 0, 1)
    overlay_uint8 = (overlay * 255).astype(np.uint8)
    
    cam_pil = Image.fromarray(overlay_uint8)
    buffer = io.BytesIO()
    cam_pil.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")

def image_to_base64(pil_image: Image.Image) -> str:
    buffer = io.BytesIO()
    pil_image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")