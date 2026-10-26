import json
import torch
import torch.nn.functional as F
from torchvision import models, transforms
from PIL import Image

class MalwareClassifier:
    def __init__(self, model_path: str, classes_path: str, confidence_threshold: float = 0.70):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.confidence_threshold = confidence_threshold
        
        # Load class mappings
        with open(classes_path, "r") as f:
            self.classes = json.load(f)
            
        # Initialize ResNet-50 base architecture
        self.model = models.resnet50(weights=None)
        num_features = self.model.fc.in_features
        
        # Load trained state dictionary
        state_dict = torch.load(model_path, map_location=self.device)
        
        # Match classification head structure to trained weights
        if "fc.0.weight" in state_dict:
            hidden_dim = state_dict["fc.0.weight"].shape[0]
            self.model.fc = torch.nn.Sequential(
                torch.nn.Linear(num_features, hidden_dim),
                torch.nn.ReLU(),
                torch.nn.Dropout(0.3),
                torch.nn.Linear(hidden_dim, len(self.classes))
            )
        else:
            self.model.fc = torch.nn.Linear(num_features, len(self.classes))

        self.model.load_state_dict(state_dict)
        self.model.to(self.device)
        self.model.eval()

        self.transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(
                mean=[0.485, 0.456, 0.406],
                std=[0.229, 0.224, 0.225]
            )
        ])

    def predict(self, pil_image: Image.Image):
        tensor = self.transform(pil_image).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(tensor)
            probabilities = F.softmax(outputs, dim=1)
            confidence, predicted_idx = torch.max(probabilities, 1)
            
        pred_idx = predicted_idx.item()
        conf_score = confidence.item() * 100.0
        family_name = self.classes[pred_idx]

        # Gating logic for benign vs. malicious categorization
        if conf_score >= 80.0:
            verdict = "MALICIOUS"
            risk_level = "CRITICAL"
        elif conf_score >= self.confidence_threshold * 100.0:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
        else:
            verdict = "BENIGN / UNKNOWN"
            risk_level = "LOW"

        return {
            "pred_idx": pred_idx,
            "family": family_name,
            "confidence": conf_score,
            "verdict": verdict,
            "risk_level": risk_level,
            "tensor": tensor
        }