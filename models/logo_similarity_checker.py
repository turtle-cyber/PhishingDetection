import requests
from PIL import Image
from transformers import CLIPProcessor, CLIPModel
import torch

class LogoSimilarityChecker:
    """
    A class to check the similarity between a reference logo and a candidate image
    using OpenAI's CLIP model, as specified in the implementation document[cite: 7].
    """

    def __init__(self, model_name="openai/clip-vit-base-patch32"):
        """
        Initializes the model and processor.
        """
        try:
            print("Loading CLIP model... This may take a moment.")
            self.model = CLIPModel.from_pretrained(model_name)
            self.processor = CLIPProcessor.from_pretrained(model_name)
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.model.to(self.device)
            print(f"Model loaded successfully on device: {self.device}")
        except Exception as e:
            print(f"Error loading model: {e}")
            raise

    def _get_image_from_url(self, url):
        """
        Downloads and opens an image from a URL.
        """
        try:
            image = Image.open(requests.get(url, stream=True).raw).convert("RGB")
            return image
        except Exception as e:
            print(f"Error fetching image from URL {url}: {e}")
            return None

    def get_image_embedding(self, image):
        """
        Processes an image and computes its embedding using the CLIP model.
        """
        inputs = self.processor(images=image, return_tensors="pt").to(self.device)
        with torch.no_grad():
            embedding = self.model.get_image_features(**inputs)
        return embedding

    def calculate_similarity(self, reference_logo_url, candidate_image_url):
        """
        Calculates the cosine similarity between two images fetched from URLs.
        
        This aligns with the use case of detecting logo similarity against brands 
        and handles variations better than traditional pixel-matching methods[cite: 11].
        """
        print(f"Fetching reference logo from: {reference_logo_url}")
        reference_logo = self._get_image_from_url(reference_logo_url)
        
        print(f"Fetching candidate image from: {candidate_image_url}")
        candidate_image = self._get_image_from_url(candidate_image_url)

        if reference_logo is None or candidate_image is None:
            print("Could not proceed with similarity calculation due to image fetching errors.")
            return 0.0

        # Compute embeddings
        ref_embedding = self.get_image_embedding(reference_logo)
        cand_embedding = self.get_image_embedding(candidate_image)

        # Normalize embeddings
        ref_embedding /= ref_embedding.norm(p=2, dim=-1, keepdim=True)
        cand_embedding /= cand_embedding.norm(p=2, dim=-1, keepdim=True)

        # Calculate cosine similarity
        similarity_score = (ref_embedding @ cand_embedding.T).item()
        
        # Scale to a more intuitive 0-100 range
        similarity_percentage = (similarity_score + 1) / 2 * 100

        return similarity_percentage

if __name__ == '__main__':
    # --- Configuration ---
    # URL of the legitimate company logo. This would be stored in a database.
    # Example: State Bank of India, as mentioned in the document [cite: 10]
    LEGIT_LOGO_URL = "https://upload.wikimedia.org/wikipedia/commons/thumb/c/cc/State_Bank_of_India_logo.svg/2048px-State_Bank_of_India_logo.svg.png"

    # --- Test Cases ---
    # 1. A slightly modified or different version of the same logo (should be high similarity)
    CANDIDATE_URL_SIMILAR = "https://cdn.iconscout.com/icon/free/png-256/free-sbi-3381666-2822055.png"
    
    # 2. A completely different logo (should be low similarity)
    CANDIDATE_URL_DIFFERENT = "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Google_2015_logo.svg/1920px-Google_2015_logo.svg.png"
    
    # --- Execution ---
    checker = LogoSimilarityChecker()

    print("\n--- Test Case 1: Comparing with a similar logo ---")
    similarity1 = checker.calculate_similarity(LEGIT_LOGO_URL, CANDIDATE_URL_SIMILAR)
    print(f"\n>>> Similarity Score: {similarity1:.2f}%")
    if similarity1 > 85: # Threshold can be tuned
        print(">>> Verdict: High similarity. Potential phishing attempt.")
    else:
        print(">>> Verdict: Low similarity.")

    print("\n--- Test Case 2: Comparing with a different logo ---")
    similarity2 = checker.calculate_similarity(LEGIT_LOGO_URL, CANDIDATE_URL_DIFFERENT)
    print(f"\n>>> Similarity Score: {similarity2:.2f}%")
    if similarity2 > 85:
        print(">>> Verdict: High similarity. Potential phishing attempt.")
    else:
        print(">>> Verdict: Low similarity.")