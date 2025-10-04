import torch
from PIL import Image
from transformers import AutoModelForCausalLM, AutoProcessor
import os

class ScreenshotAnalyzer:
    """
    Performs advanced analysis of webpage screenshots using the Qwen2-VL
    Vision-Language Model. This is the core of the Phase 2 analysis pipeline.
    """

    def __init__(self, model_name="Qwen/Qwen2-VL-7B-Instruct"):
        """
        Initializes the Qwen2-VL model and processor.
        """
        print("Initializing Qwen2-VL model. This will take some time and memory...")
        
        # Check for GPU availability
        if not torch.cuda.is_available():
            print("WARNING: No GPU detected. This model will run extremely slowly on a CPU.")
            self.device = "cpu"
        else:
            self.device = "cuda"
            print(f"GPU detected. Using device: {torch.cuda.get_device_name(0)}")

        try:
            # Using device_map="auto" and torch_dtype="auto" for automatic optimization
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype="auto",
                device_map="auto",
                trust_remote_code=True
            )
            self.processor = AutoProcessor.from_pretrained(model_name, trust_remote_code=True)
            print("Model and processor loaded successfully.")
        except Exception as e:
            print(f"Failed to load the model. Ensure you have enough VRAM and a stable internet connection.")
            print(f"Error: {e}")
            raise

    def analyze_screenshot(self, image_path, question):
        """
        Analyzes a given screenshot by asking a specific question.

        Args:
            image_path (str): The file path to the screenshot image.
            question (str): The question to ask the model about the image.

        Returns:
            str: The model's generated answer.
        """
        if not os.path.exists(image_path):
            return f"Error: Image file not found at '{image_path}'"

        try:
            image = Image.open(image_path)
            
            # Format the prompt according to the model's chat template
            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "image", "image": image},
                        {"type": "text", "text": question}
                    ]
                }
            ]
            
            # Process the inputs
            text = self.processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = self.processor(text, return_tensors="pt").to(self.model.device)

            # Generate the response
            with torch.no_grad():
                generated_ids = self.model.generate(**inputs, max_new_tokens=1024, do_sample=False)
            
            # Decode and clean the response
            decoded_response = self.processor.batch_decode(generated_ids, skip_special_tokens=True)[0]
            # The response includes the prompt, so we strip it
            answer = decoded_response.split("assistant\n")[-1].strip()

            return answer

        except Exception as e:
            return f"An error occurred during analysis: {e}"

if __name__ == '__main__':
    # --- Configuration ---
    # IMPORTANT: You must provide a path to a screenshot image on your computer.
    SCREENSHOT_PATH = "sample_login_page.png" 

    # List of analytical questions to ask the VLM about the screenshot
    QUESTIONS_TO_ASK = [
        "What is the main purpose of this webpage? Describe it in one sentence.",
        "Does this page contain any input fields for a username, email, or password? Answer with 'Yes' or 'No'.",
        "Based on the visual design, branding, and text, does this page look like a trustworthy and official website? Explain your reasoning.",
        "Transcribe all visible text from the image, including headers, buttons, and labels."
    ]

    # --- Execution ---
    try:
        if not os.path.exists(SCREENSHOT_PATH):
            print(f"Error: Screenshot file not found at '{SCREENSHOT_PATH}'.")
            print("Please create a dummy file or provide a real screenshot and run the script again.")
        else:
            analyzer = ScreenshotAnalyzer()
            print("\n" + "="*50)
            for i, q in enumerate(QUESTIONS_TO_ASK):
                print(f"\n[Question {i+1}]: {q}")
                answer = analyzer.analyze_screenshot(SCREENSHOT_PATH, q)
                print(f"[Answer]: {answer}")
            print("\n" + "="*50)

    except Exception as e:
        print(f"A critical error occurred: {e}")