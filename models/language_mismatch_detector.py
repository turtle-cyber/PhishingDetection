import fasttext
import os

class LanguageMismatchDetector:
    """
    Detects language mismatches between a declared language (e.g., from an
    HTML lang attribute) and the actual language of the text content using fastText.
    This is the final NLP module for Phase 1 Core Detection.
    """

    def __init__(self, model_path='lid.176.bin'):
        """
        Loads the pre-trained fastText language identification model.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model file not found at '{model_path}'.\n"
                f"Please download 'lid.176.bin' from the official fastText website and place it here."
            )
        try:
            print("Loading fastText language identification model...")
            # The model loading prints some info to the console, which is normal.
            self.model = fasttext.load_model(model_path)
            print("Model loaded successfully.")
        except Exception as e:
            print(f"Error loading model: {e}")
            raise

    def detect_language(self, text):
        """
        Predicts the language of a given text string.

        Args:
            text (str): The text content to analyze.

        Returns:
            tuple: A tuple containing the language code (e.g., 'en') and the confidence score.
        """
        # The model requires newline characters to be replaced for best performance.
        cleaned_text = text.replace('\n', ' ')
        predictions = self.model.predict(cleaned_text, k=1)
        
        # The output is in the format ('__label__en',), so we parse it.
        lang_code = predictions[0][0].replace('__label__', '')
        confidence = predictions[1][0]
        
        return lang_code, confidence

    def check_mismatch(self, text_content, declared_language):
        """
        Compares the detected language of the text with the declared language.

        Args:
            text_content (str): The actual text from the webpage.
            declared_language (str): The language code from the HTML tag (e.g., 'en', 'fr', 'hi').

        Returns:
            dict: A dictionary containing the analysis results.
        """
        detected_lang, confidence = self.detect_language(text_content)
        
        # Normalize for comparison (e.g., 'en-US' becomes 'en')
        declared_lang_base = declared_language.split('-')[0].lower()
        
        is_mismatch = (detected_lang != declared_lang_base)
        
        return {
            "declared_language": declared_lang_base,
            "detected_language": detected_lang,
            "confidence": f"{confidence:.2%}",
            "is_mismatch": is_mismatch
        }

if __name__ == '__main__':
    try:
        detector = LanguageMismatchDetector()

        # --- Test Cases ---

        # Case 1: No mismatch. Declared language matches the text.
        print("\n--- Test Case 1: No Mismatch ---")
        declared_en = "en-US"
        text_en = "Welcome to our secure online banking portal. Please log in to access your account."
        result1 = detector.check_mismatch(text_en, declared_en)
        print(f"Result: {result1}")
        if result1['is_mismatch']:
            print("Verdict: Mismatch Detected! (Suspicious)")
        else:
            print("Verdict: No Mismatch. (Looks OK)")

        # Case 2: Mismatch. Declared as French, but content is English.
        print("\n--- Test Case 2: Mismatch Detected ---")
        declared_fr = "fr"
        # Text is the same English text
        result2 = detector.check_mismatch(text_en, declared_fr)
        print(f"Result: {result2}")
        if result2['is_mismatch']:
            print("Verdict: Mismatch Detected! (Suspicious)")
        else:
            print("Verdict: No Mismatch. (Looks OK)")

        # Case 3: No mismatch, different language (Hindi).
        print("\n--- Test Case 3: No Mismatch (Hindi) ---")
        declared_hi = "hi"
        text_hi = "हमारे सुरक्षित ऑनलाइन बैंकिंग पोर्टल में आपका स्वागत है। कृपया अपने खाते तक पहुंचने के लिए लॉग इन करें।"
        result3 = detector.check_mismatch(text_hi, declared_hi)
        print(f"Result: {result3}")
        if result3['is_mismatch']:
            print("Verdict: Mismatch Detected! (Suspicious)")
        else:
            print("Verdict: No Mismatch. (Looks OK)")

    except FileNotFoundError as e:
        print(f"\nSetup Error: {e}")