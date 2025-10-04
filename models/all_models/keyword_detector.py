from transformers import BertTokenizer
import torch

class KeywordDetector:
    """
    Detects the presence of specific keywords in a text using a pre-trained
    multilingual BERT tokenizer. This is a core component for Phase 1
    content analysis.
    """

    def __init__(self, model_name="bert-base-multilingual-cased"):
        """
        Initializes the BERT tokenizer.
        """
        try:
            print(f"Loading tokenizer for model: '{model_name}'...")
            self.tokenizer = BertTokenizer.from_pretrained(model_name)
            print("Tokenizer loaded successfully.")
        except Exception as e:
            print(f"Error loading tokenizer: {e}")
            raise

    def detect_keywords(self, text, keywords):
        """
        Checks for the presence of keywords in the given text.

        Args:
            text (str): The input text from a webpage or other source.
            keywords (list): A list of keywords to search for.

        Returns:
            list: A list of keywords that were found in the text.
        """
        if not text or not keywords:
            return []

        # Normalize text and keywords for case-insensitive matching
        normalized_text = text.lower()
        normalized_keywords = [kw.lower() for kw in keywords]

        # Tokenize the text
        tokens = self.tokenizer.tokenize(normalized_text)
        
        # Use a set for efficient lookup of found keywords
        found_keywords = set()

        for keyword in normalized_keywords:
            # Tokenize the keyword itself to handle subwords
            keyword_tokens = self.tokenizer.tokenize(keyword)
            
            # Check if the sequence of keyword tokens exists in the text tokens
            if self._is_sublist(keyword_tokens, tokens):
                # Add the original keyword (not normalized) to the set
                original_keyword_index = normalized_keywords.index(keyword)
                found_keywords.add(keywords[original_keyword_index])

        return list(found_keywords)

    def _is_sublist(self, sub, main):
        """Helper function to check if a list is a sublist of another."""
        return any(main[i:i+len(sub)] == sub for i in range(len(main) - len(sub) + 1))


if __name__ == '__main__':
    # --- Configuration ---
    # This list should be expanded with terms relevant to your target CSEs.
    HIGH_RISK_KEYWORDS = [
        "login", "password", "verify", "account", "update", "confirm", "username",
        "credit card", "bank", "official", "secure", "SSN", "credentials",
        # Hindi examples for multilingual check
        "पासवर्ड", "बैंक", "खाता", "लॉग इन करें"
    ]

    detector = KeywordDetector()

    # --- Test Cases ---
    
    # 1. English text with several high-risk keywords
    phishing_text_en = """
    Official bank security update. Please login with your username and password 
    to confirm your account credentials and avoid suspension.
    """
    
    # 2. Benign English text
    benign_text_en = "This is a news article about the latest trends in technology."
    
    # 3. Hindi text with high-risk keywords
    phishing_text_hi = "अपने बैंक खाता को सुरक्षित रखने के लिए, कृपया अपना पासवर्ड यहाँ लॉग इन करें।"
    
    # --- Execution ---
    print("\n--- Analyzing Test Case 1 (English Phishing Text) ---")
    found1 = detector.detect_keywords(phishing_text_en, HIGH_RISK_KEYWORDS)
    print(f"Found keywords: {found1}")

    print("\n--- Analyzing Test Case 2 (Benign English Text) ---")
    found2 = detector.detect_keywords(benign_text_en, HIGH_RISK_KEYWORDS)
    print(f"Found keywords: {found2 if found2 else 'None'}")
    
    print("\n--- Analyzing Test Case 3 (Hindi Phishing Text) ---")
    found3 = detector.detect_keywords(phishing_text_hi, HIGH_RISK_KEYWORDS)
    print(f"Found keywords: {found3}")