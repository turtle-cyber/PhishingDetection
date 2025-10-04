from urllib.parse import urlparse, parse_qs
import tldextract
import math

class URLFeatureExtractor:
    """
    Extracts features from a URL based on the specifications in the
    Problem Statement's Annexure A.
    
    This class is a foundational component for the phishing detection engine,
    providing structured data for machine learning models.
    """
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.extracted_tld = tldextract.extract(url)
        self.domain = self.extracted_tld.domain + '.' + self.extracted_tld.suffix
        self.subdomain = self.extracted_tld.subdomain
        self.path = self.parsed_url.path

    def _entropy(self, text):
        """Calculates the Shannon entropy of a string."""
        if not text:
            return 0
        freq = {char: text.count(char) for char in set(text)}
        entropy = -sum((count / len(text)) * math.log2(count / len(text)) for count in freq.values())
        return entropy

    def extract_features(self):
        """
        Extracts all features and returns them as a dictionary.
        Corresponds to Annexure A feature list.
        """
        features = {
            # URL-Based Features [cite: 109]
            'url_length': len(self.url),
            'num_dots_in_url': self.url.count('.'),
            'num_special_chars_in_url': sum(not c.isalnum() for c in self.url),
            'num_hyphens_in_url': self.url.count('-'),
            'num_slashes_in_url': self.url.count('/'),
            'num_underscores_in_url': self.url.count('_'),
            'num_question_marks_in_url': self.url.count('?'),
            'num_equal_signs_in_url': self.url.count('='),
            'num_dollar_signs_in_url': self.url.count('$'),
            'num_exclamation_marks_in_url': self.url.count('!'),
            'num_hashtags_in_url': self.url.count('#'),
            'num_percent_signs_in_url': self.url.count('%'),

            # Domain-Based Features
            'domain_length': len(self.domain),
            'num_hyphens_in_domain': self.domain.count('-'),
            
            # Subdomain-Based Features [cite: 127]
            'num_subdomains': len(self.subdomain.split('.')) if self.subdomain else 0,
            
            # Path-Based Features [cite: 133]
            'path_length': len(self.path),
            'has_query_in_path': 1 if self.parsed_url.query else 0,
            'has_fragment_in_path': 1 if self.parsed_url.fragment else 0,
            
            # Entropy and Miscellaneous Features [cite: 148]
            'entropy_of_url': self._entropy(self.url),
            'entropy_of_domain': self._entropy(self.domain),
            'has_https': 1 if self.parsed_url.scheme == 'https' else 0,
        }
        return features

if __name__ == '__main__':
    # --- Test Cases ---
    
    # Example 1: A potentially suspicious URL
    suspicious_url = "https://sbi-online-services.co.in.login.support-id12345.com/update_details/?sessionid=ABC&user=xyz"
    
    # Example 2: A legitimate URL
    legitimate_url = "https://www.onlinesbi.sbi/"

    print("--- Analyzing Suspicious URL ---")
    print(f"URL: {suspicious_url}\n")
    extractor_suspicious = URLFeatureExtractor(suspicious_url)
    features_suspicious = extractor_suspicious.extract_features()
    for feature, value in features_suspicious.items():
        print(f"{feature:<30}: {value}")

    print("\n" + "="*40 + "\n")

    print("--- Analyzing Legitimate URL ---")
    print(f"URL: {legitimate_url}\n")
    extractor_legitimate = URLFeatureExtractor(legitimate_url)
    features_legitimate = extractor_legitimate.extract_features()
    for feature, value in features_legitimate.items():
        print(f"{feature:<30}: {value}")