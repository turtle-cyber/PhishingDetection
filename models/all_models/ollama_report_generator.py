import requests
import json

class OllamaReportGenerator:
    """
    Connects to a local Ollama instance to generate AI-driven analytical reports
    by synthesizing evidence from all detection modules.
    """
    def __init__(self, host='http://localhost:11434'):
        """
        Initializes the generator with the Ollama host URL.
        """
        self.api_url = f"{host}/api/generate"
        print(f"Ollama API URL set to: {self.api_url}")

    def construct_prompt(self, domain, evidence_dict):
        """
        Builds a detailed, structured prompt for an LLM based on collected evidence.
        (This function is the same as before)
        """
        prompt = f"""
You are a senior cybersecurity analyst specializing in phishing detection. Your task is to analyze the following collected evidence for the domain "{domain}" and generate a concise intelligence report.

**Collected Evidence:**
---
**1. URL Analysis:**
   - URL Length: {evidence_dict.get('url_features', {}).get('length', 'N/A')}
   - Number of Subdomains: {evidence_dict.get('url_features', {}).get('subdomains', 'N/A')}
   - Entropy: {evidence_dict.get('url_features', {}).get('entropy', 'N/A')}
   - Classification: {evidence_dict.get('url_classifier_result', 'N/A')}

**2. Visual Analysis (CLIP & VLM):**
   - Logo Similarity to known brand (e.g., SBI): {evidence_dict.get('logo_similarity', 'N/A')}
   - VLM Screenshot Analysis:
     - Purpose: {evidence_dict.get('vlm_analysis', {}).get('purpose', 'N/A')}
     - Contains Login Form: {evidence_dict.get('vlm_analysis', {}).get('has_login_form', 'N/A')}
     - Trustworthiness Assessment: {evidence_dict.get('vlm_analysis', {}).get('trustworthiness', 'N/A')}

**3. Content Analysis (NLP):**
   - High-Risk Keywords Found: {evidence_dict.get('keywords_found', 'N/A')}
   - Language Mismatch Detected: {evidence_dict.get('language_mismatch', 'N/A')}

**4. Temporal & Infrastructure Analysis (Behavioral & GNN):**
   - Temporal Anomalies Detected: {evidence_dict.get('temporal_anomalies', 'N/A')}
   - GNN Malicious Cluster Link: {evidence_dict.get('gnn_finding', 'N/A')}
---

**Your Task:**
Based *only* on the evidence provided above, generate a report with the following sections:
- **Executive Summary:** A one-paragraph summary of the findings and final verdict.
- **Key Findings:** A bulleted list of the 3-4 most critical pieces of evidence.
- **Risk Score:** An estimated risk score from 0 (Benign) to 10 (Critical Phishing Campaign). Justify your score.
- **Recommendation:** A clear, actionable recommendation (e.g., "Block and investigate," "Monitor," "Benign").
"""
        return prompt.strip()

    def generate_report_with_ollama(self, prompt, model_name='llama3.1'):
        """
        Sends the prompt to the Ollama API and returns the generated report.
        """
        try:
            print(f"\nSending prompt to Ollama model '{model_name}'... (This may take a moment)")
            payload = {
                "model": model_name,
                "prompt": prompt,
                "stream": False  # We want the full response at once
            }
            response = requests.post(self.api_url, json=payload)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

            # The response from Ollama is a JSON object, we need to parse it
            response_data = response.json()
            return response_data.get('response', 'Error: Could not find "response" key in Ollama output.').strip()

        except requests.exceptions.ConnectionError:
            return "Error: Connection to Ollama server failed. Is Ollama running?"
        except requests.exceptions.RequestException as e:
            return f"Error: An API request failed: {e}"

if __name__ == '__main__':
    # 1. Simulate the collected evidence for a suspicious domain
    evidence = {
        "url_features": {"length": 25, "subdomains": 3, "entropy": 4.8},
        "url_classifier_result": "Flagged as Malicious (92% probability)",
        "logo_similarity": "High (97.5% similarity to official SBI logo)",
        "vlm_analysis": {
            "purpose": "A login page for a banking service.",
            "has_login_form": "Yes",
            "trustworthiness": "Low. The URL is suspicious and the design is a low-quality copy."
        },
        "keywords_found": ["login", "password", "account", "username", "sbi"],
        "language_mismatch": "No",
        "temporal_anomalies": "Yes, domain became active 2 days ago after 65 days of dormancy.",
        "gnn_finding": "High Confidence. Linked to known phishing cluster 'APT-Phish-21'."
    }
    
    domain_to_analyze = "sbi-login-info.com"
    
    # 2. Instantiate the generator and construct the prompt
    generator = OllamaReportGenerator()
    final_prompt = generator.construct_prompt(domain_to_analyze, evidence)
    
    # 3. Generate and display the REAL report from your local Ollama model
    final_report = generator.generate_report_with_ollama(final_prompt, model_name='llama3.1')
    
    print("\n" + "="*60)
    print("OLLAMA-GENERATED AI ANALYST REPORT")
    print("="*60)
    print(final_report)