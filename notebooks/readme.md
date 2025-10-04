# PS-02: Phishing Detection Platform — Quickstart


## Overview
This repository contains the skeleton and dependencies for the PS-02 (AI Monitoring & Detection of Phishing Domains/URLs for CSEs) platform. The codebase is expected to include components for:


- Crawling & browser-based rendering (Playwright)
- WHOIS / RDAP / DNS collection
- Feature extraction (URL, metadata, visual, graph, temporal)
- ML models (transformers, tree ensembles, CNNs, GNNs)
- Monitoring & alerting pipeline
- Operator dashboard (FastAPI + React suggested)


**Important:** The solution **must not** use third-party phishing detection APIs / commercial threat-intel platforms for detection. Declare any external API calls you make.


## System prerequisites (recommended)
- Ubuntu 22.04 / 24.04 LTS (24.04 recommended for evaluation infra)
- Python 3.10 or 3.11
- At least 16GB RAM for development (256GB expected on evaluation infra)
- Optional: GPU for faster model training (not required for submission)


### System packages (example for Ubuntu)


```bash
sudo apt update && sudo apt install -y \
build-essential \
python3-venv \
python3-dev \
git \
curl \
tesseract-ocr \
libpq-dev \
libgl1 \
libnss3 \
libatk1.0-0 \
libxss1 \
libasound2 \
fonts-liberation