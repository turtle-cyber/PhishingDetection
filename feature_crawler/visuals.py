# crawler/visuals.py
from PIL import Image
import imagehash
import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim
import pytesseract
import os

def compute_phash(path_or_bytes):
    """Return perceptual hash string for an image path or bytes."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        from io import BytesIO
        img = Image.open(BytesIO(path_or_bytes)).convert("RGB")
    else:
        img = Image.open(path_or_bytes).convert("RGB")
    return str(imagehash.phash(img))

def compute_ssim(img_a_path, img_b_path):
    """Compute SSIM (0..1). Returns float or None on error."""
    try:
        a = cv2.imread(img_a_path, cv2.IMREAD_GRAYSCALE)
        b = cv2.imread(img_b_path, cv2.IMREAD_GRAYSCALE)
        if a is None or b is None:
            return None
        # resize to smallest mutually
        h = min(a.shape[0], b.shape[0])
        w = min(a.shape[1], b.shape[1])
        a_r = cv2.resize(a, (w, h))
        b_r = cv2.resize(b, (w, h))
        score, _ = ssim(a_r, b_r, full=True)
        return float(score)
    except Exception:
        return None

def orb_logo_matches(img_path, template_path, min_matches=8):
    """
    Return number of good ORB matches between image and template.
    Enough matches suggests the logo is present.
    """
    try:
        img = cv2.imread(img_path, 0)
        tpl = cv2.imread(template_path, 0)
        if img is None or tpl is None:
            return 0
        orb = cv2.ORB_create(1000)
        kp1, des1 = orb.detectAndCompute(img, None)
        kp2, des2 = orb.detectAndCompute(tpl, None)
        if des1 is None or des2 is None:
            return 0
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
        matches = bf.knnMatch(des1, des2, k=2)
        # ratio test
        good = []
        for m_n in matches:
            if len(m_n) != 2:
                continue
            m, n = m_n
            if m.distance < 0.75 * n.distance:
                good.append(m)
        return len(good)
    except Exception:
        return 0

def ocr_image(img_path):
    """Return OCR string. Requires Tesseract installed on system."""
    try:
        txt = pytesseract.image_to_string(Image.open(img_path))
        return txt
    except Exception:
        return ""
def save_image_from_bytes(img_bytes, save_path):
    """Save image bytes to a file."""
    try:
        with open(save_path, 'wb') as f:
            f.write(img_bytes)
        return True
    except Exception:
        return False