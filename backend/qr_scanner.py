"""
Quishing (QR Code Phishing) Computer Vision Engine
- Uses OpenCV (cv2.QRCodeDetector) to scan and extract QR codes from embedded images
- Decodes hidden destination URLs bypassing traditional text filters
- Routes decoded QR links into domain forensics and unshortener pipelines
"""

import base64
import re
from typing import Dict, Any, List, Optional
import cv2
import numpy as np

# Global OpenCV detector instance
_QR_DETECTOR = cv2.QRCodeDetector()

def decode_qr_from_bytes(image_bytes: bytes) -> Dict[str, Any]:
    """Decodes QR code from raw image byte buffer."""
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return {"found": False, "url": None, "error": "Unable to decode image format"}

        decoded_text, points, straight_qrcode = _QR_DETECTOR.detectAndDecode(img)
        if decoded_text:
            return {
                "found": True,
                "url": decoded_text.strip(),
                "error": None
            }
        
        # Fallback: Try grayscaling and thresholding to catch low-contrast QR codes
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        decoded_text, points, straight_qrcode = _QR_DETECTOR.detectAndDecode(thresh)
        if decoded_text:
            return {
                "found": True,
                "url": decoded_text.strip(),
                "error": None
            }

        return {"found": False, "url": None, "error": None}
    except Exception as e:
        return {"found": False, "url": None, "error": str(e)}

def decode_qr_from_base64(base64_str: str) -> Dict[str, Any]:
    """Decodes QR code from a base64 data URI or raw base64 string."""
    try:
        # Strip header like data:image/png;base64,
        if "," in base64_str:
            base64_str = base64_str.split(",")[1]
        image_bytes = base64.b64decode(base64_str)
        return decode_qr_from_bytes(image_bytes)
    except Exception as e:
        return {"found": False, "url": None, "error": f"Base64 parse error: {str(e)}"}
