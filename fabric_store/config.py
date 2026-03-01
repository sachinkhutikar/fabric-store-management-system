import os


class Config:
    # -----------------------------
    # Security
    # -----------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-this")

    # -----------------------------
    # Paths
    # -----------------------------
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DB_PATH = os.path.join(BASE_DIR, "fabric_store.db")

    # All uploads live inside /static/uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")

    # Main fabric thumbnail image
    FABRIC_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "fabrics")

    # Multiple images per fabric (gallery)
    FABRIC_GALLERY_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "fabric_gallery")

    # Custom design uploads from customer
    DESIGN_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "designs")

    # UPI QR image folder
    QR_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "qr")

    # QR image path relative to /static (so template uses: url_for('static', filename=qr_path))
    QR_IMAGE_PATH = "uploads/qr/upi_qr.png"

    # Max upload size (10MB)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    # -----------------------------
    # Razorpay (CARD payments)
    # -----------------------------
    RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
    RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")

    # -----------------------------
    # Store info (optional)
    # -----------------------------
    COMPANY_NAME = os.environ.get("COMPANY_NAME", "FabricStore")
    SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "tanvidivekar399@gmail.com")
    SUPPORT_PHONE = os.environ.get("SUPPORT_PHONE", "7770098084")

    # -----------------------------
    # Email (optional)
    # -----------------------------
    EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "false").lower() == "true"

    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")  # Gmail App Password recommended
    FROM_EMAIL = os.environ.get("FROM_EMAIL", "")
    ADMIN_ALERT_EMAIL = os.environ.get("ADMIN_ALERT_EMAIL", "")  # Low stock alerts