import logging
from typing import Dict, Any

# In a real application, you would use a proper email service
# like SendGrid, Mailgun, SMTP, etc.

logger = logging.getLogger(__name__)

def send_verification_email(email: str, code: str) -> Dict[str, Any]:
    """
    Send a verification email with a code.
    
    This is a mock implementation. In production, use a real email service.
    """
    logger.info(f"[MOCK EMAIL] Sending verification code {code} to {email}")
    
    # In a real implementation, you would send an actual email
    return {
        "success": True,
        "message": f"Verification code {code} sent to {email}"
    }

def send_password_reset_email(email: str, token: str) -> Dict[str, Any]:
    """
    Send a password reset email with a token.
    
    This is a mock implementation. In production, use a real email service.
    """
    reset_url = f"http://localhost:8000/reset-password/{token}"
    
    logger.info(f"[MOCK EMAIL] Sending password reset link to {email}:")
    logger.info(f"[MOCK EMAIL] Reset URL: {reset_url}")
    
    # In a real implementation, you would send an actual email
    return {
        "success": True,
        "message": f"Password reset link sent to {email}"
    }
def send_email_change_verification(email: str, code: str) -> Dict[str, Any]:
    """
    Send an email change verification email with a code.
    
    This is a mock implementation. In production, use a real email service.
    """
    logger.info(f"[MOCK EMAIL] Sending email change verification code {code} to {email}")
    
    # In a real implementation, you would send an actual email
    return {
        "success": True,
        "message": f"Email change verification code {code} sent to {email}"
    }