from datetime import datetime, timedelta
import random
import string
import secrets
import logging
import re
from typing import Optional, List, Dict, Any, Union
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import pyotp  # For TOTP-based MFA
from database import SessionLocal
import models
import password_health
from password_health import check_password_breach, check_common_password

# Configure logging
logger = logging.getLogger(__name__)

# Password hashing with stronger settings
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Increased from default 10 for better security
)

# Password validation regex patterns
PASSWORD_PATTERNS = {
    "uppercase": re.compile(r"[A-Z]"),
    "lowercase": re.compile(r"[a-z]"),
    "digit": re.compile(r"[0-9]"),
    "special": re.compile(r"[^A-Za-z0-9]")
}

def validate_password_strength(password: str) -> Dict[str, bool]:
    """
    Validate password strength against multiple criteria.
    Returns a dictionary of validation results.
    """
    results = {
        "length": len(password) >= 8,
        "uppercase": bool(PASSWORD_PATTERNS["uppercase"].search(password)),
        "lowercase": bool(PASSWORD_PATTERNS["lowercase"].search(password)),
        "digit": bool(PASSWORD_PATTERNS["digit"].search(password)),
        "special": bool(PASSWORD_PATTERNS["special"].search(password))
    }
    
    results["valid"] = all(results.values())
    return results

def get_password_hash(password: str) -> str:
    """Hash a password for storing."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a stored password against a provided password."""
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    """Authenticate a user by email and password."""
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            logger.info(f"Authentication failed: User with email {email} not found")
            return None
            
        if not verify_password(password, user.password_hash):
            logger.info(f"Authentication failed: Invalid password for user {email}")
            return None
            
        return user
    except SQLAlchemyError as e:
        logger.error(f"Database error during authentication: {str(e)}")
        return None

def create_user(db: Session, name: str, email: str, password: str) -> Union[models.User, None]:
    """Create a new user with validation and password health tracking."""
    try:
        # Validate password strength
        password_validation = validate_password_strength(password)
        if not password_validation["valid"]:
            logger.warning(f"User creation failed: Password does not meet strength requirements")
            return None
            
        hashed_password = get_password_hash(password)
        
        # Generate a secret key for TOTP if using authenticator apps
        totp_secret = pyotp.random_base32()
        
        # Create the user
        user = models.User(
            name=name,
            email=email,
            password_hash=hashed_password,
            mfa_enabled=True,  # Enable MFA by default for security
            totp_secret=totp_secret,  # Store TOTP secret for authenticator apps
            last_password_change=datetime.utcnow()
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Add to password history
        password_history = models.PasswordHistory(
            user_id=user.id,
            password_hash=hashed_password,
            created_at=datetime.utcnow()
        )
        db.add(password_history)
        
        # Check password health
        strength_score = password_validation.get("score", 0)
        
        # Check if password has been exposed in data breaches
        has_been_breached, breach_count = check_password_breach(password)
        
        # Check if password is commonly used
        is_common = check_common_password(password)
        
        # Create password health record
        password_health_record = models.PasswordHealth(
            user_id=user.id,
            strength_score=strength_score,
            has_been_breached=has_been_breached,
            is_common=is_common,
            last_changed=datetime.utcnow(),
            days_until_expiry=90,  # Default 90 days until expiry
            reused=False
        )
        db.add(password_health_record)
        db.commit()
        
        logger.info(f"User created successfully: {email}")
        return user
        
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error during user creation: {str(e)}")
        return None
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error during user creation: {str(e)}")
        return None

def generate_verification_code() -> str:
    """Generate a 6-digit verification code."""
    return str(random.randint(100000, 999999))

def create_verification_code(db: Session, user_id: str, code: str) -> Optional[models.VerificationCode]:
    """Create a verification code for a user."""
    try:
        # Delete any existing verification codes for this user
        db.query(models.VerificationCode).filter(
            models.VerificationCode.user_id == user_id
        ).delete()
        
        verification_code = models.VerificationCode(
            user_id=user_id,
            code=code,
            expires_at=datetime.utcnow() + timedelta(minutes=10)  # 10 minutes expiration
        )
        db.add(verification_code)
        db.commit()
        db.refresh(verification_code)
        return verification_code
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error creating verification code: {str(e)}")
        return None

def verify_code(db: Session, user_id: str, code: str) -> bool:
    """Verify a code for a user."""
    try:
        verification_code = db.query(models.VerificationCode).filter(
            models.VerificationCode.user_id == user_id,
            models.VerificationCode.code == code,
            models.VerificationCode.expires_at > datetime.utcnow()
        ).first()
        
        if not verification_code:
            return False
        
        # Delete the verification code
        db.delete(verification_code)
        db.commit()
        
        return True
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error verifying code: {str(e)}")
        return False

def verify_totp(user: models.User, totp_code: str) -> bool:
    """Verify a TOTP code for a user (for authenticator apps)."""
    if not user.totp_secret:
        return False
        
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(totp_code)

def generate_totp_uri(user: models.User, issuer_name: str = "SecureAuth") -> str:
    """Generate a TOTP URI for QR code generation."""
    if not user.totp_secret:
        return ""
        
    totp = pyotp.TOTP(user.totp_secret)
    return totp.provisioning_uri(name=user.email, issuer_name=issuer_name)

def generate_reset_token() -> str:
    """Generate a secure reset token."""
    return secrets.token_urlsafe(32)

def create_reset_token(db: Session, user_id: str, token: str) -> Optional[models.PasswordResetToken]:
    """Create a password reset token for a user."""
    try:
        # Delete any existing reset tokens for this user
        db.query(models.PasswordResetToken).filter(
            models.PasswordResetToken.user_id == user_id
        ).delete()
        db.commit()
        
        reset_token = models.PasswordResetToken(
            user_id=user_id,
            token=token,
            expires_at=datetime.utcnow() + timedelta(hours=1)  # 1 hour expiration
        )
        db.add(reset_token)
        db.commit()
        db.refresh(reset_token)
        return reset_token
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error creating reset token: {str(e)}")
        return None

def log_login_attempt(
    db: Session, 
    email: str, 
    ip_address: str, 
    user_id: Optional[str] = None, 
    success: bool = False,
    blocked_by_rate_limit: bool = False,
    requires_verification: bool = False,
    account_locked: bool = False  # New parameter
) -> Optional[models.LoginAttempt]:
    """Log a login attempt."""
    try:
        login_attempt = models.LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_id=user_id,
            success=success,
            blocked_by_rate_limit=blocked_by_rate_limit,
            requires_verification=requires_verification,
            account_locked=account_locked  # Include in model initialization
        )
        db.add(login_attempt)
        db.commit()
        db.refresh(login_attempt)
        return login_attempt
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error logging login attempt: {str(e)}")
        return None

def log_activity(db: Session, user_id: str, activity_type: str, ip_address: str, details: Dict[str, Any] = None) -> Optional[models.Activity]:
    """Log a user activity with optional details."""
    try:
        activity = models.Activity(
            user_id=user_id,
            type=activity_type,
            ip_address=ip_address,
            details=details  # Store additional details as JSON
        )
        db.add(activity)
        db.commit()
        db.refresh(activity)
        return activity
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error logging activity: {str(e)}")
        return None

def get_user_activities(db: Session, user_id: str, limit: int = 10) -> List[models.Activity]:
    """Get recent user activities."""
    try:
        return db.query(models.Activity).filter(
            models.Activity.user_id == user_id
        ).order_by(models.Activity.timestamp.desc()).limit(limit).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving user activities: {str(e)}")
        return []

def check_account_lockout(db: Session, email: str, window_minutes: int = 15, max_attempts: int = 5) -> bool:
    """Check if an account should be locked due to too many failed login attempts."""
    try:
        since_time = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        failed_attempts = db.query(models.LoginAttempt).filter(
            models.LoginAttempt.email == email,
            models.LoginAttempt.success == False,
            models.LoginAttempt.created_at >= since_time
        ).count()
        
        return failed_attempts >= max_attempts
    except SQLAlchemyError as e:
        logger.error(f"Database error checking account lockout: {str(e)}")
        return False  # Default to not locked in case of error

def update_password(db: Session, user_id: str, new_password: str) -> models.User:
    """Update a user's password."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return None
    
    # Get password history
    password_history_records = db.query(models.PasswordHistory).filter(
        models.PasswordHistory.user_id == user_id
    ).order_by(models.PasswordHistory.created_at.desc()).limit(5).all()
    
    password_history_hashes = [record.password_hash for record in password_history_records]
    
    # Check if password is reused
    reused = password_health.is_password_reused(new_password, password_history_hashes, pwd_context)
    
    # Hash the new password
    hashed_password = get_password_hash(new_password)
    
    # Update user password
    user.password_hash = hashed_password
    user.updated_at = datetime.utcnow()
    
    # Add to password history
    password_history = models.PasswordHistory(
        user_id=user_id,
        password_hash=hashed_password
    )
    db.add(password_history)
    
    # Check password health
    strength_score, _ = password_health.check_password_strength(new_password)
    has_been_breached, _ = password_health.check_password_breach(new_password)
    is_common = password_health.check_common_password(new_password)
    
    # Update or create password health record
    password_health_record = db.query(models.PasswordHealth).filter(
        models.PasswordHealth.user_id == user_id
    ).first()
    
    if password_health_record:
        password_health_record.strength_score = strength_score
        password_health_record.has_been_breached = has_been_breached
        password_health_record.is_common = is_common
        password_health_record.last_changed = datetime.utcnow()
        password_health_record.days_until_expiry = 90  # Reset to 90 days
        password_health_record.reused = reused
    else:
        password_health_record = models.PasswordHealth(
            user_id=user_id,
            strength_score=strength_score,
            has_been_breached=has_been_breached,
            is_common=is_common,
            last_changed=datetime.utcnow(),
            days_until_expiry=90,
            reused=reused
        )
        db.add(password_health_record)
    
    db.commit()
    db.refresh(user)
    
    return user
    
def generate_backup_codes(count=10):
    """Generate a set of backup codes."""
    codes = []
    for _ in range(count):
        # Generate a code like XXXX-XXXX-XXXX where X is alphanumeric
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        code += '-'
        code += ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        code += '-'
        code += ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        codes.append(code)
    return codes

def create_backup_codes(db: Session, user_id: str, count=10):
    """Create backup codes for a user."""
    # Delete existing backup codes
    db.query(models.BackupCode).filter(models.BackupCode.user_id == user_id).delete()
    db.commit()
    
    # Generate new backup codes
    codes = generate_backup_codes(count)
    
    # Store backup codes
    for code in codes:
        backup_code = models.BackupCode(
            user_id=user_id,
            code=code
        )
        db.add(backup_code)
    
    db.commit()
    return codes

def verify_backup_code(db: Session, user_id: str, code: str):
    """Verify a backup code for a user."""
    backup_code = db.query(models.BackupCode).filter(
        models.BackupCode.user_id == user_id,
        models.BackupCode.code == code,
        models.BackupCode.used == False
    ).first()
    
    if not backup_code:
        return False
    
    # Mark the code as used
    backup_code.used = True
    db.commit()
    
    return True

def get_unused_backup_codes(db: Session, user_id: str):
    """Get unused backup codes for a user."""
    return db.query(models.BackupCode).filter(
        models.BackupCode.user_id == user_id,
        models.BackupCode.used == False
    ).all()


def is_account_locked(user: models.User) -> bool:
    """Check if a user account is locked."""
    if not user.account_locked:
        return False
    
    # If the lockout period has expired, unlock the account
    if user.account_locked_until and user.account_locked_until < datetime.utcnow():
        user.account_locked = False
        user.account_locked_until = None
        # Make sure to commit this change to the database
        try:
            db = SessionLocal()
            db.add(user)
            db.commit()
        except Exception as e:
            logger.error(f"Error unlocking account: {e}")
        finally:
            if 'db' in locals():
                db.close()
        return False
    
    return user.account_locked

def get_lockout_time_remaining(user: models.User) -> int:
    """Get the time remaining (in minutes) for an account lockout."""
    if not user.account_locked or not user.account_locked_until:
        return 0
    
    now = datetime.utcnow()
    if user.account_locked_until <= now:
        return 0
    
    # Calculate minutes remaining
    delta = user.account_locked_until - now
    return max(1, int(delta.total_seconds() / 60))

def lock_account(db: Session, user_id: str, minutes: int = 30) -> None:
    """Lock a user account for a specified number of minutes."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.account_locked = True
        user.account_locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        db.commit()

def unlock_account(db: Session, user_id: str) -> None:
    """Unlock a user account."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.account_locked = False
        user.account_locked_until = None
        db.commit()

def count_recent_failed_attempts(db: Session, user_id: str, minutes: int = 30) -> int:
    """Count recent failed login attempts for a user."""
    since = datetime.utcnow() - timedelta(minutes=minutes)
    return db.query(models.LoginAttempt).filter(
        models.LoginAttempt.user_id == user_id,
        models.LoginAttempt.success == False,
        models.LoginAttempt.created_at >= since
    ).count()

def reset_failed_attempts(db: Session, user_id: str) -> None:
    """Reset the failed login attempts counter for a user."""
    # This is implemented by simply not counting old attempts
    # No need to delete or modify existing records
    pass