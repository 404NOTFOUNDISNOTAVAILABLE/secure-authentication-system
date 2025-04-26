import secrets
import uvicorn
import os
import qrcode
import io
import base64
import pyotp
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Optional, List, Union 
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, EmailStr, validator
from rate_limiter import RateLimiter
import password_health
from database import SessionLocal, engine
import models
import security
import email_service
import password_health

load_dotenv()
# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Authentication System")

# Add session middleware with a secure key
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_urlsafe(32),
    max_age=3600,  # 1 hour
    https_only=True,
    same_site="lax"
)

# Rate limiter for brute force protection
rate_limiter = RateLimiter(max_attempts=5, window_seconds=900)  # 5 attempts per 15 minutes

# Set up templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get the current user from session
def get_current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    
    user = db.query(models.User).filter(models.User.id == user_id).first()
    return user

# Add this helper function to your main.py file
def render_security_settings(
    request: Request, 
    user: models.User, 
    db: Session, 
    password_error: Optional[str] = None,
    password_success: Optional[str] = None,
    mfa_success: Optional[str] = None,
    totp_error: Optional[str] = None,
    totp_success: Optional[str] = None,
    account_success: Optional[str] = None
):
    # Get user activities related to security
    security_activities = db.query(models.Activity).filter(
        models.Activity.user_id == user.id,
        models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes", "Account Locked", "Account Unlocked"])
    ).order_by(models.Activity.timestamp.desc()).limit(10).all()
    
    # Get recent login attempts
    login_attempts = db.query(models.LoginAttempt).filter(
        models.LoginAttempt.email == user.email
    ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse(
        "security_settings.html", 
        {
            "request": request,
            "user": user,
            "security_activities": security_activities,
            "login_attempts": login_attempts,
            "timedelta": timedelta,
            "password_error": password_error,
            "password_success": password_success,
            "mfa_success": mfa_success,
            "totp_error": totp_error,
            "totp_success": totp_success,
            "account_success": account_success
        }
    )

# Pydantic models for validation
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    
    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        if not any(c for c in v if not c.isalnum()):
            raise ValueError('Password must contain at least one special character')
        return v

class LoginForm(BaseModel):
    email: EmailStr
    password: str

class VerifyForm(BaseModel):
    code: str
    
    @validator('code')
    def code_length(cls, v):
        if len(v) != 6:
            raise ValueError('Verification code must be 6 digits')
        if not v.isdigit():
            raise ValueError('Verification code must contain only digits')
        return v

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    password: str
    
    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        if not any(c for c in v if not c.isalnum()):
            raise ValueError('Password must contain at least one special character')
        return v

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: Optional[models.User] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user: Optional[models.User] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request, 
    email: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    # Check rate limiting
    client_ip = request.client.host
    
    # Use a combination of IP and email for rate limiting to avoid blocking different users from same IP
    rate_limit_key = f"{client_ip}:{email}"
    
    if rate_limiter.is_rate_limited(rate_limit_key):
        # Log failed attempt
        security.log_login_attempt(db, email, client_ip, None, False, True)
        
        # Calculate time remaining for rate limit
        time_remaining = rate_limiter.get_time_remaining(rate_limit_key)
        
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": f"Too many failed login attempts. Please try again in {time_remaining} minutes."
            }
        )
    
    # Check if the account exists
    user_exists = db.query(models.User).filter(models.User.email == email).first()
    
    # Check if account is locked
    if user_exists and security.is_account_locked(user_exists):
        # Calculate time remaining in lockout
        time_remaining = security.get_lockout_time_remaining(user_exists)
        
        # Log failed attempt due to account lockout
        security.log_login_attempt(db, email, client_ip, user_exists.id, False, False, False, True)
        
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": f"Your account is locked due to multiple failed login attempts. Please try again in {time_remaining} minutes or reset your password."
            }
        )
    
    # Validate credentials
    user = security.authenticate_user(db, email, password)
    if not user:
        # Log failed attempt
        security.log_login_attempt(db, email, client_ip, user_exists.id if user_exists else None, False)
        
        # Increment rate limiter counter
        rate_limiter.increment(rate_limit_key)
        
        # Check if we should lock the account
        if user_exists:
            # Count recent failed attempts for this user
            recent_failed_attempts = security.count_recent_failed_attempts(db, user_exists.id)
            max_attempts = 5  # Maximum allowed failed attempts
            attempts_left = max_attempts - recent_failed_attempts
            
            # Lock account after max_attempts failed attempts
            if recent_failed_attempts >= max_attempts:
                security.lock_account(db, user_exists.id)
                
                # Log account lockout
                security.log_activity(db, user_exists.id, "Account Locked", client_ip)
                
                return templates.TemplateResponse(
                    "login.html", 
                    {
                        "request": request, 
                        "error": "Your account has been locked due to multiple failed login attempts. Please try again in 30 minutes or reset your password."
                    }
                )
            else:
                # Show attempts left
                return templates.TemplateResponse(
                    "login.html", 
                    {
                        "request": request, 
                        "error": f"Invalid email or password. You have {attempts_left} attempts left before your account is locked."
                    }
                )
        
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": "Invalid email or password"
            }
        )
    
    # If we get here, authentication was successful
    # Reset failed login attempts counter
    security.reset_failed_attempts(db, user.id)
    
    # Reset rate limiter counter
    rate_limiter.reset(rate_limit_key)
    
    # Check if TOTP is enabled for this user
    if user.totp_enabled:
        # Set session with pending TOTP verification
        request.session["pending_totp_verification"] = True
        request.session["email"] = user.email
        
        # Log login attempt with verification required
        security.log_login_attempt(db, email, client_ip, user.id, True, False, True)
        
        return RedirectResponse(url="/verify-totp-login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Check if MFA is required
    if user.mfa_enabled:
        # Generate verification code
        verification_code = security.generate_verification_code()
        
        # Store verification code
        security.create_verification_code(db, user.id, verification_code)
        
        # Send verification email
        email_service.send_verification_email(user.email, verification_code)
        
        # Set session with pending verification
        request.session["pending_verification"] = True
        request.session["email"] = user.email
        
        # Log login attempt with verification required
        security.log_login_attempt(db, email, client_ip, user.id, True, False, True)
        
        return RedirectResponse(url="/verify", status_code=status.HTTP_303_SEE_OTHER)
    
    # Set session
    request.session["user_id"] = user.id
    
    # Log successful login
    security.log_login_attempt(db, email, client_ip, user.id, True)
    security.log_activity(db, user.id, "Login", client_ip)
    
    # Reset rate limiter counter
    rate_limiter.reset(client_ip)
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, user: Optional[models.User] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request, 
    name: str = Form(...), 
    email: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    # Check if user already exists
    existing_user = db.query(models.User).filter(models.User.email == email).first()
    if existing_user:
        return templates.TemplateResponse(
            "register.html", 
            {
                "request": request, 
                "error": "Email already in use"
            }
        )
    
    try:
        # Validate password strength
        user_create = UserCreate(name=name, email=email, password=password)
    except ValueError as e:
        return templates.TemplateResponse(
            "register.html", 
            {
                "request": request, 
                "error": str(e)
            }
        )
    
    # Create user
    user = security.create_user(db, name, email, password)
    
    # Generate verification code
    verification_code = security.generate_verification_code()
    
    # Store verification code
    security.create_verification_code(db, user.id, verification_code)
    
    # Send verification email
    email_service.send_verification_email(email, verification_code)
    
    # Set session with pending verification
    request.session["pending_verification"] = True
    request.session["email"] = user.email
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Registration", client_ip)
    
    return RedirectResponse(url="/verify", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    if not request.session.get("pending_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    return templates.TemplateResponse("verify.html", {"request": request, "email": email, "error": None})

@app.post("/verify", response_class=HTMLResponse)
async def verify(
    request: Request, 
    code: str = Form(...), 
    db: Session = Depends(get_db)
):
    if not request.session.get("pending_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    
    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "verify.html", 
            {
                "request": request, 
                "email": email,
                "error": "User not found"
            }
        )
    
    # Verify code
    if not security.verify_code(db, user.id, code):
        return templates.TemplateResponse(
            "verify.html", 
            {
                "request": request, 
                "email": email,
                "error": "Invalid or expired verification code"
            }
        )
    
    # Set session
    request.session["user_id"] = user.id
    request.session.pop("pending_verification", None)
    request.session.pop("email", None)
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "MFA Verification", client_ip)
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/resend-code", response_class=HTMLResponse)
async def resend_code(request: Request, db: Session = Depends(get_db)):
    if not request.session.get("pending_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    
    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "verify.html", 
            {
                "request": request, 
                "email": email,
                "error": "User not found"
            }
        )
    
    # Delete existing verification codes
    db.query(models.VerificationCode).filter(models.VerificationCode.user_id == user.id).delete()
    db.commit()
    
    # Generate new verification code
    verification_code = security.generate_verification_code()
    
    # Store verification code
    security.create_verification_code(db, user.id, verification_code)
    
    # Send verification email
    email_service.send_verification_email(email, verification_code)
    
    return templates.TemplateResponse(
        "verify.html", 
        {
            "request": request, 
            "email": email,
            "message": "A new verification code has been sent to your email"
        }
    )

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(
    request: Request, 
    email: str = Form(...), 
    db: Session = Depends(get_db)
):
    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    
    # Don't reveal if user exists or not
    if user:
        # Delete existing reset tokens
        db.query(models.PasswordResetToken).filter(models.PasswordResetToken.user_id == user.id).delete()
        db.commit()
        
        # Generate reset token
        token = security.generate_reset_token()
        
        # Store reset token
        security.create_reset_token(db, user.id, token)
        
        # Send password reset email
        email_service.send_password_reset_email(email, token)
        
        # Log activity
        client_ip = request.client.host
        security.log_activity(db, user.id, "Password Reset Request", client_ip)
    
    return templates.TemplateResponse(
        "forgot_password_success.html", 
        {
            "request": request
        }
    )

@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str, db: Session = Depends(get_db)):
    # Validate token
    reset_token = db.query(models.PasswordResetToken).filter(models.PasswordResetToken.token == token).first()
    
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        if reset_token:
            db.delete(reset_token)
            db.commit()
        return templates.TemplateResponse(
            "reset_password_error.html", 
            {
                "request": request,
                "error": "Invalid or expired reset token"
            }
        )
    
    return templates.TemplateResponse(
        "reset_password.html", 
        {
            "request": request,
            "token": token
        }
    )

@app.post("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password(
    request: Request, 
    token: str, 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    # Validate token
    reset_token = db.query(models.PasswordResetToken).filter(models.PasswordResetToken.token == token).first()
    
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        if reset_token:
            db.delete(reset_token)
            db.commit()
        return templates.TemplateResponse(
            "reset_password_error.html", 
            {
                "request": request,
                "error": "Invalid or expired reset token"
            }
        )
    
    try:
        # Validate password strength
        password_reset = PasswordReset(password=password)
    except ValueError as e:
        return templates.TemplateResponse(
            "reset_password.html", 
            {
                "request": request,
                "token": token,
                "error": str(e)
            }
        )
    
    # Update user password
    user = db.query(models.User).filter(models.User.id == reset_token.user_id).first()
    user.password_hash = security.get_password_hash(password)
    user.updated_at = datetime.utcnow()
    
    # Delete reset token
    db.delete(reset_token)
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Password Reset", client_ip)
    
    return RedirectResponse(url="/login?reset=success", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request, 
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Get user activities
    activities = security.get_user_activities(db, user.id)
    
    # Get password health
    password_health_record = db.query(models.PasswordHealth).filter(
        models.PasswordHealth.user_id == user.id
    ).first()
    
    if password_health_record:
        # Update days until expiry
        password_health_record.days_until_expiry = password_health.calculate_password_expiry(
            password_health_record.last_changed
        )
        db.commit()
        
        # Get password health summary
        password_health_summary = password_health.get_password_health_summary(
            password_health_record.strength_score,
            password_health_record.has_been_breached,
            password_health_record.is_common,
            password_health_record.days_until_expiry,
            password_health_record.reused
        )
    else:
        password_health_summary = None
    
    return templates.TemplateResponse(
        "dashboard.html", 
        {
            "request": request,
            "user": user,
            "activities": activities,
            "password_health": password_health_summary
        }
    )

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# TOTP Routes
@app.get("/setup-totp", response_class=HTMLResponse)
async def setup_totp_page(request: Request, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Generate TOTP secret if not exists
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.commit()
    
    # Generate TOTP URI for QR code
    totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email, 
        issuer_name="SecureAuth"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return templates.TemplateResponse(
        "setup_totp.html", 
        {
            "request": request,
            "user": user,
            "qr_code": img_str,
            "secret": user.totp_secret
        }
    )

@app.post("/verify-totp", response_class=HTMLResponse)
async def verify_totp(
    request: Request,
    code: str = Form(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify TOTP code
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        # Generate QR code again for the error page
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
            name=user.email, 
            issuer_name="SecureAuth"
        )
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered)
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return templates.TemplateResponse(
            "setup_totp.html", 
            {
                "request": request,
                "user": user,
                "qr_code": img_str,
                "secret": user.totp_secret,
                "error": "Invalid verification code. Please try again."
            }
        )
    
    # Update user to indicate TOTP is set up
    user.totp_enabled = True
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "TOTP Setup", client_ip)
    
    return templates.TemplateResponse(
        "setup_totp.html", 
        {
            "request": request,
            "user": user,
            "message": "Authenticator app successfully set up! You will now be asked for a verification code when you log in."
        }
    )

@app.get("/verify-totp-login", response_class=HTMLResponse)
async def verify_totp_login_page(request: Request):
    # Check if there's a pending TOTP verification
    if not request.session.get("pending_totp_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    
    return templates.TemplateResponse(
        "verify_totp.html", 
        {
            "request": request,
            "email": email,
            "error": None
        }
    )

@app.post("/verify-totp-login", response_class=HTMLResponse)
async def verify_totp_login(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if there's a pending TOTP verification
    if not request.session.get("pending_totp_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    
    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "verify_totp.html", 
            {
                "request": request,
                "email": email,
                "error": "User not found"
            }
        )
    
    # Verify TOTP code
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        return templates.TemplateResponse(
            "verify_totp.html", 
            {
                "request": request,
                "email": email,
                "error": "Invalid verification code"
            }
        )
    
    # Set session
    request.session["user_id"] = user.id
    request.session.pop("pending_totp_verification", None)
    request.session.pop("email", None)
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "TOTP Verification", client_ip)
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

@app.get("/backup-codes", response_class=HTMLResponse)
async def backup_codes_page(
    request: Request, 
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Check if user has TOTP enabled
    if not user.totp_enabled:
        return RedirectResponse(url="/setup-totp", status_code=status.HTTP_303_SEE_OTHER)
    
    # Get existing backup codes
    backup_codes = security.get_unused_backup_codes(db, user.id)
    
    return templates.TemplateResponse(
        "backup_codes.html", 
        {
            "request": request,
            "user": user,
            "backup_codes": backup_codes,
            "has_codes": len(backup_codes) > 0
        }
    )

@app.post("/generate-backup-codes", response_class=HTMLResponse)
async def generate_backup_codes(
    request: Request, 
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Check if user has TOTP enabled
    if not user.totp_enabled:
        return RedirectResponse(url="/setup-totp", status_code=status.HTTP_303_SEE_OTHER)
    
    # Generate new backup codes
    backup_codes = security.create_backup_codes(db, user.id)
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Generated Backup Codes", client_ip)
    
    return templates.TemplateResponse(
        "backup_codes.html", 
        {
            "request": request,
            "user": user,
            "backup_codes": backup_codes,
            "new_codes": True,
            "has_codes": True
        }
    )

@app.get("/use-backup-code", response_class=HTMLResponse)
async def use_backup_code_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    
    if not request.session.get("pending_totp_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    
    return templates.TemplateResponse(
        "use_backup_code.html", 
        {
            "request": request,
            "email": email,
            "error": None
        }
    )

@app.post("/use-backup-code", response_class=HTMLResponse)
async def use_backup_code(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    if not request.session.get("pending_totp_verification"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    email = request.session.get("email")
    
    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "use_backup_code.html", 
            {
                "request": request,
                "email": email,
                "error": "User not found"
            }
        )
    
    # Verify backup code
    if not security.verify_backup_code(db, user.id, code):
        return templates.TemplateResponse(
            "use_backup_code.html", 
            {
                "request": request,
                "email": email,
                "error": "Invalid backup code"
            }
        )
    
    # Set session
    request.session["user_id"] = user.id
    request.session.pop("pending_totp_verification", None)
    request.session.pop("email", None)
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Used Backup Code", client_ip)
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/dashboard/security", response_class=HTMLResponse)
async def security_settings(
    request: Request, 
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    return render_security_settings(request, user, db)

@app.post("/toggle-mfa", response_class=HTMLResponse)
async def toggle_mfa(
    request: Request,
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Toggle MFA
    user.mfa_enabled = not user.mfa_enabled
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    action = "Enabled Email MFA" if user.mfa_enabled else "Disabled Email MFA"
    security.log_activity(db, user.id, action, client_ip)
    
    return render_security_settings(
        request, 
        user, 
        db, 
        mfa_success=f"Email verification has been {'enabled' if user.mfa_enabled else 'disabled'}"
    )
@app.post("/change-password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify current password
    if not security.verify_password(current_password, user.password_hash):
        # Get user activities related to security
        security_activities = db.query(models.Activity).filter(
            models.Activity.user_id == user.id,
            models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes"])
        ).order_by(models.Activity.timestamp.desc()).limit(10).all()
        
        # Get recent login attempts
        login_attempts = db.query(models.LoginAttempt).filter(
            models.LoginAttempt.email == user.email
        ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
        
        return templates.TemplateResponse(
            "security_settings.html", 
            {
                "request": request,
                "user": user,
                "security_activities": security_activities,
                "login_attempts": login_attempts,
                "password_error": "Current password is incorrect",
                "timedelta": timedelta  # Add timedelta to the template context
            }
        )
    
    # Verify new password matches confirmation
    if new_password != confirm_password:
        # Get user activities related to security
        security_activities = db.query(models.Activity).filter(
            models.Activity.user_id == user.id,
            models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes"])
        ).order_by(models.Activity.timestamp.desc()).limit(10).all()
        
        # Get recent login attempts
        login_attempts = db.query(models.LoginAttempt).filter(
            models.LoginAttempt.email == user.email
        ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
        
        return templates.TemplateResponse(
            "security_settings.html", 
            {
                "request": request,
                "user": user,
                "security_activities": security_activities,
                "login_attempts": login_attempts,
                "password_error": "New passwords do not match",
                "timedelta": timedelta  # Add timedelta to the template context
            }
        )
    
    try:
        # Validate password strength
        password_reset = PasswordReset(password=new_password)
    except ValueError as e:
        # Get user activities related to security
        security_activities = db.query(models.Activity).filter(
            models.Activity.user_id == user.id,
            models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes"])
        ).order_by(models.Activity.timestamp.desc()).limit(10).all()
        
        # Get recent login attempts
        login_attempts = db.query(models.LoginAttempt).filter(
            models.LoginAttempt.email == user.email
        ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
        
        return templates.TemplateResponse(
            "security_settings.html", 
            {
                "request": request,
                "user": user,
                "security_activities": security_activities,
                "login_attempts": login_attempts,
                "password_error": str(e),
                "timedelta": timedelta  # Add timedelta to the template context
            }
        )
    
    # Update password
    user.password_hash = security.get_password_hash(new_password)
    user.last_password_change = datetime.utcnow()
    user.updated_at = datetime.utcnow()
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Password Change", client_ip)
    
    # Get user activities related to security
    security_activities = db.query(models.Activity).filter(
        models.Activity.user_id == user.id,
        models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes"])
    ).order_by(models.Activity.timestamp.desc()).limit(10).all()
    
    # Get recent login attempts
    login_attempts = db.query(models.LoginAttempt).filter(
        models.LoginAttempt.email == user.email
    ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse(
        "security_settings.html", 
        {
            "request": request,
            "user": user,
            "security_activities": security_activities,
            "login_attempts": login_attempts,
            "password_success": "Your password has been updated successfully",
            "timedelta": timedelta  # Add timedelta to the template context
        }
    )

@app.post("/disable-totp", response_class=HTMLResponse)
async def disable_totp(
    request: Request,
    password: str = Form(...),
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify password
    if not security.verify_password(password, user.password_hash):
        # Get user activities related to security
        security_activities = db.query(models.Activity).filter(
            models.Activity.user_id == user.id,
            models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes"])
        ).order_by(models.Activity.timestamp.desc()).limit(10).all()
        
        # Get recent login attempts
        login_attempts = db.query(models.LoginAttempt).filter(
            models.LoginAttempt.email == user.email
        ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
        
        return templates.TemplateResponse(
            "security_settings.html", 
            {
                "request": request,
                "user": user,
                "security_activities": security_activities,
                "login_attempts": login_attempts,
                "totp_error": "Password is incorrect",
                "timedelta": timedelta  # Add timedelta to the template context
            }
        )
    
    # Disable TOTP
    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    
    # Delete backup codes
    db.query(models.BackupCode).filter(models.BackupCode.user_id == user.id).delete()
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Disabled TOTP", client_ip)
    
    # Get user activities related to security
    security_activities = db.query(models.Activity).filter(
        models.Activity.user_id == user.id,
        models.Activity.type.in_(["Login", "Failed Login", "Password Change", "TOTP Setup", "TOTP Verification", "Used Backup Code", "Generated Backup Codes"])
    ).order_by(models.Activity.timestamp.desc()).limit(10).all()
    
    # Get recent login attempts
    login_attempts = db.query(models.LoginAttempt).filter(
        models.LoginAttempt.email == user.email
    ).order_by(models.LoginAttempt.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse(
        "security_settings.html", 
        {
            "request": request,
            "user": user,
            "security_activities": security_activities,
            "login_attempts": login_attempts,
            "totp_success": "Authenticator app verification has been disabled",
            "timedelta": timedelta  # Add timedelta to the template context
        }
    )

@app.post("/unlock-account", response_class=HTMLResponse)
async def unlock_account(
    request: Request,
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user or not user.account_locked:
        return RedirectResponse(url="/dashboard/security", status_code=status.HTTP_303_SEE_OTHER)
    
    # Unlock the account
    security.unlock_account(db, user.id)
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Account Unlocked", client_ip)
    
    return render_security_settings(
        request, 
        user, 
        db, 
        account_success="Your account has been unlocked successfully"
    )

@app.get("/dashboard/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request, 
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    success_message = None
    if request.session.get("email_change_success"):
        success_message = "Your email has been successfully updated"
        request.session.pop("email_change_success", None)
    
    return templates.TemplateResponse(
        "profile.html", 
        {
            "request": request,
            "user": user,
            "success_message": success_message,
            "error": None
        }
    )

@app.post("/dashboard/profile", response_class=HTMLResponse)
async def update_profile(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    current_password: Optional[str] = Form(None),
    new_password: Optional[str] = Form(None),
    confirm_password: Optional[str] = Form(None),
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Initialize messages
    success_message = None
    error = None
    
    # Check if email is being changed
    email_changed = email != user.email
    if email_changed:
        # Check if email is already in use
        existing_user = db.query(models.User).filter(
            models.User.email == email, 
            models.User.id != user.id
        ).first()
        
        if existing_user:
            error = "Email is already in use by another account"
            return templates.TemplateResponse(
                "profile.html", 
                {
                    "request": request,
                    "user": user,
                    "success_message": success_message,
                    "error": error
                }
            )
        
        # Store the new email in a pending state
        # First, delete any existing pending email changes
        db.query(models.PendingEmailChange).filter(
            models.PendingEmailChange.user_id == user.id
        ).delete()
        
        # Generate verification code
        verification_code = security.generate_verification_code()
        
        # Create pending email change record
        pending_change = models.PendingEmailChange(
            user_id=user.id,
            new_email=email,
            verification_code=verification_code,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.add(pending_change)
        db.commit()
        
        # Send verification email to the new address
        email_service.send_email_change_verification(email, verification_code)
        
        # Log activity
        client_ip = request.client.host
        security.log_activity(db, user.id, "Email Change Requested", client_ip)
        
        # Update only the name for now
        user.name = name
        user.updated_at = datetime.utcnow()
        db.commit()
        
        # Redirect to email verification page
        request.session["pending_email_verification"] = True
        request.session["new_email"] = email
        
        return RedirectResponse(
            url="/dashboard/verify-email-change", 
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    # Update basic info (just name if email hasn't changed)
    user.name = name
    user.updated_at = datetime.utcnow()
    success_message = "Profile updated successfully"
    
    # Handle password change if requested
    if current_password and new_password and confirm_password:
        # Verify current password
        if not security.verify_password(current_password, user.password_hash):
            error = "Current password is incorrect"
            return templates.TemplateResponse(
                "profile.html", 
                {
                    "request": request,
                    "user": user,
                    "success_message": success_message,
                    "error": error
                }
            )
        
        # Verify new passwords match
        if new_password != confirm_password:
            error = "New passwords do not match"
            return templates.TemplateResponse(
                "profile.html", 
                {
                    "request": request,
                    "user": user,
                    "success_message": success_message,
                    "error": error
                }
            )
        
        # Validate password strength
        try:
            password_reset = PasswordReset(password=new_password)
            user.password_hash = security.get_password_hash(new_password)
            success_message = "Profile and password updated successfully"
            
            # Log activity
            client_ip = request.client.host
            security.log_activity(db, user.id, "Password Change", client_ip)
        except ValueError as e:
            error = str(e)
            return templates.TemplateResponse(
                "profile.html", 
                {
                    "request": request,
                    "user": user,
                    "success_message": success_message,
                    "error": error
                }
            )
    
    # Save changes
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Profile Update", client_ip)
    
    return templates.TemplateResponse(
        "profile.html", 
        {
            "request": request,
            "user": user,
            "success_message": success_message,
            "error": error
        }
    )

@app.get("/dashboard/verify-email-change", response_class=HTMLResponse)
async def verify_email_change_page(
    request: Request,
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user or not request.session.get("pending_email_verification"):
        return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)
    
    new_email = request.session.get("new_email")
    
    # Check if there's a pending change
    pending_change = db.query(models.PendingEmailChange).filter(
        models.PendingEmailChange.user_id == user.id,
        models.PendingEmailChange.new_email == new_email
    ).first()
    
    if not pending_change:
        request.session.pop("pending_email_verification", None)
        request.session.pop("new_email", None)
        return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(
        "verify_email_change.html", 
        {
            "request": request,
            "user": user,
            "new_email": new_email,
            "error": None
        }
    )

@app.post("/dashboard/verify-email-change", response_class=HTMLResponse)
async def verify_email_change(
    request: Request,
    code: str = Form(...),
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user or not request.session.get("pending_email_verification"):
        return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)
    
    new_email = request.session.get("new_email")
    
    # Check if there's a pending change
    pending_change = db.query(models.PendingEmailChange).filter(
        models.PendingEmailChange.user_id == user.id,
        models.PendingEmailChange.new_email == new_email,
        models.PendingEmailChange.expires_at > datetime.utcnow()
    ).first()
    
    if not pending_change:
        request.session.pop("pending_email_verification", None)
        request.session.pop("new_email", None)
        return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify the code
    if pending_change.verification_code != code:
        return templates.TemplateResponse(
            "verify_email_change.html", 
            {
                "request": request,
                "user": user,
                "new_email": new_email,
                "error": "Invalid verification code"
            }
        )
    
    # Update the user's email
    old_email = user.email
    user.email = pending_change.new_email
    user.updated_at = datetime.utcnow()
    
    # Delete the pending change
    db.delete(pending_change)
    db.commit()
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, f"Email Changed from {old_email} to {new_email}", client_ip)
    
    # Clear session variables
    request.session.pop("pending_email_verification", None)
    request.session.pop("new_email", None)
    
    # Redirect to profile with success message
    request.session["email_change_success"] = True
    
    return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/dashboard/resend-email-verification", response_class=HTMLResponse)
async def resend_email_verification(
    request: Request,
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user or not request.session.get("pending_email_verification"):
        return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)
    
    new_email = request.session.get("new_email")
    
    # Check if there's a pending change
    pending_change = db.query(models.PendingEmailChange).filter(
        models.PendingEmailChange.user_id == user.id,
        models.PendingEmailChange.new_email == new_email
    ).first()
    
    if not pending_change:
        request.session.pop("pending_email_verification", None)
        request.session.pop("new_email", None)
        return RedirectResponse(url="/dashboard/profile", status_code=status.HTTP_303_SEE_OTHER)
    
    # Generate new verification code
    verification_code = security.generate_verification_code()
    
    # Update pending change
    pending_change.verification_code = verification_code
    pending_change.expires_at = datetime.utcnow() + timedelta(hours=24)
    db.commit()
    
    # Send verification email
    email_service.send_email_change_verification(new_email, verification_code)
    
    return templates.TemplateResponse(
        "verify_email_change.html", 
        {
            "request": request,
            "user": user,
            "new_email": new_email,
            "message": "A new verification code has been sent to your email",
            "error": None
        }
    )

@app.post("/dashboard/delete-account", response_class=HTMLResponse)
async def delete_account(
    request: Request,
    password: str = Form(...),
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify password
    if not security.verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "profile.html", 
            {
                "request": request,
                "user": user,
                "success_message": None,
                "error": "Incorrect password. Account deletion cancelled."
            }
        )
    
    # Log the deletion
    client_ip = request.client.host
    security.log_activity(db, user.id, "Account Deletion", client_ip)
    
    # Delete the user (this will cascade to related records due to our model setup)
    db.delete(user)
    db.commit()
    
    # Clear session
    request.session.clear()
    
    # Redirect to home with message
    response = RedirectResponse(url="/?deleted=true", status_code=status.HTTP_303_SEE_OTHER)
    return response

@app.get("/dashboard/password-health", response_class=HTMLResponse)
async def password_health_page(
    request: Request, 
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Get password health record
    password_health_record = db.query(models.PasswordHealth).filter(
        models.PasswordHealth.user_id == user.id
    ).first()
    
    if not password_health_record:
        # Create a default record if none exists
        strength_score, _ = password_health.check_password_strength("dummy_password")  # We can't check the actual password
        password_health_record = models.PasswordHealth(
            user_id=user.id,
            strength_score=strength_score,
            has_been_breached=False,
            is_common=False,
            last_changed=user.updated_at or user.created_at,
            days_until_expiry=90,
            reused=False
        )
        db.add(password_health_record)
        db.commit()
        db.refresh(password_health_record)
    
    # Update days until expiry
    password_health_record.days_until_expiry = password_health.calculate_password_expiry(
        password_health_record.last_changed
    )
    db.commit()
    
    # Get password health summary
    health_summary = password_health.get_password_health_summary(
        password_health_record.strength_score,
        password_health_record.has_been_breached,
        password_health_record.is_common,
        password_health_record.days_until_expiry,
        password_health_record.reused
    )
    
    # Get password history
    password_history = db.query(models.PasswordHistory).filter(
        models.PasswordHistory.user_id == user.id
    ).order_by(models.PasswordHistory.created_at.desc()).all()
    
    return templates.TemplateResponse(
        "password_health.html", 
        {
            "request": request,
            "user": user,
            "health": health_summary,
            "password_history": password_history,
            "success_message": request.session.pop("password_success_message", None),
            "error": request.session.pop("password_error", None)
        }
    )

@app.post("/dashboard/change-password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: Optional[models.User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify current password
    if not security.verify_password(current_password, user.password_hash):
        request.session["password_error"] = "Current password is incorrect"
        return RedirectResponse(url="/dashboard/password-health", status_code=status.HTTP_303_SEE_OTHER)
    
    # Check if new password matches confirmation
    if new_password != confirm_password:
        request.session["password_error"] = "New password and confirmation do not match"
        return RedirectResponse(url="/dashboard/password-health", status_code=status.HTTP_303_SEE_OTHER)
    
    try:
        # Validate password strength
        password_reset = PasswordReset(password=new_password)
    except ValueError as e:
        request.session["password_error"] = str(e)
        return RedirectResponse(url="/dashboard/password-health", status_code=status.HTTP_303_SEE_OTHER)
    
    # Update password
    security.update_password(db, user.id, new_password)
    
    # Log activity
    client_ip = request.client.host
    security.log_activity(db, user.id, "Password Changed", client_ip)
    
    request.session["password_success_message"] = "Password changed successfully"
    return RedirectResponse(url="/dashboard/password-health", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/dashboard/check-password-strength", response_class=HTMLResponse)
async def check_password_strength(
    request: Request,
    password: str,
    user: Optional[models.User] = Depends(get_current_user)
):
    if not user:
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    
    # Check password strength
    strength_score, issues = password_health.check_password_strength(password)
    
    # Check if password has been breached
    has_been_breached, breach_count = password_health.check_password_breach(password)
    
    # Check if password is common
    is_common = password_health.check_common_password(password)
    
    return JSONResponse(content={
        "score": strength_score,
        "issues": issues,
        "has_been_breached": has_been_breached,
        "breach_count": breach_count,
        "is_common": is_common
    })