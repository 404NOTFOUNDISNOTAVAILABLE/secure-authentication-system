import re
import hashlib
import requests
from typing import Dict, Any, Tuple, List
from datetime import datetime, timedelta
from passlib.context import CryptContext

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def check_password_strength(password: str) -> Tuple[int, List[str]]:
    """
    Check password strength and return a score (0-100) and list of issues.
    """
    score = 0
    issues = []
    
    # Length check
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
        issues.append("Password should be at least 12 characters long for better security.")
    else:
        issues.append("Password is too short. Use at least 8 characters.")
    
    # Complexity checks
    if re.search(r'[A-Z]', password):
        score += 10
    else:
        issues.append("Add uppercase letters to your password.")
        
    if re.search(r'[a-z]', password):
        score += 10
    else:
        issues.append("Add lowercase letters to your password.")
        
    if re.search(r'[0-9]', password):
        score += 10
    else:
        issues.append("Add numbers to your password.")
        
    if re.search(r'[^A-Za-z0-9]', password):
        score += 15
    else:
        issues.append("Add special characters to your password.")
    
    # Check for common patterns
    common_patterns = [
        r'12345', r'qwerty', r'password', r'admin', r'welcome',
        r'123123', r'abcabc', r'abc123', r'password123'
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            score -= 15
            issues.append("Your password contains common patterns that are easy to guess.")
            break
    
    # Check for sequential characters
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        score -= 10
        issues.append("Your password contains sequential letters.")
    
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        score -= 10
        issues.append("Your password contains sequential numbers.")
    
    # Ensure score is within 0-100 range
    score = max(0, min(score, 100))
    
    return score, issues

def check_password_breach(password: str) -> Tuple[bool, int]:
    """
    Check if password has been exposed in data breaches using the HaveIBeenPwned API.
    Returns a tuple of (breached, count).
    
    This uses the k-anonymity model so the full password is never sent to the API.
    """
    # Hash the password with SHA-1
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Get the first 5 characters of the hash (prefix)
    prefix = password_hash[:5]
    
    # Get the rest of the hash (suffix)
    suffix = password_hash[5:]
    
    try:
        # Query the API with just the prefix
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        
        if response.status_code != 200:
            # If API call fails, assume not breached for safety
            return False, 0
        
        # Check if the suffix is in the response
        hashes = (line.split(':') for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return True, int(count)
        
        return False, 0
    except Exception:
        # If any error occurs, assume not breached for safety
        return False, 0

def check_common_password(password: str) -> bool:
    """
    Check if the password is in a list of common passwords.
    In a real implementation, you would use a more comprehensive list.
    """
    common_passwords = [
        "password", "123456", "qwerty", "admin", "welcome",
        "password123", "abc123", "letmein", "monkey", "1234567890",
        "trustno1", "dragon", "baseball", "football", "superman",
        "iloveyou", "starwars", "master", "hello", "freedom"
    ]
    
    return password.lower() in common_passwords

def is_password_reused(password: str, password_history: List[str], pwd_context: CryptContext) -> bool:
    """
    Check if the password has been used before.
    """
    for old_hash in password_history:
        if pwd_context.verify(password, old_hash):
            return True
    return False

def calculate_password_expiry(last_changed: datetime, expiry_days: int = 90) -> int:
    """
    Calculate days until password expiry.
    """
    expiry_date = last_changed + timedelta(days=expiry_days)
    days_left = (expiry_date - datetime.utcnow()).days
    return max(0, days_left)

def get_password_health_summary(
    strength_score: int,
    has_been_breached: bool,
    is_common: bool,
    days_until_expiry: int,
    reused: bool
) -> Dict[str, Any]:
    """
    Generate a summary of password health.
    """
    status = "Good"
    issues = []
    recommendations = []
    
    if strength_score < 50:
        status = "Poor"
        issues.append("Your password is weak")
        recommendations.append("Create a stronger password with a mix of characters")
    
    if has_been_breached:
        status = "Critical"
        issues.append("Your password has been exposed in data breaches")
        recommendations.append("Change your password immediately")
    
    if is_common:
        status = "Poor"
        issues.append("Your password is commonly used and easy to guess")
        recommendations.append("Choose a more unique password")
    
    if days_until_expiry <= 14 and days_until_expiry > 0:
        issues.append(f"Your password will expire in {days_until_expiry} days")
        recommendations.append("Consider changing your password soon")
    elif days_until_expiry <= 0:
        status = "Warning"
        issues.append("Your password has expired")
        recommendations.append("Change your password now")
    
    if reused:
        status = "Warning"
        issues.append("You've used this password before")
        recommendations.append("Use a completely new password for better security")
    
    # Overall health score calculation
    health_score = strength_score
    
    if has_been_breached:
        health_score = max(0, health_score - 50)
    
    if is_common:
        health_score = max(0, health_score - 30)
    
    if reused:
        health_score = max(0, health_score - 20)
    
    if days_until_expiry <= 0:
        health_score = max(0, health_score - 10)
    
    return {
        "status": status,
        "score": health_score,
        "strength_score": strength_score,
        "issues": issues,
        "recommendations": recommendations,
        "has_been_breached": has_been_breached,
        "is_common": is_common,
        "days_until_expiry": days_until_expiry,
        "reused": reused
    }