import os
import secrets
import string
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta

# Storage for active codes: {code_upper: {'type': 'file'|'text', 'file_path'?: str, 'filename'?: str, 'content'?: str, 'created_at': datetime}}
_active_codes = {}
_lock = threading.Lock()
_expiry_minutes = 15

def generate_code(length=6):
    """Generate a random alphanumeric code of specified length (5-8 chars)"""
    if length < 5:
        length = 5
    elif length > 8:
        length = 8
    
    # Use alphanumeric characters (0-9, A-Z)
    characters = string.ascii_uppercase + string.digits
    # Avoid ambiguous characters: 0, O, 1, I
    characters = characters.replace('0', '').replace('O', '').replace('1', '').replace('I', '')
    
    while True:
        code = ''.join(secrets.choice(characters) for _ in range(length))
        code_upper = code.upper()
        
        with _lock:
            # Check if code already exists, if so generate new one
            if code_upper not in _active_codes:
                return code

def normalize_code(code):
    """Normalize code to uppercase for case-insensitive comparison"""
    if code:
        return code.upper().strip()
    return None

def register_file(code, file_path, filename):
    """Register a file with a code"""
    code_upper = normalize_code(code)
    if not code_upper:
        return False
    
    with _lock:
        _active_codes[code_upper] = {
            'type': 'file',
            'file_path': file_path,
            'filename': filename,
            'created_at': datetime.now()
        }
    return True

def register_text(code, content):
    """Register text content with a code"""
    code_upper = normalize_code(code)
    if not code_upper:
        return False
    
    with _lock:
        _active_codes[code_upper] = {
            'type': 'text',
            'content': content,
            'created_at': datetime.now()
        }
    return True

def get_file_info(code):
    """Get file/text info for a code, return None if not found or expired"""
    code_upper = normalize_code(code)
    if not code_upper:
        return None
    
    with _lock:
        if code_upper not in _active_codes:
            return None
        
        info = _active_codes[code_upper]
        created_at = info['created_at']
        
        # Check if expired (15 minutes)
        if datetime.now() - created_at > timedelta(minutes=_expiry_minutes):
            # Code expired, remove it
            _remove_code(code_upper)
            return None
        
        return info.copy()

def delete_code(code):
    """Delete a code and its associated file"""
    code_upper = normalize_code(code)
    if not code_upper:
        return False
    
    with _lock:
        return _remove_code(code_upper)

def _remove_code(code_upper):
    """Internal method to remove code and delete file if applicable. Must be called with lock held."""
    if code_upper not in _active_codes:
        return False
    
    info = _active_codes[code_upper]
    
    # Remove from active codes
    del _active_codes[code_upper]
    
    # Delete file only if it's a file type
    if info.get('type') == 'file':
        file_path = info.get('file_path')
        try:
            if file_path:
                # Normalize path for Windows compatibility
                file_path = os.path.normpath(os.path.abspath(file_path))
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                # Try to remove parent directory if empty
                file_dir = os.path.dirname(file_path)
                if os.path.exists(file_dir):
                    try:
                        # Only remove if directory is empty
                        if not os.listdir(file_dir):
                            os.rmdir(file_dir)
                            
                            # Try to remove codes directory if empty
                            codes_dir = os.path.dirname(file_dir)
                            if os.path.exists(codes_dir):
                                try:
                                    if not os.listdir(codes_dir):
                                        os.rmdir(codes_dir)
                                except (OSError, PermissionError):
                                    # Directory not empty or permission denied, skip
                                    pass
                    except (OSError, PermissionError):
                        # Directory not empty or permission denied, skip
                        pass
        except Exception as e:
            # Log error but continue
            print(f"Error deleting file for code {code_upper}: {e}")
    # For text type, no file deletion needed
    
    return True

def cleanup_expired_codes():
    """Remove all expired codes and their files"""
    current_time = datetime.now()
    expired_codes = []
    
    with _lock:
        for code_upper, file_info in list(_active_codes.items()):
            created_at = file_info['created_at']
            if current_time - created_at > timedelta(minutes=_expiry_minutes):
                expired_codes.append(code_upper)
    
    # Remove expired codes (outside lock to avoid holding lock during file deletion)
    count = 0
    for code_upper in expired_codes:
        with _lock:
            if _remove_code(code_upper):
                count += 1
    
    return count

