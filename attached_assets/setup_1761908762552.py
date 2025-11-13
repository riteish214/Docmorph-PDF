#!/usr/bin/env python3
"""
DocMorph Setup Script
Installs dependencies and sets up the application
"""

import subprocess
import sys
import os

def install_requirements():
    """Install Python requirements"""
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python dependencies installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing Python dependencies: {e}")
        return False
    return True

def check_tesseract():
    """Check if Tesseract OCR is installed"""
    print("Checking for Tesseract OCR...")
    try:
        import pytesseract
        # Try to get version
        version = pytesseract.get_tesseract_version()
        print(f"✅ Tesseract OCR found (version: {version})")
        return True
    except Exception as e:
        print("❌ Tesseract OCR not found or not properly configured")
        print("Please install Tesseract OCR:")
        print("  Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki")
        print("  macOS: brew install tesseract")
        print("  Ubuntu/Debian: sudo apt-get install tesseract-ocr")
        print("  CentOS/RHEL: sudo yum install tesseract")
        return False

def create_directories():
    """Create necessary directories"""
    print("Creating necessary directories...")
    directories = ['uploads', 'temp', 'static/qr_codes']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✅ Created directory: {directory}")
        else:
            print(f"✅ Directory already exists: {directory}")

def main():
    """Main setup function"""
    print("🚀 DocMorph Setup")
    print("=" * 50)
    
    # Create directories
    create_directories()
    
    # Install Python requirements
    if not install_requirements():
        print("❌ Setup failed during dependency installation")
        return False
    
    # Check Tesseract
    tesseract_ok = check_tesseract()
    
    print("\n" + "=" * 50)
    if tesseract_ok:
        print("✅ Setup completed successfully!")
        print("\nTo run the application:")
        print("  python app.py")
    else:
        print("⚠️  Setup completed with warnings!")
        print("OCR functionality will not work until Tesseract is installed.")
        print("\nTo run the application:")
        print("  python app.py")
    
    return True

if __name__ == "__main__":
    main()
