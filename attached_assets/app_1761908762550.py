import os
import logging
import tempfile
import shutil
import uuid
import qrcode
import io
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# Import models and utilities
from models import db, User, SharedFile, PDFProcessingJob
from utils.pdf_processor import PDFProcessor
from utils.file_converter import FileConverter
from utils.qr_generator import QRGenerator
from utils.ocr_processor import OCRProcessor

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the Flask app instance
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Database configuration
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # Use SQLite as fallback if no DATABASE_URL is set
    database_url = 'sqlite:///pdfsurgeon.db'

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File upload configuration
UPLOAD_FOLDER = 'uploads'
SHARED_FOLDER = 'shared_files'
QR_FOLDER = 'qr_codes'
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'csv'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SHARED_FOLDER'] = SHARED_FOLDER
app.config['QR_FOLDER'] = QR_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create directories
for folder in [UPLOAD_FOLDER, SHARED_FOLDER, QR_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Initialize utilities
pdf_processor = PDFProcessor()
file_converter = FileConverter()
qr_generator = QRGenerator()
ocr_processor = OCRProcessor()

# Optional HTTPS enforcement (set FORCE_HTTPS=1 in env for prod)
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', '0') == '1'

@app.before_request
def enforce_https_in_production():
    if not FORCE_HTTPS:
        return
    if request.is_secure:
        return
    # Respect reverse proxy headers
    if request.headers.get('X-Forwarded-Proto', 'http') == 'https':
        return
    url = request.url.replace('http://', 'https://', 1)
    return redirect(url, code=301)

@app.after_request
def set_security_headers(response):
    # Prevent content-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Clickjacking protection
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Basic referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Minimal permissions policy inc. camera for QR modal
    response.headers['Permissions-Policy'] = 'camera=(self)'
    # Content Security Policy tuned for this app
    csp = (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Add security headers for file downloads
    if request.endpoint and 'api' in request.endpoint:
        response.headers['X-Download-Options'] = 'noopen'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    # HSTS when running on HTTPS
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Main routes
@app.route('/')
def index():
    """Home page with tool overview"""
    return render_template('index.html')

@app.route('/tools')
def tools():
    """PDF tools page"""
    return render_template('tools.html')

@app.route('/share')
def share():
    """File sharing page"""
    return render_template('share.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    """User logout"""
    logout_user()
    return redirect(url_for('index'))

# PDF Processing API endpoints
@app.route('/api/pdf/merge', methods=['POST'])
def api_merge_pdf():
    """Merge multiple PDF files"""
    try:
        files = request.files.getlist('files')
        if len(files) < 2:
            return jsonify({'error': 'Please select at least 2 PDF files'}), 400
        
        # Save uploaded files temporarily
        temp_files = []
        for file in files:
            if file.filename.lower().endswith('.pdf'):
                temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
                file.save(temp_path)
                temp_files.append(temp_path)
        
        # Merge PDFs
        output_path = pdf_processor.merge_pdfs(temp_files)
        
        # Clean up temp files
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        return send_file(output_path, as_attachment=True, download_name='merged.pdf')
    
    except Exception as e:
        logging.error(f"Error merging PDFs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/pdf/split', methods=['POST'])
def api_split_pdf():
    """Split PDF into individual pages"""
    try:
        file = request.files['file']
        if not file.filename.lower().endswith('.pdf'):
            return jsonify({'error': 'Please select a PDF file'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(temp_path)
        
        # Split PDF
        output_zip = pdf_processor.split_pdf(temp_path)
        
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return send_file(output_zip, as_attachment=True, download_name='split_pages.zip')
    
    except Exception as e:
        logging.error(f"Error splitting PDF: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/pdf/compress', methods=['POST'])
def api_compress_pdf():
    """Compress PDF file"""
    try:
        file = request.files['file']
        if not file.filename.lower().endswith('.pdf'):
            return jsonify({'error': 'Please select a PDF file'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(temp_path)
        
        # Compress PDF
        output_path = pdf_processor.compress_pdf(temp_path)
        
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return send_file(output_path, as_attachment=True, download_name='compressed.pdf')
    
    except Exception as e:
        logging.error(f"Error compressing PDF: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/convert', methods=['POST'])
def api_convert_file():
    """Convert between different file formats"""
    try:
        file = request.files['file']
        conversion_type = request.form.get('conversion_type')
        
        if not file or not conversion_type:
            return jsonify({'error': 'File and conversion type are required'}), 400
        
        # Validate file type
        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(temp_path)
        
        # Perform conversion
        output_path = file_converter.convert_file(temp_path, conversion_type)
        
        # Generate proper output filename
        base_name = os.path.splitext(filename)[0]
        output_extension = get_output_extension(conversion_type)
        output_filename = f"{base_name}_converted{output_extension}"
        
        # Clean up input file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return send_file(output_path, as_attachment=True, download_name=output_filename)
    
    except Exception as e:
        logging.error(f"Error converting file: {str(e)}")
        # Clean up temp files on error
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': str(e)}), 500

def get_output_extension(conversion_type):
    """Get output file extension based on conversion type"""
    extension_map = {
        'pdf_to_docx': '.docx',
        'pdf_to_txt': '.txt',
        'pdf_to_csv': '.csv',
        'docx_to_pdf': '.pdf',
        'txt_to_pdf': '.pdf',
        'csv_to_pdf': '.pdf',
        'pptx_to_pdf': '.pdf'
    }
    return extension_map.get(conversion_type, '.pdf')

@app.route('/api/pdf/encrypt', methods=['POST'])
def api_encrypt_pdf():
    """Add password protection to PDF"""
    try:
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(temp_path)
        
        # Encrypt PDF
        output_path = pdf_processor.encrypt_pdf(temp_path, password)
        
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return send_file(output_path, as_attachment=True, download_name='protected.pdf')
    
    except Exception as e:
        logging.error(f"Error encrypting PDF: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/pdf/decrypt', methods=['POST'])
def api_decrypt_pdf():
    """Remove password protection from PDF"""
    try:
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(temp_path)
        
        # Decrypt PDF
        output_path = pdf_processor.decrypt_pdf(temp_path, password)
        
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return send_file(output_path, as_attachment=True, download_name='decrypted.pdf')
    
    except Exception as e:
        logging.error(f"Error decrypting PDF: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ocr', methods=['POST'])
def api_ocr_extract():
    """Extract text from PDF using OCR"""
    try:
        file = request.files['file']
        
        if not file:
            return jsonify({'error': 'File is required'}), 400
        
        # Validate file type
        filename = secure_filename(file.filename)
        if not filename.lower().endswith('.pdf'):
            return jsonify({'error': 'Only PDF files are supported for OCR'}), 400
        
        temp_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(temp_path)
        
        # Process PDF with OCR
        extracted_text = ocr_processor.process_pdf_with_ocr(temp_path)
        
        # Save text to file
        base_name = os.path.splitext(filename)[0]
        output_filename = f"{base_name}_extracted_text.txt"
        output_path = os.path.join(tempfile.gettempdir(), output_filename)
        ocr_processor.save_text_to_file(extracted_text, output_path)
        
        # Clean up input file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return send_file(output_path, as_attachment=True, download_name=output_filename)
    
    except Exception as e:
        logging.error(f"Error processing OCR: {str(e)}")
        # Clean up temp files on error
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': str(e)}), 500

# File Sharing API endpoints
@app.route('/api/share/upload', methods=['POST'])
def api_share_upload():
    """Upload file for sharing"""
    try:
        file = request.files.get('file')
        text_content = request.form.get('text_content')
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        expiry_hours = int(request.form.get('expiry_hours', 24))
        max_downloads = request.form.get('max_downloads')
        access_password = request.form.get('access_password')
        
        if not file and not text_content:
            return jsonify({'error': 'Please provide a file or text content'}), 400
        
        # Create shared file record
        shared_file = SharedFile(
            title=title,
            description=description,
            user_id=current_user.id if current_user.is_authenticated else None
        )
        
        # Set expiry
        shared_file.set_expiry(expiry_hours)
        
        # Set download limit
        if max_downloads:
            shared_file.max_downloads = int(max_downloads)
        
        # Set access password
        if access_password:
            shared_file.set_access_password(access_password)
        
        if file:
            # Handle file upload
            filename = secure_filename(file.filename)
            file_path = os.path.join(SHARED_FOLDER, f"{shared_file.access_code}_{filename}")
            file.save(file_path)
            
            shared_file.filename = filename
            shared_file.original_filename = file.filename
            shared_file.file_type = file.content_type or 'application/octet-stream'
            shared_file.file_size = os.path.getsize(file_path)
            shared_file.file_path = file_path
            shared_file.is_text_content = False
        else:
            # Handle text content
            shared_file.filename = f"text_{shared_file.access_code}.txt"
            shared_file.original_filename = f"{title or 'Shared Text'}.txt"
            shared_file.file_type = 'text/plain'
            shared_file.text_content = text_content
            shared_file.is_text_content = True

            # Persist text content to file to satisfy NOT NULL columns and for consistency
            text_file_path = os.path.join(SHARED_FOLDER, f"{shared_file.access_code}_{shared_file.filename}")
            os.makedirs(os.path.dirname(text_file_path), exist_ok=True)
            with open(text_file_path, 'w', encoding='utf-8') as f:
                f.write(text_content or '')
            shared_file.file_path = text_file_path
            shared_file.file_size = os.path.getsize(text_file_path)
        
        # Generate QR code
        qr_path = qr_generator.generate_qr_code(
            shared_file.access_code,
            os.path.join(QR_FOLDER, f"{shared_file.access_code}.png")
        )
        shared_file.qr_code_path = qr_path
        
        db.session.add(shared_file)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'access_code': shared_file.access_code,
            'qr_code_url': url_for('get_qr_code', code=shared_file.access_code),
            'share_url': url_for('access_shared_file', code=shared_file.access_code, _external=True),
            'expires_at': shared_file.expires_at.isoformat() if shared_file.expires_at else None
        })
    
    except Exception as e:
        logging.error(f"Error sharing file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/shared/<code>')
def access_shared_file(code):
    """Access shared file by code"""
    shared_file = SharedFile.query.filter_by(access_code=code).first_or_404()
    
    if not shared_file.can_access():
        flash('This file has expired or reached its download limit', 'error')
        return render_template('shared/expired.html')
    
    if shared_file.password_protected:
        return render_template('shared/password.html', code=code)
    
    return render_template('shared/access.html', shared_file=shared_file)

@app.route('/shared/<code>/verify', methods=['POST'])
def verify_shared_file_password(code):
    """Verify password for protected shared file"""
    shared_file = SharedFile.query.filter_by(access_code=code).first_or_404()
    password = request.form.get('password')
    
    if shared_file.check_access_password(password):
        session[f'verified_{code}'] = True
        return redirect(url_for('access_shared_file', code=code))
    else:
        flash('Incorrect password', 'error')
        return render_template('shared/password.html', code=code)

@app.route('/shared/<code>/download')
def download_shared_file(code):
    """Download shared file"""
    shared_file = SharedFile.query.filter_by(access_code=code).first_or_404()
    
    if not shared_file.can_access():
        flash('This file has expired or reached its download limit', 'error')
        return redirect(url_for('access_shared_file', code=code))
    
    if shared_file.password_protected and not session.get(f'verified_{code}'):
        flash('Password verification required', 'error')
        return redirect(url_for('access_shared_file', code=code))
    
    # Record access
    shared_file.record_access()
    
    if shared_file.is_text_content:
        # Create temporary file for text content
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        temp_file.write(shared_file.text_content)
        temp_file.close()
        return send_file(temp_file.name, as_attachment=True, download_name=shared_file.filename)
    else:
        return send_file(shared_file.file_path, as_attachment=True, download_name=shared_file.original_filename)

@app.route('/qr/<code>')
def get_qr_code(code):
    """Get QR code image"""
    shared_file = SharedFile.query.filter_by(access_code=code).first_or_404()
    return send_file(shared_file.qr_code_path, mimetype='image/png')

# Error handlers
@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum file size is 1GB.', 'error')
    return redirect(request.referrer or url_for('index'))

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


    