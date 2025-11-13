from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    shared_files = db.relationship('SharedFile', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    
    # Sharing details
    access_code = db.Column(db.String(10), unique=True, nullable=False)
    qr_code_path = db.Column(db.String(500))
    
    # Metadata
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    is_text_content = db.Column(db.Boolean, default=False)
    text_content = db.Column(db.Text)  # For direct text sharing
    
    # Access control
    password_protected = db.Column(db.Boolean, default=False)
    access_password_hash = db.Column(db.String(256))
    download_count = db.Column(db.Integer, default=0)
    max_downloads = db.Column(db.Integer)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    last_accessed = db.Column(db.DateTime)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Anonymous uploads allowed
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.access_code:
            self.access_code = self.generate_access_code()
    
    @staticmethod
    def generate_access_code(length=8):
        """Generate a unique access code"""
        while True:
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) 
                         for _ in range(length))
            if not SharedFile.query.filter_by(access_code=code).first():
                return code
    
    def set_access_password(self, password):
        """Set password for accessing the file"""
        if password:
            self.access_password_hash = generate_password_hash(password)
            self.password_protected = True
        else:
            self.access_password_hash = None
            self.password_protected = False
    
    def check_access_password(self, password):
        """Check if the provided password is correct"""
        if not self.password_protected or not self.access_password_hash:
            return True
        return check_password_hash(self.access_password_hash, password)
    
    def is_expired(self):
        """Check if the file has expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def is_download_limit_reached(self):
        """Check if download limit has been reached"""
        if not self.max_downloads:
            return False
        return self.download_count >= self.max_downloads
    
    def can_access(self):
        """Check if file can be accessed (not expired and under download limit)"""
        return not self.is_expired() and not self.is_download_limit_reached()
    
    def record_access(self):
        """Record an access/download"""
        self.download_count += 1
        self.last_accessed = datetime.utcnow()
        db.session.commit()
    
    def set_expiry(self, hours=24):
        """Set expiry time (default 24 hours)"""
        self.expires_at = datetime.utcnow() + timedelta(hours=hours)
    
    def __repr__(self):
        return f'<SharedFile {self.filename} - {self.access_code}>'

class PDFProcessingJob(db.Model):
    """Track PDF processing jobs for better user experience"""
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(50), unique=True, nullable=False)
    job_type = db.Column(db.String(50), nullable=False)  # merge, split, convert, etc.
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    
    # Input/Output
    input_files = db.Column(db.JSON)  # List of input file paths
    output_file = db.Column(db.String(500))
    error_message = db.Column(db.Text)
    
    # Progress tracking
    progress_percentage = db.Column(db.Integer, default=0)
    current_step = db.Column(db.String(100))
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # User association (optional for anonymous users)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<PDFProcessingJob {self.job_id} - {self.job_type}>'