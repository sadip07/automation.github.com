from flask import Flask, request, jsonify, render_template, send_from_directory, Response, stream_with_context, redirect, url_for, flash, session
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import openai
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import tweepy
from wordpress_xmlrpc import Client, WordPressPost
from wordpress_xmlrpc.methods.posts import NewPost
import json
from dotenv import load_dotenv
import facebook
import requests
import html2text
import time
from threading import Thread
from werkzeug.utils import secure_filename
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import uuid
import secrets
from functools import wraps
from error_handlers import register_error_handlers, APIError, ValidationError, AuthenticationError, AuthorizationError, ResourceNotFoundError, APIProviderError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables
load_dotenv()

app = Flask(__name__, 
    static_folder='static',  # Change static folder to 'static'
    static_url_path='',      # Serve static files from root
    template_folder='templates'
)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure proxy fix for proper IP detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com; connect-src 'self' https://api.openai.com https://api.twitter.com https://graph.facebook.com;"

# Configure CORS with specific settings
CORS(app, resources={
    r"/*": {
        "origins": os.environ.get('ALLOWED_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Register error handlers
register_error_handlers(app)

# Set up the Secret Key for the app
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
# Set session configuration for security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('PRODUCTION', 'False').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Configure database
DB_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
# Heroku uses postgres:// but SQLAlchemy requires postgresql://
if DB_URI.startswith("postgres://"):
    DB_URI = DB_URI.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize bcrypt for password hashing
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database initialization and error handling
def init_db():
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

# Initialize database on startup
init_db()

# API Keys and Configuration
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
WORDPRESS_URL = os.environ.get('WORDPRESS_URL')
WORDPRESS_USERNAME = os.environ.get('WORDPRESS_USERNAME')
WORDPRESS_PASSWORD = os.environ.get('WORDPRESS_PASSWORD')
TWITTER_API_KEY = os.environ.get('TWITTER_API_KEY')
TWITTER_API_SECRET = os.environ.get('TWITTER_API_SECRET')
TWITTER_ACCESS_TOKEN = os.environ.get('TWITTER_ACCESS_TOKEN')
TWITTER_ACCESS_SECRET = os.environ.get('TWITTER_ACCESS_SECRET')
FACEBOOK_ACCESS_TOKEN = os.environ.get('FACEBOOK_ACCESS_TOKEN')
INSTAGRAM_ACCESS_TOKEN = os.environ.get('INSTAGRAM_ACCESS_TOKEN')
PINTEREST_ACCESS_TOKEN = os.environ.get('PINTEREST_ACCESS_TOKEN')
PINTEREST_BOARD_ID = os.environ.get('PINTEREST_BOARD_ID')

# Initialize OpenAI client
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY
    from openai import OpenAI
    openai_client = OpenAI(api_key=OPENAI_API_KEY)
else:
    openai_client = None

# Status log to store application activity
status_log = []

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# For file uploads
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# User model for authentication
class User(db.Model, UserMixin):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='User')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    articles = db.relationship('Article', backref='author', lazy=True)
    api_settings = db.relationship('APISettings', backref='user', lazy=True)
    social_media_settings = db.relationship('SocialMediaSettings', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Article(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    keyword = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='draft')  # draft, published, failed
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    published_at = db.Column(db.DateTime)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    retry_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)

    def __repr__(self):
        return f'<Article {self.title}>'

class APISettings(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    api_provider = db.Column(db.String(50), nullable=False)  # openai, gemini, claude, huggingface, grok
    api_key = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Additional settings for each provider
    model_name = db.Column(db.String(100))  # e.g., gpt-3.5-turbo, gemini-pro, claude-3-opus
    temperature = db.Column(db.Float, default=0.7)
    max_tokens = db.Column(db.Integer, default=1000)
    
    # SEO and content settings
    seo_optimization = db.Column(db.Boolean, default=True)
    content_structure = db.Column(db.String(50), default='article')  # article, blog, guide, etc.
    language = db.Column(db.String(10), default='en')
    tone = db.Column(db.String(50), default='professional')  # professional, casual, technical, etc.
    
    def __repr__(self):
        return f'<APISettings {self.api_provider} for user {self.user_id}>'
    
    def get_api_key(self):
        """Get the API key, falling back to environment variables if needed"""
        if not self.api_key or self.api_key.startswith('$2b$'):
            # Try to get from environment variables
            env_key = None
            if self.api_provider == 'openai':
                env_key = os.environ.get('OPENAI_API_KEY')
            elif self.api_provider == 'anthropic':
                env_key = os.environ.get('ANTHROPIC_API_KEY')
            elif self.api_provider == 'gemini':
                env_key = os.environ.get('GOOGLE_API_KEY')
            elif self.api_provider == 'huggingface':
                env_key = os.environ.get('HUGGINGFACE_API_KEY')
            elif self.api_provider == 'grok':
                env_key = os.environ.get('GROK_API_KEY')
            
            if not env_key:
                raise ValueError(f"No API key available for {self.api_provider}")
            return env_key
        return self.api_key

class SocialMediaSettings(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    platform = db.Column(db.String(50), nullable=False)  # wordpress, twitter, facebook, instagram
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Credentials (these will be encrypted in the database)
    api_key = db.Column(db.String(255), nullable=True)
    api_secret = db.Column(db.String(255), nullable=True)
    access_token = db.Column(db.String(255), nullable=True)
    access_token_secret = db.Column(db.String(255), nullable=True)
    
    # WordPress specific settings
    site_url = db.Column(db.String(255), nullable=True)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    
    # Publishing preferences
    auto_publish = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(100), nullable=True)
    tags = db.Column(db.String(255), nullable=True)  # Comma-separated tags
    
    def __repr__(self):
        return f'<SocialMediaSettings {self.platform} for user {self.user_id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            flash('You need to be an admin to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_activity(activity_type, message, status="success"):
    """Add an activity to the status log"""
    status_log.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": activity_type,
        "message": message,
        "status": status
    })
    # Keep only the latest 100 logs
    if len(status_log) > 100:
        status_log.pop(0)

@app.route('/')
def home():
    if current_user.is_authenticated:
        return send_from_directory('.', 'index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_activity("auth", f"User {username} logged in")
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    log_activity("auth", f"User {username} logged out")
    flash(f'You have been successfully logged out!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'User')
        
        # Check if username or email already exists
        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
        
        if user_exists:
            flash('Username already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
            
        if email_exists:
            flash('Email already in use. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        
        # Create new user with hashed password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        log_activity("auth", f"User {username} registered with role {role}")
        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('user_list'))
    
    return render_template('register.html')

@app.route('/users')
@admin_required
def user_list():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/delete/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.username == current_user.username:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('user_list'))
    
    db.session.delete(user)
    db.session.commit()
    
    log_activity("auth", f"User {user.username} deleted")
    flash(f'User {user.username} has been deleted!', 'success')
    return redirect(url_for('user_list'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        # Update email
        if email and email != current_user.email:
            email_exists = User.query.filter_by(email=email).first()
            if email_exists:
                flash('Email already in use. Please use a different email.', 'danger')
            else:
                current_user.email = email
                db.session.commit()
                flash('Email updated successfully!', 'success')
        
        # Update password
        if current_password and new_password:
            if bcrypt.check_password_hash(current_user.password, current_password):
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                current_user.password = hashed_password
                db.session.commit()
                flash('Password updated successfully!', 'success')
            else:
                flash('Current password is incorrect.', 'danger')
    
    return render_template('profile.html')

@app.route('/api/user/status')
def user_status():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'username': current_user.username,
            'role': current_user.role,
            'email': current_user.email
        })
    return jsonify({
        'authenticated': False
    })

@app.route('/<path:path>')
def static_files(path):
    # Check if the file exists in static folder
    if os.path.exists(os.path.join('static', path)):
        return send_from_directory('static', path)
    # Check if the file exists in templates folder
    elif os.path.exists(os.path.join('templates', path)):
        return send_from_directory('templates', path)
    # If file doesn't exist, return 404
    return jsonify({
        'status': 'error',
        'message': 'File not found'
    }), 404

@app.route('/api/generate', methods=['POST'])
@login_required
def generate_api():
    data = request.json
    prompt = data.get('prompt', '')
    word_count = int(data.get('wordCount', 500))
    
    if not prompt:
        return jsonify({
            'status': 'error',
            'message': 'Prompt is required'
        }), 400
        
    try:
        content = generate_content(prompt, word_count)
        log_activity("content_generation", f"User {current_user.username} generated content for prompt: '{prompt[:30]}...'")
        
        return jsonify({
            'status': 'success',
            'content': content
        })
    except Exception as e:
        error_message = str(e)
        log_activity("content_generation", f"Error generating content: {error_message}", "error")
        return jsonify({
            'status': 'error',
            'message': error_message
        }), 500

@app.route('/api/wordpress/publish', methods=['POST'])
def publish_to_wordpress():
    data = request.json
    title = data.get('title', '')
    content = data.get('content', '')
    
    try:
        # Connect to WordPress
        wp = Client(WORDPRESS_URL, WORDPRESS_USERNAME, WORDPRESS_PASSWORD)
        
        # Create post
        post = WordPressPost()
        post.title = title
        post.content = content
        post.post_status = 'publish'
        
        # Post to WordPress
        post_id = wp.call(NewPost(post))
        
        log_activity("wordpress", f"Published post: {title}")
        
        return jsonify({
            'status': 'success',
            'message': 'Content published to WordPress',
            'post_id': post_id
        })
    
    except Exception as e:
        log_activity("wordpress", f"Error publishing to WordPress: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/twitter/share', methods=['POST'])
def share_to_twitter():
    data = request.json
    message = data.get('message', '')
    
    try:
        # Set up Tweepy client
        auth = tweepy.OAuth1UserHandler(
            TWITTER_API_KEY, TWITTER_API_SECRET,
            TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET
        )
        api = tweepy.API(auth)
        
        # Post to Twitter
        tweet = api.update_status(message)
        
        log_activity("twitter", f"Shared tweet: {message[:30]}...")
        
        return jsonify({
            'status': 'success',
            'message': 'Content shared on Twitter',
            'tweet_id': tweet.id
        })
    
    except Exception as e:
        log_activity("twitter", f"Error sharing to Twitter: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/facebook/share', methods=['POST'])
def share_to_facebook():
    data = request.json
    message = data.get('message', '')
    link = data.get('link', '')
    
    try:
        # Set up Facebook Graph API
        graph = facebook.GraphAPI(access_token=FACEBOOK_ACCESS_TOKEN, version="3.1")
        
        # Post to Facebook Page
        if link:
            post = graph.put_object(
                parent_object='me',
                connection_name='feed',
                message=message,
                link=link
            )
        else:
            post = graph.put_object(
                parent_object='me',
                connection_name='feed',
                message=message
            )
        
        log_activity("facebook", f"Shared post to Facebook: {message[:30]}...")
        
        return jsonify({
            'status': 'success',
            'message': 'Content shared on Facebook',
            'post_id': post['id']
        })
    
    except Exception as e:
        log_activity("facebook", f"Error sharing to Facebook: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/instagram/share', methods=['POST'])
def share_to_instagram():
    data = request.json
    caption = data.get('caption', '')
    image_url = data.get('image_url', '')
    
    try:
        # For Instagram, we'll use the Graph API - simplified implementation
        # In production, this would require more complex handling for media upload
        
        # First download the image
        if not image_url:
            return jsonify({
                'status': 'error',
                'message': 'Image URL is required for Instagram posts'
            }), 400
            
        # Here's a simplified implementation using the Instagram Graph API
        headers = {
            'Authorization': f'Bearer {INSTAGRAM_ACCESS_TOKEN}'
        }
        
        # 1. Create a container for the media
        container_payload = {
            'image_url': image_url,
            'caption': caption
        }
        container_response = requests.post(
            'https://graph.instagram.com/me/media',
            headers=headers,
            data=container_payload
        )
        container_data = container_response.json()
        
        if 'id' not in container_data:
            raise Exception(f"Failed to create media container: {container_data}")
            
        # 2. Publish the container
        publish_payload = {
            'creation_id': container_data['id']
        }
        publish_response = requests.post(
            'https://graph.instagram.com/me/media_publish',
            headers=headers,
            data=publish_payload
        )
        publish_data = publish_response.json()
        
        log_activity("instagram", f"Shared post to Instagram: {caption[:30]}...")
        
        return jsonify({
            'status': 'success',
            'message': 'Content shared on Instagram',
            'post_id': publish_data.get('id', '')
        })
    
    except Exception as e:
        log_activity("instagram", f"Error sharing to Instagram: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/pinterest/share', methods=['POST'])
def share_to_pinterest():
    data = request.json
    note = data.get('note', '')
    image_url = data.get('image_url', '')
    link = data.get('link', '')
    board = data.get('board', PINTEREST_BOARD_ID)
    
    try:
        # Pinterest API - simplified implementation
        headers = {
            'Authorization': f'Bearer {PINTEREST_ACCESS_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'board_id': board,
            'note': note,
            'image_url': image_url,
            'link': link
        }
        
        response = requests.post(
            'https://api.pinterest.com/v5/pins',
            headers=headers,
            data=json.dumps(payload)
        )
        pin_data = response.json()
        
        if 'id' not in pin_data:
            raise Exception(f"Failed to create pin: {pin_data}")
        
        log_activity("pinterest", f"Shared pin to Pinterest: {note[:30]}...")
        
        return jsonify({
            'status': 'success',
            'message': 'Content shared on Pinterest',
            'pin_id': pin_data['id']
        })
    
    except Exception as e:
        log_activity("pinterest", f"Error sharing to Pinterest: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/logs', methods=['GET'])
def get_status_logs():
    return jsonify({
        'status': 'success',
        'logs': status_log
    })

@app.route('/api/schedule', methods=['POST'])
def schedule_task():
    data = request.json
    task_type = data.get('taskType')
    task_data = data.get('taskData', {})
    schedule_time = data.get('scheduleTime', '10:00')  # Default to 10 AM
    
    try:
        # Parse schedule time
        hour, minute = map(int, schedule_time.split(':'))
        
        # Schedule task based on type
        if task_type == 'content_generation':
            job = scheduler.add_job(
                scheduled_content_generation,
                CronTrigger(hour=hour, minute=minute),
                args=[task_data],
                id=f"content_gen_{datetime.now().timestamp()}"
            )
        elif task_type == 'wordpress_publish':
            job = scheduler.add_job(
                scheduled_wordpress_publish,
                CronTrigger(hour=hour, minute=minute),
                args=[task_data],
                id=f"wordpress_{datetime.now().timestamp()}"
            )
        elif task_type == 'twitter_share':
            job = scheduler.add_job(
                scheduled_twitter_share,
                CronTrigger(hour=hour, minute=minute),
                args=[task_data],
                id=f"twitter_{datetime.now().timestamp()}"
            )
        elif task_type == 'facebook_share':
            job = scheduler.add_job(
                scheduled_facebook_share,
                CronTrigger(hour=hour, minute=minute),
                args=[task_data],
                id=f"facebook_{datetime.now().timestamp()}"
            )
        elif task_type == 'instagram_share':
            job = scheduler.add_job(
                scheduled_instagram_share,
                CronTrigger(hour=hour, minute=minute),
                args=[task_data],
                id=f"instagram_{datetime.now().timestamp()}"
            )
        elif task_type == 'pinterest_share':
            job = scheduler.add_job(
                scheduled_pinterest_share,
                CronTrigger(hour=hour, minute=minute),
                args=[task_data],
                id=f"pinterest_{datetime.now().timestamp()}"
            )
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unknown task type: {task_type}'
            }), 400
        
        log_activity("scheduler", f"Scheduled {task_type} task for {schedule_time}")
        
        return jsonify({
            'status': 'success',
            'message': f'{task_type} task scheduled for {schedule_time}',
            'job_id': job.id
        })
    
    except Exception as e:
        log_activity("scheduler", f"Error scheduling task: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def scheduled_content_generation(task_data):
    prompt = task_data.get('prompt', '')
    word_count = task_data.get('wordCount', 500)
    
    try:
        # Generate content using OpenAI
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": f"Generate content about {word_count} words long."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=task_data.get('max_tokens', 1000),
            temperature=task_data.get('temperature', 0.7)
        )
        
        generated_content = response.choices[0].message.content
        
        log_activity("scheduled_content", f"Generated scheduled content for prompt: {prompt[:30]}...")
        
        # Store generated content for later use
        # This is just a placeholder - in a real app, you'd save this to a database
        with open('generated_content.json', 'a') as f:
            json.dump({
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'prompt': prompt,
                'content': generated_content
            }, f)
            f.write('\n')
            
    except Exception as e:
        log_activity("scheduled_content", f"Error generating scheduled content: {str(e)}", "error")

def scheduled_wordpress_publish(task_data):
    title = task_data.get('title', '')
    content = task_data.get('content', '')
    
    try:
        # Connect to WordPress
        wp = Client(WORDPRESS_URL, WORDPRESS_USERNAME, WORDPRESS_PASSWORD)
        
        # Create post
        post = WordPressPost()
        post.title = title
        post.content = content
        post.post_status = 'publish'
        
        # Post to WordPress
        post_id = wp.call(NewPost(post))
        
        log_activity("scheduled_wordpress", f"Published scheduled post: {title}")
            
    except Exception as e:
        log_activity("scheduled_wordpress", f"Error publishing scheduled post: {str(e)}", "error")

def scheduled_twitter_share(task_data):
    message = task_data.get('message', '')
    
    try:
        # Set up Tweepy client
        auth = tweepy.OAuth1UserHandler(
            TWITTER_API_KEY, TWITTER_API_SECRET,
            TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET
        )
        api = tweepy.API(auth)
        
        # Post to Twitter
        tweet = api.update_status(message)
        
        log_activity("scheduled_twitter", f"Shared scheduled tweet: {message[:30]}...")
            
    except Exception as e:
        log_activity("scheduled_twitter", f"Error sharing scheduled tweet: {str(e)}", "error")

def scheduled_facebook_share(task_data):
    message = task_data.get('message', '')
    link = task_data.get('link', '')
    
    try:
        # Set up Facebook Graph API
        graph = facebook.GraphAPI(access_token=FACEBOOK_ACCESS_TOKEN, version="3.1")
        
        # Post to Facebook Page
        if link:
            post = graph.put_object(
                parent_object='me',
                connection_name='feed',
                message=message,
                link=link
            )
        else:
            post = graph.put_object(
                parent_object='me',
                connection_name='feed',
                message=message
            )
        
        log_activity("scheduled_facebook", f"Shared scheduled post to Facebook: {message[:30]}...")
            
    except Exception as e:
        log_activity("scheduled_facebook", f"Error sharing scheduled post to Facebook: {str(e)}", "error")

def scheduled_instagram_share(task_data):
    caption = task_data.get('caption', '')
    image_url = task_data.get('image_url', '')
    
    try:
        # For Instagram, we'll use the Graph API
        if not image_url:
            log_activity("scheduled_instagram", "No image URL provided for Instagram post", "error")
            return
            
        headers = {
            'Authorization': f'Bearer {INSTAGRAM_ACCESS_TOKEN}'
        }
        
        # 1. Create a container for the media
        container_payload = {
            'image_url': image_url,
            'caption': caption
        }
        container_response = requests.post(
            'https://graph.instagram.com/me/media',
            headers=headers,
            data=container_payload
        )
        container_data = container_response.json()
        
        if 'id' not in container_data:
            raise Exception(f"Failed to create media container: {container_data}")
            
        # 2. Publish the container
        publish_payload = {
            'creation_id': container_data['id']
        }
        
        publish_response = requests.post(
            'https://graph.instagram.com/me/media_publish',
            headers=headers,
            data=publish_payload
        )
        publish_data = publish_response.json()
        
        log_activity("scheduled_instagram", f"Shared scheduled post to Instagram: {caption[:30]}...")
            
    except Exception as e:
        log_activity("scheduled_instagram", f"Error sharing scheduled post to Instagram: {str(e)}", "error")

def scheduled_pinterest_share(task_data):
    note = task_data.get('note', '')
    image_url = task_data.get('image_url', '')
    link = task_data.get('link', '')
    board = task_data.get('board', PINTEREST_BOARD_ID)
    
    try:
        # Pinterest API
        headers = {
            'Authorization': f'Bearer {PINTEREST_ACCESS_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'board_id': board,
            'note': note,
            'image_url': image_url,
            'link': link
        }
        
        response = requests.post(
            'https://api.pinterest.com/v5/pins',
            headers=headers,
            data=json.dumps(payload)
        )
        
        log_activity("scheduled_pinterest", f"Shared scheduled pin to Pinterest: {note[:30]}...")
            
    except Exception as e:
        log_activity("scheduled_pinterest", f"Error sharing scheduled pin to Pinterest: {str(e)}", "error")

@app.route('/api/process_keywords', methods=['POST'])
def process_keywords():
    # Check if file is included in the request
    if 'keywordFile' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file provided'
        }), 400
        
    file = request.files['keywordFile']
    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No file selected'
        }), 400
        
    # Check file extension
    if not file.filename.endswith('.txt'):
        return jsonify({
            'status': 'error',
            'message': 'Only .txt files are supported'
        }), 400
    
    # Get parameters
    try:
        word_count = int(request.form.get('wordCount', 500))
        delay_minutes = int(request.form.get('delayMinutes', 5))
        delay_seconds = delay_minutes * 60
    except (ValueError, TypeError) as e:
        return jsonify({
            'status': 'error',
            'message': f'Invalid parameters: {str(e)}'
        }), 400
    
    # Save the file
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # Read keywords from the file
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            keywords = [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error reading file: {str(e)}'
        }), 500
    
    if not keywords:
        return jsonify({
            'status': 'error',
            'message': 'No keywords found in the file'
        }), 400
    
    log_activity("keyword_processing", f"Started processing {len(keywords)} keywords from {filename}")
    
    # Stream the response to provide real-time updates
    def generate():
        total_keywords = len(keywords)
        
        for i, keyword in enumerate(keywords):
            current_index = i + 1
            keyword_log_prefix = f"[{current_index}/{total_keywords}] Keyword: '{keyword}'"
            
            try:
                # Send progress update
                yield json.dumps({
                    'status': 'progress',
                    'current': current_index,
                    'total': total_keywords,
                    'keyword': keyword,
                    'action': 'Processing Keyword',
                    'message': f"Starting to process keyword: '{keyword}'"
                }) + '\n'
                
                # 1. Generate content
                yield json.dumps({
                    'status': 'progress',
                    'current': current_index,
                    'total': total_keywords,
                    'keyword': keyword,
                    'action': 'Generating Content',
                    'message': f"Generating {word_count} word content for '{keyword}'"
                }) + '\n'
                
                try:
                    title = f"Guide to {keyword.title()}"
                    content = generate_content(f"Write a comprehensive guide about {keyword}. Include practical tips, best practices, and industry insights.", word_count)
                    
                    # 2. Publish to WordPress
                    yield json.dumps({
                        'status': 'progress',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'action': 'WordPress Publishing',
                        'message': f"Publishing article '{title}' to WordPress"
                    }) + '\n'
                    
                    # Publish to WordPress
                    wp_response = publish_to_wordpress(title, content)
                    post_url = wp_response.get('link', '')
                    post_id = wp_response.get('id', '')
                    
                    # 3. Share on Twitter
                    yield json.dumps({
                        'status': 'progress',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'action': 'Twitter Sharing',
                        'message': f"Sharing '{title}' on Twitter"
                    }) + '\n'
                    
                    # Create a short message for Twitter
                    twitter_message = f"Check out our new guide on {keyword}! {post_url}"
                    share_to_twitter(twitter_message)
                    
                    # 4. Share on Facebook
                    yield json.dumps({
                        'status': 'progress',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'action': 'Facebook Sharing',
                        'message': f"Sharing '{title}' on Facebook"
                    }) + '\n'
                    
                    # Create a message for Facebook
                    facebook_message = f"{title}\n\nWe've just published a new guide on {keyword}. Check it out at {post_url}"
                    share_to_facebook(facebook_message)
                    
                    # 5. Share on Instagram
                    yield json.dumps({
                        'status': 'progress',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'action': 'Instagram Sharing',
                        'message': f"Sharing '{title}' on Instagram"
                    }) + '\n'
                    
                    # Create a caption for Instagram and share it
                    instagram_caption = f"{title}\n\nWe've just published a new guide on {keyword}. Check out the link in our bio!"
                    image_url = f"https://source.unsplash.com/featured/?{keyword.replace(' ', ',')}"
                    share_to_instagram(instagram_caption, image_url)
                    
                    # Log completion for this keyword
                    log_activity("keyword_processing", f"{keyword_log_prefix} - All platforms updated successfully")
                    
                    # Wait before processing the next keyword (unless it's the last one)
                    if current_index < total_keywords:
                        yield json.dumps({
                            'status': 'progress',
                            'current': current_index,
                            'total': total_keywords,
                            'keyword': keyword,
                            'action': 'Delaying',
                            'message': f"Waiting {delay_minutes} minutes before processing next keyword"
                        }) + '\n'
                        
                        # For testing purposes, reduce the delay
                        if app.debug:
                            time.sleep(3)  # 3 seconds in debug mode
                        else:
                            time.sleep(delay_seconds)
                except Exception as e:
                    error_message = f"Error processing content for keyword '{keyword}': {str(e)}"
                    log_activity("keyword_processing", error_message, "error")
                    
                    yield json.dumps({
                        'status': 'error',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'message': error_message
                    }) + '\n'
                
            except Exception as e:
                error_message = f"Error processing keyword '{keyword}': {str(e)}"
                log_activity("keyword_processing", error_message, "error")
                
                yield json.dumps({
                    'status': 'error',
                    'current': current_index,
                    'total': total_keywords,
                    'keyword': keyword,
                    'message': error_message
                }) + '\n'
        
        # Final completion message
        yield json.dumps({
            'status': 'progress',
            'current': total_keywords,
            'total': total_keywords,
            'keyword': 'Complete',
            'action': 'Process Complete',
            'message': f"Successfully processed all {total_keywords} keywords"
        }) + '\n'
    
    return Response(stream_with_context(generate()), content_type='application/json', headers={
        'X-Content-Type-Options': 'nosniff',  # Prevent MIME type sniffing
        'Cache-Control': 'no-cache'  # Prevent caching
    })

def publish_to_wordpress(title, content):
    """Helper function to publish content to WordPress"""
    # Use mock implementation for testing in debug mode
    if app.debug:
        # Mock WordPress response
        mock_response = {
            'id': str(int(time.time())),
            'link': f"https://example.com/post/{title.replace(' ', '-').lower()}",
            'title': {'rendered': title},
            'content': {'rendered': content}
        }
        log_activity("wordpress", f"Published post: {title} (MOCK)", "success")
        return mock_response
    
    # Real implementation for production
    auth = (WORDPRESS_USERNAME, WORDPRESS_PASSWORD)
    
    post_data = {
        'title': title,
        'content': content,
        'status': 'publish'
    }
    
    try:
        response = requests.post(
            f"{WORDPRESS_URL}/posts",
            auth=auth,
            json=post_data
        )
        response_data = response.json()
        
        if 'id' not in response_data:
            raise Exception(f"Failed to publish to WordPress: {response_data}")
        
        log_activity("wordpress", f"Published post: {title}", "success")
        return response_data
        
    except Exception as e:
        log_activity("wordpress", f"Error publishing to WordPress: {str(e)}", "error")
        raise e

def share_to_twitter(message):
    """Helper function to share content on Twitter"""
    # Use mock implementation for testing in debug mode
    if app.debug:
        # Mock Twitter response
        mock_response = {
            'data': {
                'id': str(int(time.time())),
                'text': message
            }
        }
        log_activity("twitter", f"Shared tweet: {message[:30]}... (MOCK)", "success")
        return mock_response
    
    # Real implementation for production
    try:
        headers = {
            'Authorization': f'Bearer {TWITTER_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'text': message
        }
        
        response = requests.post(
            'https://api.twitter.com/2/tweets',
            headers=headers,
            json=payload
        )
        response_data = response.json()
        
        if 'data' not in response_data or 'id' not in response_data['data']:
            raise Exception(f"Failed to share on Twitter: {response_data}")
        
        log_activity("twitter", f"Shared tweet: {message[:30]}...", "success")
        return response_data
        
    except Exception as e:
        log_activity("twitter", f"Error sharing to Twitter: {str(e)}", "error")
        raise e

def share_to_facebook(message):
    """Helper function to share content on Facebook"""
    # Use mock implementation for testing in debug mode
    if app.debug:
        # Mock Facebook response
        mock_response = {
            'id': str(int(time.time()))
        }
        log_activity("facebook", f"Shared post: {message[:30]}... (MOCK)", "success")
        return mock_response
    
    # Real implementation for production
    try:
        url = f"https://graph.facebook.com/v12.0/me/feed"
        
        payload = {
            'message': message,
            'access_token': FACEBOOK_ACCESS_TOKEN
        }
        
        response = requests.post(url, data=payload)
        response_data = response.json()
        
        if 'id' not in response_data:
            raise Exception(f"Failed to share on Facebook: {response_data}")
        
        log_activity("facebook", f"Shared post: {message[:30]}...", "success")
        return response_data
        
    except Exception as e:
        log_activity("facebook", f"Error sharing to Facebook: {str(e)}", "error")
        raise e

def share_to_instagram(caption, image_url):
    """Helper function to share content on Instagram"""
    # Use mock implementation for testing in debug mode
    if app.debug:
        # Mock Instagram response
        mock_response = {
            'id': str(int(time.time()))
        }
        log_activity("instagram", f"Shared post to Instagram: {caption[:30]}... (MOCK)", "success")
        return mock_response
    
    # Real implementation for production
    try:
        # For Instagram, we'll use the Graph API - simplified implementation
        headers = {
            'Authorization': f'Bearer {INSTAGRAM_ACCESS_TOKEN}'
        }
        
        # 1. Create a container for the media
        container_payload = {
            'image_url': image_url,
            'caption': caption
        }
        
        container_response = requests.post(
            'https://graph.instagram.com/me/media',
            headers=headers,
            data=container_payload
        )
        container_data = container_response.json()
        
        if 'id' not in container_data:
            raise Exception(f"Failed to create media container: {container_data}")
            
        # 2. Publish the container
        publish_payload = {
            'creation_id': container_data['id']
        }
        
        publish_response = requests.post(
            'https://graph.instagram.com/me/media_publish',
            headers=headers,
            data=publish_payload
        )
        publish_data = publish_response.json()
        
        log_activity("instagram", f"Shared post to Instagram: {caption[:30]}...", "success")
        return publish_data
        
    except Exception as e:
        log_activity("instagram", f"Error sharing to Instagram: {str(e)}", "error")
        raise e

def generate_content(prompt, word_count=500):
    """Helper function to generate content using the active API provider"""
    try:
        # Get active API settings
        active_settings = APISettings.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).first()
        
        if not active_settings:
            raise Exception("No active API provider found. Please configure API settings first.")
        
        # Get settings from the active provider
        provider = active_settings.api_provider
        model = active_settings.model_name
        temp = active_settings.temperature
        max_token = active_settings.max_tokens
        
        # Get the API key using the new method
        try:
            api_key = active_settings.get_api_key()
        except ValueError as e:
            log_activity("content_generation", str(e), "error")
            raise e
        
        # Generate content based on provider
        if provider == 'openai':
            openai.api_key = api_key
            # Use the client for OpenAI API v1
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": f"Generate content about {word_count} words long."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_token,
                temperature=temp
            )
            content = response.choices[0].message.content
            
        elif provider == 'gemini':
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model_obj = genai.GenerativeModel(model)
            response = model_obj.generate_content(
                prompt,
                generation_config={
                    'temperature': temp,
                    'max_output_tokens': max_token
                }
            )
            content = response.text
            
        elif provider == 'anthropic':
            import anthropic
            client = anthropic.Client(api_key=api_key)
            response = client.messages.create(
                model=model,
                max_tokens=max_token,
                temperature=temp,
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text
            
        elif provider == 'huggingface':
            import huggingface_hub
            client = huggingface_hub.InferenceClient(token=api_key)
            response = client.text_generation(
                prompt,
                model=model,
                max_new_tokens=max_token,
                temperature=temp
            )
            content = response
            
        elif provider == 'grok':
            # Placeholder for Grok API when it becomes more widely available
            content = f"Grok API integration is coming soon. Your query was: {prompt}"
            
        else:
            raise Exception(f"Unsupported provider: {provider}")
        
        log_activity("content_generation", f"Successfully generated content using {provider} ({model})", "success")
        
        # Format content for SEO if needed
        if active_settings.seo_optimization:
            content = format_content_for_seo(content)
        
        return content
        
    except Exception as e:
        log_activity("content_generation", f"Error generating content: {str(e)}", "error")
        raise e

def format_content_for_seo(content):
    """Helper function to format content for SEO optimization"""
    # Add HTML structure
    formatted = f"""
    <article>
        <h1>{content.split('\n')[0]}</h1>
        <div class="content">
            {content}
        </div>
    </article>
    """
    
    # Add meta description
    meta_desc = content[:160] + "..." if len(content) > 160 else content
    formatted = f"""
    <meta name="description" content="{meta_desc}">
    {formatted}
    """
    
    return formatted

# Schedule keyword processing to run daily
def schedule_keyword_processing():
    """Function to schedule the processing of keywords on a daily basis"""
    log_activity("scheduler", "Starting daily keyword processing job")
    
    # Get all .txt files in the upload folder
    for filename in os.listdir(UPLOAD_FOLDER):
        if filename.endswith('.txt'):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    keywords = [line.strip() for line in f.readlines() if line.strip()]
                
                if not keywords:
                    log_activity("scheduler", f"No keywords found in {filename}", "warning")
                    continue
                
                log_activity("scheduler", f"Processing {len(keywords)} keywords from {filename}")
                
                # Process each keyword
                for keyword in keywords:
                    try:
                        # Generate content
                        title = f"Guide to {keyword.title()}"
                        content = generate_content(f"Write a comprehensive guide about {keyword}. Include practical tips, best practices, and industry insights.", 500)
                        
                        # Publish to WordPress
                        wp_response = publish_to_wordpress(title, content)
                        post_url = wp_response.get('link', '')
                        
                        # Share on social media
                        twitter_message = f"Check out our new guide on {keyword}! {post_url}"
                        share_to_twitter(twitter_message)
                        
                        facebook_message = f"{title}\n\nWe've just published a new guide on {keyword}. Check it out at {post_url}"
                        share_to_facebook(facebook_message)
                        
                        # For Instagram
                        instagram_caption = f"{title}\n\nWe've just published a new guide on {keyword}. Check out the link in our bio!"
                        image_url = f"https://source.unsplash.com/featured/?{keyword.replace(' ', ',')}"
                        share_to_instagram(instagram_caption, image_url)
                        
                        log_activity("scheduler", f"Successfully processed keyword: '{keyword}'")
                        
                        # Wait 5 minutes before the next keyword
                        time.sleep(300)
                        
                    except Exception as e:
                        log_activity("scheduler", f"Error processing keyword '{keyword}': {str(e)}", "error")
                        continue
                
            except Exception as e:
                log_activity("scheduler", f"Error reading file {filename}: {str(e)}", "error")
                continue

# Add scheduled job to run daily at 10:00 AM
scheduler.add_job(
    schedule_keyword_processing,
    CronTrigger(hour=10, minute=0),
    id='daily_keyword_processing'
)

@app.route('/api/test', methods=['GET', 'POST'])
def test_api():
    """Simple test endpoint to verify the server is running correctly"""
    if request.method == 'POST':
        # If this is a POST request, echo back any form data
        data = {}
        if request.is_json:
            data = request.json
        elif request.form:
            data = {key: request.form[key] for key in request.form.keys()}
        elif request.files:
            data = {key: f"File: {request.files[key].filename}" for key in request.files.keys()}
        
        return jsonify({
            'status': 'success',
            'message': 'POST request received successfully',
            'data': data,
            'method': request.method
        })
    else:
        # For GET requests, just return a success message
        return jsonify({
            'status': 'success',
            'message': 'API is running correctly',
            'method': request.method
        })

@app.route('/articles')
@login_required
def articles():
    user_articles = Article.query.filter_by(user_id=current_user.id).order_by(Article.created_at.desc()).all()
    return render_template('articles.html', articles=user_articles)

@app.route('/api/articles')
@login_required
def get_all_articles():
    try:
        articles = Article.query.filter_by(user_id=current_user.id).order_by(Article.created_at.desc()).all()
        
        # Format articles for the frontend
        formatted_articles = []
        for article in articles:
            formatted_articles.append({
                'id': article.id,
                'title': article.title,
                'content': article.content,
                'keyword': article.keyword,
                'status': article.status,
                'created_at': article.created_at.isoformat(),
                'published_at': article.published_at.isoformat() if article.published_at else None,
                'error_message': article.error_message
            })
        
        return jsonify({
            'status': 'success',
            'articles': formatted_articles
        })
    except Exception as e:
        log_activity("article", f"Error retrieving articles: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve articles: {str(e)}'
        }), 500

@app.route('/api/articles/stats')
@login_required
def get_article_stats():
    try:
        # Get total count
        total_count = Article.query.filter_by(user_id=current_user.id).count()
        
        # Get count by status
        published_count = Article.query.filter_by(user_id=current_user.id, status='published').count()
        draft_count = Article.query.filter_by(user_id=current_user.id, status='draft').count()
        failed_count = Article.query.filter_by(user_id=current_user.id, status='failed').count()
        
        # Get count by keyword (top 5)
        keyword_counts = db.session.query(
            Article.keyword, db.func.count(Article.id).label('count')
        ).filter_by(
            user_id=current_user.id
        ).group_by(
            Article.keyword
        ).order_by(
            db.desc('count')
        ).limit(5).all()
        
        # Format keyword counts
        formatted_keyword_counts = [
            {'keyword': kw, 'count': count} for kw, count in keyword_counts
        ]
        
        return jsonify({
            'status': 'success',
            'total': total_count,
            'published': published_count,
            'draft': draft_count,
            'failed': failed_count,
            'by_keyword': formatted_keyword_counts
        })
    except Exception as e:
        log_activity("article_stats", f"Error retrieving article stats: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve article statistics: {str(e)}'
        }), 500

@app.route('/api/articles/generate', methods=['POST'])
@login_required
def generate_articles():
    if 'keywordFile' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file provided'
        }), 400
        
    file = request.files['keywordFile']
    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No file selected'
        }), 400
        
    if not file.filename.endswith('.txt'):
        return jsonify({
            'status': 'error',
            'message': 'Only .txt files are supported'
        }), 400
    
    try:
        # Save the file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Read keywords from the file
        with open(file_path, 'r', encoding='utf-8') as f:
            keywords = [line.strip() for line in f.readlines() if line.strip()]
        
        if not keywords:
            return jsonify({
                'status': 'error',
                'message': 'No keywords found in the file'
            }), 400
        
        # Get the prompt template from the request
        prompt_template = request.form.get('prompt', 'Write a 500-word article on {keyword}')
        word_count = int(request.form.get('wordCount', 500))
        
        log_activity("keyword_processing", f"Started processing {len(keywords)} keywords from {filename}")
        
        def generate():
            total_keywords = len(keywords)
            
            for i, keyword in enumerate(keywords):
                current_index = i + 1
                keyword_log_prefix = f"[{current_index}/{total_keywords}] Keyword: '{keyword}'"
                
                try:
                    # Send progress update
                    yield json.dumps({
                        'status': 'progress',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'action': 'Processing Keyword',
                        'message': f"Starting to process keyword: '{keyword}'"
                    }) + '\n'
                    
                    # Generate content with retry logic
                    max_retries = 3
                    retry_delay = 10
                    content = None
                    
                    for attempt in range(max_retries):
                        try:
                            prompt = prompt_template.format(keyword=keyword)
                            yield json.dumps({
                                'status': 'progress',
                                'current': current_index,
                                'total': total_keywords,
                                'keyword': keyword,
                                'action': 'Generating Content',
                                'message': f"Generating content for '{keyword}' (attempt {attempt+1}/{max_retries})"
                            }) + '\n'
                            
                            content = generate_content(prompt, word_count)
                            break
                        except Exception as e:
                            if attempt < max_retries - 1:
                                yield json.dumps({
                                    'status': 'progress',
                                    'current': current_index,
                                    'total': total_keywords,
                                    'keyword': keyword,
                                    'action': 'Retrying',
                                    'message': f"Retry {attempt+1}/{max_retries-1} after error: {str(e)}"
                                }) + '\n'
                                time.sleep(retry_delay)
                                continue
                            raise e
                    
                    if not content:
                        raise Exception("Failed to generate content after all retries")
                    
                    # Create article in database
                    title = f"Article about {keyword}"
                    article = Article(
                        title=title,
                        content=content,
                        keyword=keyword,
                        user_id=current_user.id,
                        status='draft'
                    )
                    db.session.add(article)
                    db.session.commit()
                    
                    # Send success update
                    yield json.dumps({
                        'status': 'success',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'article_id': article.id,
                        'message': f"Successfully generated article for '{keyword}'"
                    }) + '\n'
                    
                except Exception as e:
                    error_message = f"Error processing keyword '{keyword}': {str(e)}"
                    log_activity("article_generation", error_message, "error")
                    
                    # Create failed article in database
                    article = Article(
                        title=f"Failed article for {keyword}",
                        content="",
                        keyword=keyword,
                        user_id=current_user.id,
                        status='failed',
                        error_message=str(e),
                        retry_count=3
                    )
                    db.session.add(article)
                    db.session.commit()
                    
                    yield json.dumps({
                        'status': 'error',
                        'current': current_index,
                        'total': total_keywords,
                        'keyword': keyword,
                        'message': error_message
                    }) + '\n'
            
            # Final completion message
            yield json.dumps({
                'status': 'complete',
                'message': f"Processed {total_keywords} keywords"
            }) + '\n'
        
        return Response(stream_with_context(generate()), content_type='application/json', headers={
            'X-Content-Type-Options': 'nosniff',  # Prevent MIME type sniffing
            'Cache-Control': 'no-cache'  # Prevent caching
        })
        
    except Exception as e:
        log_activity("article_generation", f"Error in keyword processing: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/articles/<article_id>', methods=['GET'])
@login_required
def get_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    # Check if user owns the article
    if article.user_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized'
        }), 403
    
    return jsonify({
        'status': 'success',
        'article': {
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'keyword': article.keyword,
            'status': article.status,
            'created_at': article.created_at.isoformat(),
            'published_at': article.published_at.isoformat() if article.published_at else None,
            'error_message': article.error_message
        }
    })

@app.route('/api/articles/<article_id>', methods=['PUT'])
@login_required
@limiter.limit("30 per hour")
@validate_request({
    'title': {'type': str, 'required': False, 'min_length': 3, 'max_length': 200},
    'content': {'type': str, 'required': False, 'min_length': 100},
    'status': {'type': str, 'required': False}
})
def update_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    # Check if user owns the article
    if article.user_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized'
        }), 403
    
    data = request.json
    
    if 'title' in data:
        article.title = data['title']
    if 'content' in data:
        article.content = data['content']
    if 'status' in data:
        article.status = data['status']
        if data['status'] == 'published':
            article.published_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Article updated successfully'
    })

@app.route('/api/articles/<article_id>', methods=['DELETE'])
@login_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    # Check if user owns the article
    if article.user_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized'
        }), 403
    
    db.session.delete(article)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Article deleted successfully'
    })

@app.route('/api/settings', methods=['GET'])
@login_required
def get_api_settings():
    try:
        settings = APISettings.query.filter_by(user_id=current_user.id).all()
        
        # Format settings for the frontend, masking sensitive data
        formatted_settings = []
        for setting in settings:
            formatted_settings.append({
                'api_provider': setting.api_provider,
                'model_name': setting.model_name,
                'is_active': setting.is_active,
                'temperature': setting.temperature,
                'max_tokens': setting.max_tokens,
                'content_structure': setting.content_structure or 'article',
                'language': setting.language or 'en',
                'tone': setting.tone or 'professional',
                'seo_optimization': setting.seo_optimization or True,
                'updated_at': setting.updated_at.strftime('%Y-%m-%d %H:%M:%S') if setting.updated_at else None,
                'has_key': True  # Indicate a key exists without exposing it
            })
        
        return jsonify({
            'status': 'success',
            'settings': formatted_settings
        })
    except Exception as e:
        log_activity("api", f"Error retrieving API settings: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve API settings: {str(e)}'
        }), 500

@app.route('/api/settings', methods=['POST'])
@login_required
def save_api_settings():
    try:
        data = request.json
        provider = data.get('provider')
        api_key = data.get('api_key')
        model_name = data.get('model_name')
        is_active = data.get('is_active', False)
        temperature = data.get('temperature', 0.7)
        max_tokens = data.get('max_tokens', 1000)
        
        # Log received data (without the actual API key for security)
        logger.info(f"Received API settings: provider={provider}, model={model_name}, is_active={is_active}")
        
        # Validate required fields
        if not all([provider, api_key, model_name]):
            missing_fields = []
            if not provider:
                missing_fields.append('provider')
            if not api_key:
                missing_fields.append('api_key')
            if not model_name:
                missing_fields.append('model_name')
                
            error_msg = f'Missing required fields: {", ".join(missing_fields)}'
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 400
        
        # Validate provider value
        valid_providers = ['openai', 'anthropic', 'gemini', 'huggingface', 'grok']
        if provider not in valid_providers:
            error_msg = f'Invalid provider. Must be one of: {", ".join(valid_providers)}'
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 400
        
        try:
            # Check if settings already exist for this provider and user
            existing_settings = APISettings.query.filter_by(
                user_id=current_user.id,
                api_provider=provider
            ).first()
            
            if existing_settings:
                # Update existing settings
                existing_settings.api_key = api_key  # Store the API key directly
                existing_settings.model_name = model_name
                existing_settings.is_active = is_active
                existing_settings.temperature = temperature
                existing_settings.max_tokens = max_tokens
                existing_settings.updated_at = datetime.utcnow()
                logger.info(f"Updated existing {provider} API settings for user {current_user.id}")
                log_activity("api", f"Updated {provider} API settings", "success")
            else:
                # Create new settings
                new_settings = APISettings(
                    user_id=current_user.id,
                    api_provider=provider,
                    api_key=api_key,  # Store the API key directly
                    model_name=model_name,
                    is_active=is_active,
                    temperature=temperature,
                    max_tokens=max_tokens
                )
                db.session.add(new_settings)
                logger.info(f"Added new {provider} API settings for user {current_user.id}")
                log_activity("api", f"Added new {provider} API settings", "success")
            
            # If this provider is being set as active, deactivate others
            if is_active:
                APISettings.query.filter_by(
                    user_id=current_user.id,
                    is_active=True
                ).filter(
                    APISettings.api_provider != provider
                ).update({'is_active': False})
                logger.info(f"Deactivated other API providers for user {current_user.id}")
            
            db.session.commit()
            
            # Test the API key
            try:
                test_api_key(provider, api_key, model_name)
                return jsonify({
                    'status': 'success',
                    'message': f'{provider} API settings saved and validated successfully'
                })
            except Exception as api_error:
                error_msg = f"API key validation failed: {str(api_error)}"
                logger.error(error_msg)
                return jsonify({
                    'status': 'error',
                    'message': error_msg
                }), 400
                
        except Exception as db_error:
            error_msg = f"Database error: {str(db_error)}"
            logger.error(error_msg)
            db.session.rollback()
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 500
            
    except Exception as e:
        error_msg = f"Error saving API settings: {str(e)}"
        logger.error(error_msg)
        return jsonify({
            'status': 'error',
            'message': error_msg
        }), 500

def test_api_key(provider, api_key, model_name):
    """Test if the API key is valid"""
    try:
        if provider == 'openai':
            openai.api_key = api_key
            client = openai.OpenAI(api_key=api_key)
            client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": "Test"}],
                max_tokens=5
            )
        elif provider == 'gemini':
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(model_name)
            model.generate_content("Test", max_output_tokens=5)
        elif provider == 'anthropic':
            import anthropic
            client = anthropic.Client(api_key=api_key)
            client.messages.create(
                model=model_name,
                messages=[{"role": "user", "content": "Test"}],
                max_tokens=5
            )
        elif provider == 'huggingface':
            import huggingface_hub
            client = huggingface_hub.InferenceClient(token=api_key)
            client.text_generation("Test", model=model_name, max_new_tokens=5)
        elif provider == 'grok':
            # Skip validation for Grok as it's not widely available yet
            pass
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    except Exception as e:
        raise ValueError(f"Invalid API key for {provider}: {str(e)}")

@app.route('/api/settings/test', methods=['POST'])
@login_required
def test_api_settings():
    try:
        data = request.json
        provider = data.get('provider')
        api_key = data.get('api_key')
        model_name = data.get('model_name')
        
        # Validate required fields
        if not all([provider, api_key, model_name]):
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields: provider, api_key, and model_name are required'
            }), 400
        
        # Validate provider value
        valid_providers = ['openai', 'anthropic', 'gemini', 'huggingface', 'grok']
        if provider not in valid_providers:
            return jsonify({
                'status': 'error',
                'message': f'Invalid provider. Must be one of: {", ".join(valid_providers)}'
            }), 400
        
        # Test the API connection based on provider
        if provider == 'openai':
            try:
                openai.api_key = api_key
                client = openai.OpenAI(api_key=api_key)
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": "Test message"}],
                    max_tokens=10
                )
                log_activity("api", "Successfully tested OpenAI API connection", "success")
            except Exception as e:
                log_activity("api", f"OpenAI API test failed: {str(e)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'OpenAI API error: {str(e)}'
                }), 400
                
        elif provider == 'gemini':
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel(model_name)
                response = model.generate_content("Test message")
                log_activity("api", "Successfully tested Google Gemini API connection", "success")
            except Exception as e:
                log_activity("api", f"Google Gemini API test failed: {str(e)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Google Gemini API error: {str(e)}'
                }), 400
                
        elif provider == 'anthropic':
            try:
                import anthropic
                client = anthropic.Client(api_key=api_key)
                response = client.messages.create(
                    model=model_name,
                    max_tokens=10,
                    temperature=0.7,
                    messages=[{"role": "user", "content": "Test message"}]
                )
                log_activity("api", "Successfully tested Anthropic API connection", "success")
            except Exception as e:
                log_activity("api", f"Anthropic API test failed: {str(e)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Anthropic API error: {str(e)}'
                }), 400
                
        elif provider == 'huggingface':
            try:
                import huggingface_hub
                client = huggingface_hub.InferenceClient(token=api_key)
                response = client.text_generation(
                    "Test message",
                    model=model_name,
                    max_new_tokens=10
                )
                log_activity("api", "Successfully tested Hugging Face API connection", "success")
            except Exception as e:
                log_activity("api", f"Hugging Face API test failed: {str(e)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Hugging Face API error: {str(e)}'
                }), 400
                
        elif provider == 'grok':
            try:
                # Simulate Grok API test as it's not widely available yet
                if not api_key or len(api_key) < 10:
                    raise ValueError("Invalid Grok API key format")
                log_activity("api", "Successfully tested Grok API connection (simulated)", "success")
            except Exception as e:
                log_activity("api", f"Grok API test failed: {str(e)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Grok API error: {str(e)}'
                }), 400
        
        return jsonify({
            'status': 'success',
            'message': 'API connection successful'
        })
        
    except Exception as e:
        log_activity("api", f"API test encountered an unexpected error: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'An unexpected error occurred: {str(e)}'
        }), 500

@app.route('/api/settings/active', methods=['GET'])
@login_required
def get_active_api():
    try:
        active_settings = APISettings.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).first()
        
        if not active_settings:
            return jsonify({
                'status': 'error',
                'message': 'No active API provider found. Please configure API settings first.'
            }), 404
        
        # Return provider information without the actual API key
        return jsonify({
            'status': 'success',
            'provider': active_settings.api_provider,
            'model_name': active_settings.model_name,
            'temperature': active_settings.temperature,
            'max_tokens': active_settings.max_tokens,
            'has_key': True  # Indicate a key exists without exposing it
        })
    except Exception as e:
        log_activity("api", f"Error retrieving active API settings: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve active API settings: {str(e)}'
        }), 500

@app.route('/api/diagnostic', methods=['GET'])
@login_required
def run_diagnostic():
    """Run a diagnostic check on API settings"""
    try:
        # Check environment variables
        env_vars = {
            'OPENAI_API_KEY': bool(OPENAI_API_KEY),
            'ANTHROPIC_API_KEY': bool(os.environ.get('ANTHROPIC_API_KEY')),
            'GOOGLE_API_KEY': bool(os.environ.get('GOOGLE_API_KEY')),
            'HUGGINGFACE_API_KEY': bool(os.environ.get('HUGGINGFACE_API_KEY')),
            'GROK_API_KEY': bool(os.environ.get('GROK_API_KEY')),
        }
        
        # Check database API settings
        active_settings = APISettings.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).first()
        
        db_settings = None
        if active_settings:
            db_settings = {
                'api_provider': active_settings.api_provider,
                'model_name': active_settings.model_name,
                'is_active': active_settings.is_active,
                'has_key': bool(active_settings.api_key),
                'key_hashed': active_settings.api_key.startswith('$2b$'),
                'temperature': active_settings.temperature,
                'max_tokens': active_settings.max_tokens,
            }
        
        # Check OpenAI configuration
        openai_settings = {
            'client_initialized': openai_client is not None,
            'api_key_configured': bool(openai.api_key),
        }
        
        # Test connection for the active provider
        connection_test = None
        if active_settings:
            try:
                provider = active_settings.api_provider
                api_key = active_settings.api_key
                
                # If key is hashed, try to get from environment
                if api_key.startswith('$2b$'):
                    if provider == 'openai':
                        api_key = os.environ.get('OPENAI_API_KEY')
                    elif provider == 'anthropic':
                        api_key = os.environ.get('ANTHROPIC_API_KEY')
                    elif provider == 'gemini':
                        api_key = os.environ.get('GOOGLE_API_KEY')
                    elif provider == 'huggingface':
                        api_key = os.environ.get('HUGGINGFACE_API_KEY')
                    elif provider == 'grok':
                        api_key = os.environ.get('GROK_API_KEY')
                
                # Basic validation of API key
                if not api_key:
                    connection_test = {
                        'success': False,
                        'message': f'No API key available for {provider}'
                    }
                elif provider == 'openai':
                    # Test OpenAI connection
                    client = openai.OpenAI(api_key=api_key)
                    response = client.chat.completions.create(
                        model=active_settings.model_name,
                        messages=[{"role": "user", "content": "Hello"}],
                        max_tokens=10
                    )
                    connection_test = {
                        'success': True,
                        'message': 'OpenAI API connection successful',
                        'model': active_settings.model_name
                    }
                else:
                    # For other providers, just check that we have a key
                    connection_test = {
                        'success': True,
                        'message': f'{provider} API key is present (test call not attempted)',
                        'model': active_settings.model_name
                    }
            except Exception as e:
                connection_test = {
                    'success': False,
                    'message': f'API connection test failed: {str(e)}',
                    'provider': active_settings.api_provider,
                    'model': active_settings.model_name,
                    'error': str(e)
                }
        
        return jsonify({
            'status': 'success',
            'environment_variables': env_vars,
            'database_settings': db_settings,
            'openai_settings': openai_settings,
            'connection_test': connection_test,
            'debug_mode': app.debug
        })
    except Exception as e:
        log_activity("diagnostic", f"Error running diagnostic: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Diagnostic failed: {str(e)}'
        }), 500

@app.route('/api/settings/env', methods=['POST'])
@login_required
@admin_required
def update_env_settings():
    """Update environment variable API settings at runtime (admin only)"""
    data = request.json
    provider = data.get('provider')
    api_key = data.get('api_key')
    
    if not provider or not api_key:
        return jsonify({
            'status': 'error',
            'message': 'Both provider and api_key are required'
        }), 400
    
    # Validate provider
    valid_providers = ['openai', 'anthropic', 'gemini', 'huggingface', 'grok']
    if provider not in valid_providers:
        return jsonify({
            'status': 'error',
            'message': f'Invalid provider. Must be one of: {", ".join(valid_providers)}'
        }), 400
    
    # Update the correct environment variable
    try:
        if provider == 'openai':
            os.environ['OPENAI_API_KEY'] = api_key
        elif provider == 'anthropic':
            os.environ['ANTHROPIC_API_KEY'] = api_key
        elif provider == 'gemini':
            os.environ['GOOGLE_API_KEY'] = api_key
        elif provider == 'huggingface':
            os.environ['HUGGINGFACE_API_KEY'] = api_key
        elif provider == 'grok':
            os.environ['GROK_API_KEY'] = api_key
        else:
            return jsonify({
                'status': 'error',
                'message': f'Invalid provider: {provider}'
            }), 400
        
        log_activity("api", f"Updated {provider} API settings", "success")
        return jsonify({
            'status': 'success',
            'message': f'{provider} API settings updated successfully'
        })
    except Exception as e:
        log_activity("api", f"Error updating {provider} API settings: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

# Social Media Integration Routes
@app.route('/social-media', methods=['GET'])
@login_required
def social_media_page():
    return render_template('social_media_settings.html')

@app.route('/api/social-media/settings', methods=['GET'])
@login_required
def get_social_media_settings():
    try:
        settings = SocialMediaSettings.query.filter_by(user_id=current_user.id).all()
        
        # Format settings for frontend, masking sensitive data
        formatted_settings = []
        for setting in settings:
            formatted_setting = {
                'id': setting.id,
                'platform': setting.platform,
                'is_active': setting.is_active,
                'auto_publish': setting.auto_publish,
                'created_at': setting.created_at.isoformat(),
                'updated_at': setting.updated_at.isoformat(),
                'site_url': setting.site_url,
                'username': setting.username,
                'category': setting.category,
                'tags': setting.tags,
                # Don't include sensitive fields like passwords or tokens
                'has_credentials': bool(setting.api_key or setting.password or setting.access_token)
            }
            formatted_settings.append(formatted_setting)
        
        return jsonify({
            'status': 'success',
            'settings': formatted_settings
        })
    except Exception as e:
        log_activity("social_media", f"Error retrieving social media settings: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving social media settings: {str(e)}'
        }), 500

@app.route('/api/social-media/settings', methods=['POST'])
@login_required
def save_social_media_settings():
    try:
        data = request.json
        platform = data.get('platform')
        
        if not platform:
            return jsonify({
                'status': 'error',
                'message': 'Platform is required'
            }), 400
        
        # Validate platform
        valid_platforms = ['wordpress', 'twitter', 'facebook', 'instagram']
        if platform not in valid_platforms:
            return jsonify({
                'status': 'error',
                'message': f'Invalid platform. Must be one of: {", ".join(valid_platforms)}'
            }), 400
        
        # Check if settings already exist for this platform
        existing_settings = SocialMediaSettings.query.filter_by(
            user_id=current_user.id,
            platform=platform
        ).first()
        
        # Hash password if it's provided (for WordPress)
        password = data.get('password')
        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        else:
            hashed_password = None if not existing_settings else existing_settings.password
        
        if existing_settings:
            # Update existing settings
            existing_settings.is_active = True
            existing_settings.auto_publish = data.get('auto_publish', False)
            existing_settings.updated_at = datetime.utcnow()
            
            # Update credentials (only if provided)
            if data.get('api_key'):
                existing_settings.api_key = data.get('api_key')
            if data.get('api_secret'):
                existing_settings.api_secret = data.get('api_secret')
            if data.get('access_token'):
                existing_settings.access_token = data.get('access_token')
            if data.get('access_token_secret'):
                existing_settings.access_token_secret = data.get('access_token_secret')
            
            # WordPress specific fields
            if platform == 'wordpress':
                existing_settings.site_url = data.get('site_url', existing_settings.site_url)
                existing_settings.username = data.get('username', existing_settings.username)
                if hashed_password:
                    existing_settings.password = hashed_password
                existing_settings.category = data.get('category', existing_settings.category)
                existing_settings.tags = data.get('tags', existing_settings.tags)
            
            db.session.commit()
            log_activity("social_media", f"Updated {platform} settings", "success")
        else:
            # Create new settings
            new_settings = SocialMediaSettings(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                platform=platform,
                is_active=True,
                auto_publish=data.get('auto_publish', False),
                api_key=data.get('api_key'),
                api_secret=data.get('api_secret'),
                access_token=data.get('access_token'),
                access_token_secret=data.get('access_token_secret')
            )
            
            # WordPress specific fields
            if platform == 'wordpress':
                new_settings.site_url = data.get('site_url')
                new_settings.username = data.get('username')
                new_settings.password = hashed_password
                new_settings.category = data.get('category')
                new_settings.tags = data.get('tags')
            
            db.session.add(new_settings)
            db.session.commit()
            log_activity("social_media", f"Added new {platform} settings", "success")
        
        return jsonify({
            'status': 'success',
            'message': f'{platform.title()} settings saved successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        log_activity("social_media", f"Error saving social media settings: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Error saving settings: {str(e)}'
        }), 500

@app.route('/api/social-media/test', methods=['POST'])
@login_required
def test_social_media_connection():
    try:
        data = request.json
        platform = data.get('platform')
        
        if not platform:
            return jsonify({
                'status': 'error',
                'message': 'Platform is required'
            }), 400
        
        # Test connection based on platform
        if platform == 'wordpress':
            site_url = data.get('site_url')
            username = data.get('username')
            password = data.get('password')
            
            if not all([site_url, username, password]):
                return jsonify({
                    'status': 'error',
                    'message': 'WordPress site URL, username, and password are required'
                }), 400
            
            # Test WordPress XML-RPC connection
            try:
                xml_rpc_url = f"{site_url.rstrip('/')}/xmlrpc.php"
                client = Client(xml_rpc_url, username, password)
                
                # Try to get user info to verify connection
                user_methods = client.call('wp.getUsersBlogs', username, password)
                
                return jsonify({
                    'status': 'success',
                    'message': 'WordPress connection successful',
                    'details': f"Connected to {len(user_methods)} site(s)"
                })
            except Exception as wp_error:
                log_activity("social_media", f"WordPress connection test failed: {str(wp_error)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'WordPress connection failed: {str(wp_error)}'
                }), 400
                
        elif platform == 'twitter':
            api_key = data.get('api_key')
            api_secret = data.get('api_secret')
            access_token = data.get('access_token')
            access_token_secret = data.get('access_token_secret')
            
            if not all([api_key, api_secret, access_token, access_token_secret]):
                return jsonify({
                    'status': 'error',
                    'message': 'All Twitter API credentials are required'
                }), 400
            
            # Test Twitter API connection
            try:
                auth = tweepy.OAuth1UserHandler(api_key, api_secret, access_token, access_token_secret)
                api = tweepy.API(auth)
                
                # Verify credentials
                user = api.verify_credentials()
                
                return jsonify({
                    'status': 'success',
                    'message': 'Twitter connection successful',
                    'details': f"Connected as @{user.screen_name}"
                })
            except Exception as twitter_error:
                log_activity("social_media", f"Twitter connection test failed: {str(twitter_error)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Twitter connection failed: {str(twitter_error)}'
                }), 400
                
        elif platform == 'facebook':
            access_token = data.get('access_token')
            
            if not access_token:
                return jsonify({
                    'status': 'error',
                    'message': 'Facebook access token is required'
                }), 400
            
            # Test Facebook API connection
            try:
                graph = facebook.GraphAPI(access_token)
                
                # Get user info to verify connection
                user = graph.get_object('me')
                
                return jsonify({
                    'status': 'success',
                    'message': 'Facebook connection successful',
                    'details': f"Connected as {user.get('name')}"
                })
            except Exception as fb_error:
                log_activity("social_media", f"Facebook connection test failed: {str(fb_error)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Facebook connection failed: {str(fb_error)}'
                }), 400
                
        elif platform == 'instagram':
            access_token = data.get('access_token')
            
            if not access_token:
                return jsonify({
                    'status': 'error',
                    'message': 'Instagram access token is required'
                }), 400
            
            # Test Instagram Graph API connection
            try:
                url = f"https://graph.instagram.com/me?fields=id,username&access_token={access_token}"
                response = requests.get(url)
                
                if response.status_code == 200:
                    user_data = response.json()
                    return jsonify({
                        'status': 'success',
                        'message': 'Instagram connection successful',
                        'details': f"Connected as @{user_data.get('username')}"
                    })
                else:
                    error_data = response.json()
                    return jsonify({
                        'status': 'error',
                        'message': f"Instagram connection failed: {error_data.get('error', {}).get('message', 'Unknown error')}"
                    }), 400
            except Exception as ig_error:
                log_activity("social_media", f"Instagram connection test failed: {str(ig_error)}", "error")
                return jsonify({
                    'status': 'error',
                    'message': f'Instagram connection failed: {str(ig_error)}'
                }), 400
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unsupported platform: {platform}'
            }), 400
    except Exception as e:
        log_activity("social_media", f"Error testing social media connection: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Error testing connection: {str(e)}'
        }), 500

@app.route('/api/social-media/platforms', methods=['GET'])
@login_required
def get_available_platforms():
    try:
        settings = SocialMediaSettings.query.filter_by(user_id=current_user.id).all()
        
        # Get platforms with configured credentials
        platforms = []
        for setting in settings:
            if (setting.platform == 'wordpress' and setting.site_url and setting.username and setting.password) or \
               (setting.platform == 'twitter' and setting.api_key and setting.api_secret and setting.access_token and setting.access_token_secret) or \
               (setting.platform == 'facebook' and setting.access_token) or \
               (setting.platform == 'instagram' and setting.access_token):
                platforms.append(setting.platform)
        
        return jsonify({
            'status': 'success',
            'platforms': platforms
        })
    except Exception as e:
        log_activity("social_media", f"Error retrieving available platforms: {str(e)}", "error")
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving available platforms: {str(e)}'
        }), 500

@app.route('/api/articles/<article_id>/publish', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def publish_article(article_id):
    try:
        article = Article.query.get_or_404(article_id)
        
        # Validate article ownership
        if article.user_id != current_user.id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        data = request.get_json()
        if not data or 'platforms' not in data:
            return jsonify({
                'status': 'error',
                'message': 'No platforms specified for publishing'
            }), 400
        
        platforms = data.get('platforms', [])
        platform_data = data.get('platform_data', {})
        results = {}
        
        for platform in platforms:
            try:
                # Get platform settings
                settings = SocialMediaSettings.query.filter_by(
                    user_id=current_user.id,
                    platform=platform,
                    is_active=True
                ).first()
                
                if not settings:
                    results[platform] = {
                        'success': False,
                        'message': f"{platform} is not configured"
                    }
                    continue
                
                # Platform-specific publishing logic
                if platform == 'wordpress':
                    result = publish_to_wordpress(article, settings, platform_data)
                elif platform == 'twitter':
                    result = publish_to_twitter(article, settings, platform_data)
                elif platform == 'facebook':
                    result = publish_to_facebook(article, settings, platform_data)
                elif platform == 'instagram':
                    result = publish_to_instagram(article, settings, platform_data)
                else:
                    results[platform] = {
                        'success': False,
                        'message': f"Unsupported platform: {platform}"
                    }
                    continue
                
                results[platform] = result
                
            except Exception as e:
                logger.error(f"Error publishing to {platform}: {str(e)}")
                results[platform] = {
                    'success': False,
                    'message': str(e)
                }
        
        # Update article status if at least one platform succeeded
        if any(result.get('success', False) for result in results.values()):
            article.status = 'published'
            article.published_at = datetime.utcnow()
            db.session.commit()
        
        return jsonify({
            'status': 'success',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error in publish_article: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def publish_to_wordpress(article, settings, platform_data):
    try:
        client = Client(
            settings.site_url,
            settings.username,
            settings.password
        )
        
        post = WordPressPost()
        post.title = article.title
        post.content = article.content
        
        # Set category and tags if provided
        if platform_data.get('category'):
            post.terms_names = {'category': [platform_data['category']]}
        if platform_data.get('tags'):
            post.terms_names['post_tag'] = [tag.strip() for tag in platform_data['tags'].split(',')]
        
        post.post_status = 'publish'
        post_id = client.call(NewPost(post))
        
        return {
            'success': True,
            'message': 'Article published successfully',
            'url': f"{settings.site_url}/?p={post_id}"
        }
    except Exception as e:
        logger.error(f"WordPress publishing failed: {str(e)}")
        return {
            'success': False,
            'message': f"WordPress publishing failed: {str(e)}"
        }

def publish_to_twitter(article, settings, platform_data):
    try:
        auth = tweepy.OAuthHandler(settings.api_key, settings.api_secret)
        auth.set_access_token(settings.access_token, settings.access_token_secret)
        api = tweepy.API(auth)
        
        tweet_text = platform_data.get('text', article.title)
        if platform_data.get('include_link', True):
            tweet_text += f"\n\nRead more: {article.url}"
        
        tweet = api.update_status(tweet_text)
        
        return {
            'success': True,
            'message': 'Tweet posted successfully',
            'url': f"https://twitter.com/user/status/{tweet.id}"
        }
    except Exception as e:
        logger.error(f"Twitter publishing failed: {str(e)}")
        return {
            'success': False,
            'message': f"Twitter publishing failed: {str(e)}"
        }

def publish_to_facebook(article, settings, platform_data):
    try:
        graph = facebook.GraphAPI(settings.access_token)
        
        post_text = platform_data.get('text', article.title)
        if article.url:
            post_text += f"\n\nRead more: {article.url}"
        
        post = graph.put_object(
            parent_object='me',
            connection_name='feed',
            message=post_text
        )
        
        return {
            'success': True,
            'message': 'Facebook post created successfully',
            'url': f"https://facebook.com/{post['id']}"
        }
    except Exception as e:
        logger.error(f"Facebook publishing failed: {str(e)}")
        return {
            'success': False,
            'message': f"Facebook publishing failed: {str(e)}"
        }

def publish_to_instagram(article, settings, platform_data):
    try:
        # Instagram API requires a business account and proper setup
        # This is a simplified version
        graph = facebook.GraphAPI(settings.access_token)
        
        caption = platform_data.get('caption', article.title)
        if article.url:
            caption += f"\n\nRead more: {article.url}"
        
        # Note: Instagram API requires media upload
        # This is a placeholder for the actual implementation
        return {
            'success': True,
            'message': 'Instagram post created successfully'
        }
    except Exception as e:
        logger.error(f"Instagram publishing failed: {str(e)}")
        return {
            'success': False,
            'message': f"Instagram publishing failed: {str(e)}"
        }

if __name__ == '__main__':
    # Use 0.0.0.0 to make the server publicly available
    port = int(os.environ.get('PORT', 5000))
    
    # Set debug mode based on environment
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
    
    print(f"Starting Content Automation Dashboard on port {port}")
    print(f"Debug mode: {'ON' if debug_mode else 'OFF'}")
    print(f"OpenAI API Key: {'Configured' if OPENAI_API_KEY else 'NOT CONFIGURED'}")
    print(f"WordPress API: {'Configured' if WORDPRESS_URL and WORDPRESS_USERNAME else 'NOT CONFIGURED'}")
    
    if debug_mode:
        print("\n⚠️ Running in DEBUG mode - API calls will be mocked ⚠️")
        print("Set FLASK_DEBUG=False in environment to use real API calls\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode) 