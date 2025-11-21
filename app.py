import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from flask_cors import CORS

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'elitefix-secret-key-2025')

# Configure CORS for Vercel frontend
CORS(app, origins=[
    "http://localhost:3000",
    "https://your-vercel-app.vercel.app",  # Replace with your Vercel URL
    "https://*.vercel.app"
])

# Use PostgreSQL in production
if os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elitefix.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models (same as before)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_vip = db.Column(db.Boolean, default=False)
    vip_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at

class VipCorrectScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match = db.Column(db.String(200), nullable=False)
    score = db.Column(db.String(20), nullable=False)
    odd = db.Column(db.Float, nullable=False)
    result = db.Column(db.String(10))
    status = db.Column(db.String(20), default='pending')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    is_today = db.Column(db.Boolean, default=True)

class ComboTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match = db.Column(db.String(200), nullable=False)
    tip = db.Column(db.String(10), nullable=False)
    odd = db.Column(db.Float, nullable=False)
    result = db.Column(db.String(10))
    status = db.Column(db.String(20), default='pending')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    is_today = db.Column(db.Boolean, default=True)

class PremiumTip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match = db.Column(db.String(200), nullable=False)
    tip = db.Column(db.String(10), nullable=False)
    odd = db.Column(db.Float, nullable=False)
    result = db.Column(db.String(10))
    status = db.Column(db.String(20), default='pending')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    is_today = db.Column(db.Boolean, default=True)

class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Remove the main route since we're serving frontend from Vercel
@app.route('/')
def home():
    return jsonify({
        "message": "EliteFix Tips API is running!",
        "status": "success",
        "frontend_url": "https://your-vercel-app.vercel.app"  # Update this
    })

# API Routes (same as before but without templates)
@app.route('/api/vip-correct-today')
def get_vip_correct_today():
    games = VipCorrectScore.query.filter_by(is_today=True).all()
    return jsonify([{
        'match': game.match,
        'score': game.score,
        'odd': game.odd,
        'result': game.result,
        'status': game.status
    } for game in games])

@app.route('/api/vip-correct-previous')
def get_vip_correct_previous():
    games = VipCorrectScore.query.filter_by(is_today=False).order_by(VipCorrectScore.date.desc()).limit(10).all()
    return jsonify([{
        'date': game.date.strftime('%Y-%m-%d'),
        'match': game.match,
        'score': game.score,
        'odd': game.odd,
        'result': game.result
    } for game in games])

@app.route('/api/combo-today')
def get_combo_today():
    games = ComboTicket.query.filter_by(is_today=True).all()
    return jsonify([{
        'match': game.match,
        'tip': game.tip,
        'odd': game.odd,
        'result': game.result,
        'status': game.status
    } for game in games])

@app.route('/api/combo-previous')
def get_combo_previous():
    games = ComboTicket.query.filter_by(is_today=False).order_by(ComboTicket.date.desc()).limit(10).all()
    return jsonify([{
        'date': game.date.strftime('%Y-%m-%d'),
        'matches': "5 Games",
        'totalOdd': game.odd,
        'result': game.result
    } for game in games])

@app.route('/api/premium-today')
def get_premium_today():
    games = PremiumTip.query.filter_by(is_today=True).all()
    return jsonify([{
        'match': game.match,
        'tip': game.tip,
        'odd': game.odd,
        'result': game.result,
        'status': game.status
    } for game in games])

@app.route('/api/premium-history')
def get_premium_history():
    games = PremiumTip.query.filter_by(is_today=False).order_by(PremiumTip.date.desc()).limit(10).all()
    return jsonify([{
        'date': game.date.strftime('%Y-%m-%d'),
        'match': game.match,
        'tip': game.tip,
        'odd': game.odd,
        'result': game.result
    } for game in games])

@app.route('/api/testimonials')
def get_testimonials():
    testimonials = Testimonial.query.order_by(Testimonial.created_at.desc()).limit(6).all()
    return jsonify([{
        'name': testimonial.name,
        'text': testimonial.text
    } for testimonial in testimonials])

# Authentication Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({'success': True, 'is_vip': user.is_vip})
    
    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'success': False, 'message': 'Username already exists'})
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'success': False, 'message': 'Email already exists'})
    
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    login_user(user)
    return jsonify({'success': True})

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

# Password Reset Routes
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
        
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at
        )
        
        db.session.add(reset_token)
        db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': 'If an account with that email exists, a password reset link has been sent.'
    })

@app.route('/api/validate-reset-token/<token>')
def validate_reset_token(token):
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    
    if reset_token and reset_token.is_valid():
        return jsonify({'valid': True, 'message': 'Token is valid'})
    else:
        return jsonify({'valid': False, 'message': 'Invalid or expired token'}), 400

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    
    if not reset_token or not reset_token.is_valid():
        return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400
    
    user = User.query.get(reset_token.user_id)
    user.set_password(new_password)
    reset_token.used = True
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password has been reset successfully'})

# Admin Routes
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    if data.get('password') == 'admin123':
        session['is_admin'] = True
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/api/admin/data')
def get_admin_data():
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({
        'vipCorrectToday': [{
            'id': game.id,
            'match': game.match,
            'score': game.score,
            'odd': game.odd,
            'result': game.result,
            'status': game.status
        } for game in VipCorrectScore.query.filter_by(is_today=True).all()]
    })

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        
        if not User.query.first():
            admin = User(username='admin', email='admin@elitefixtips.com')
            admin.set_password('admin123')
            admin.is_vip = True
            db.session.add(admin)
        
        if not VipCorrectScore.query.first():
            sample_vip = VipCorrectScore(
                match="Barcelona - Real Madrid",
                score="2-1",
                odd=12.00,
                status="pending",
                is_today=True
            )
            db.session.add(sample_vip)
            
            testimonial1 = Testimonial(
                name="James K.",
                text="EliteFix Tips has completely transformed my betting strategy!"
            )
            db.session.add(testimonial1)
            
            db.session.commit()
        print("✅ Database initialized successfully!")

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)