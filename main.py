from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import uuid

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///linktr.db'
app.config['JWT_SECRET_KEY'] = '48a2b1412047d0eaa7485d69e9ecc996df7de9629180edc2bd71450e071ddaeb'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# Database Models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    referral_code = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4())[:8])
    referred_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    referred_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    date_referred = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], email=data['email'], password_hash=hashed_password)

    # Handle referral
    if 'referral_code' in data and data['referral_code']:
        referrer = User.query.filter_by(referral_code=data['referral_code']).first()
        if referrer:
            user.referred_by = referrer.id

    db.session.add(user)
    db.session.commit()

    if user.referred_by:
        referral = Referral(referrer_id=user.referred_by, referred_user_id=user.id)
        db.session.add(referral)
        db.session.commit()

    return jsonify({'message': 'User registered successfully', 'referral_code': user.referral_code}), 201


# User Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter((User.email == data.get('email')) | (User.username == data.get('username'))).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(days=1))
        return jsonify({'access_token': access_token}), 200
    return jsonify({'error': 'Invalid credentials'}), 401


# Referral Statistics
@app.route('/api/referrals', methods=['GET'])
@jwt_required()
def get_referrals():
    user_id = get_jwt_identity()
    referrals = Referral.query.filter_by(referrer_id=user_id).all()
    referred_users = [{'referred_user_id': r.referred_user_id, 'date_referred': r.date_referred} for r in referrals]
    return jsonify({'referrals': referred_users}), 200


# Forgot Password
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user:
        reset_token = str(uuid.uuid4())
        return jsonify({'message': 'Password reset link sent', 'reset_token': reset_token}), 200
    return jsonify({'error': 'Email not found'}), 404


# Default Route
@app.route('/', methods=['GET'])
def home():
    return "Flask is running!"


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database is set up
    print(app.url_map)  # Debugging: Print available routes
    app.run(debug=True)
