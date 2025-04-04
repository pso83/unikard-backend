from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unikard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['JWT_SECRET_KEY'] = 'unikard-jwt-secret-key'

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
jwt = JWTManager(app)

# Modèles
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100))
    is_merchant = db.Column(db.Boolean, default=False)

class Commerce(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User')

class Point(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    commerce_id = db.Column(db.Integer, db.ForeignKey('commerce.id'))
    amount = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Tampon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    commerce_id = db.Column(db.Integer, db.ForeignKey('commerce.id'))
    count = db.Column(db.Integer, default=0)
    threshold = db.Column(db.Integer, default=10)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commerce_id = db.Column(db.Integer, db.ForeignKey('commerce.id'))
    label = db.Column(db.String(100), nullable=False)
    threshold = db.Column(db.Integer, default=10)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return "Unikard API en ligne."

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data['email']
    password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    name = data.get('name', '')
    is_merchant = data.get('is_merchant', False)
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email déjà utilisé."}), 400
    user = User(email=email, password=password, name=name, is_merchant=is_merchant)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Utilisateur enregistré."})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
        return jsonify({
            "message": "Connexion réussie",
            "token": token,
            "user_id": user.id,
            "name": user.name,
            "is_merchant": user.is_merchant
        })
    return jsonify({"error": "Identifiants invalides."}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Déconnexion réussie."})

@app.route('/commerce', methods=['POST'])
@jwt_required()
def create_commerce():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_merchant:
        return jsonify({"error": "Seuls les commerçants peuvent créer un commerce."}), 403
    data = request.json
    name = data.get('name')
    commerce = Commerce(name=name, owner_id=user_id)
    db.session.add(commerce)
    db.session.commit()
    return jsonify({"message": "Commerce créé.", "commerce_id": commerce.id})

@app.route('/rewards', methods=['POST'])
@jwt_required()
def create_reward():
    user_id = get_jwt_identity()
    data = request.json
    commerce_id = data.get('commerce_id')
    label = data.get('label')
    threshold = data.get('threshold', 10)
    reward = Reward(commerce_id=commerce_id, label=label, threshold=threshold)
    db.session.add(reward)
    db.session.commit()
    return jsonify({"message": "Récompense enregistrée."})

@app.route('/rewards/<int:commerce_id>', methods=['GET'])
@jwt_required()
def get_rewards(commerce_id):
    rewards = Reward.query.filter_by(commerce_id=commerce_id).all()
    result = [{"label": r.label, "threshold": r.threshold} for r in rewards]
    return jsonify(result)

@app.route('/commerce', methods=['GET'])
@jwt_required()
def get_commerces():
    user_id = get_jwt_identity()
    commerces = Commerce.query.filter_by(owner_id=user_id).all()
    result = [{"id": c.id, "name": c.name} for c in commerces]
    return jsonify(result)

@app.route('/points', methods=['POST'])
@jwt_required()
def add_points():
    user_id = get_jwt_identity()
    data = request.json
    commerce_id = data.get('commerce_id')
    amount = data.get('amount', 10)
    point = Point(user_id=user_id, commerce_id=commerce_id, amount=amount)
    db.session.add(point)
    db.session.commit()
    return jsonify({"message": "Points ajoutés.", "amount": amount})

@app.route('/points', methods=['GET'])
@jwt_required()
def get_points():
    user_id = get_jwt_identity()
    commerce_id = request.args.get('commerce_id')
    query = Point.query.filter_by(user_id=user_id)
    if commerce_id:
        query = query.filter_by(commerce_id=commerce_id)
    points = query.all()
    result = [{"commerce_id": p.commerce_id, "amount": p.amount, "timestamp": p.timestamp} for p in points]
    return jsonify(result)

@app.route('/tampons', methods=['POST'])
@jwt_required()
def add_tampon():
    user_id = get_jwt_identity()
    data = request.json
    commerce_id = data.get('commerce_id')
    tampon = Tampon.query.filter_by(user_id=user_id, commerce_id=commerce_id).first()
    if not tampon:
        tampon = Tampon(user_id=user_id, commerce_id=commerce_id, count=1)
        db.session.add(tampon)
    else:
        tampon.count += 1
        tampon.last_updated = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Tampon ajouté.", "total": tampon.count})

@app.route('/tampons', methods=['GET'])
@jwt_required()
def get_tampons():
    user_id = get_jwt_identity()
    commerce_id = request.args.get('commerce_id')
    query = Tampon.query.filter_by(user_id=user_id)
    if commerce_id:
        query = query.filter_by(commerce_id=commerce_id)
    tampons = query.all()
    result = [{"commerce_id": t.commerce_id, "count": t.count, "threshold": t.threshold, "last_updated": t.last_updated} for t in tampons]
    return jsonify(result)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
