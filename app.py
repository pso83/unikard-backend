from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from generate_android_pass import generate_enhanced_android_pass
import os

# Crée le dossier 'static' s'il n'existe pas
os.makedirs("static", exist_ok=True)

app = Flask(__name__)
# Configuration CORS correcte et exclusive
CORS(app,
     resources={r"/*": {"origins": "http://localhost:5173"}},
     supports_credentials=True)

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
commerce_users = db.Table('commerce_users',
                          db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                          db.Column('commerce_id', db.Integer, db.ForeignKey('commerce.id'), primary_key=True)
                          )

# Met à jour les relations
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100))
    is_merchant = db.Column(db.Boolean, default=False)
    referrer_commerce = db.Column(db.Integer, nullable=True)

    commerces = db.relationship('Commerce', secondary=commerce_users, backref='clients')

class Commerce(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100))
    address = db.Column(db.String(255))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(120))
    hours = db.Column(db.String(255))
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

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    commerce_id = db.Column(db.Integer, db.ForeignKey('commerce.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # "point" ou "tampon"
    amount = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    referrer_commerce = data.get('referrer_commerce')

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email déjà utilisé."}), 400

    user = User(email=email, password=password, name=name, is_merchant=is_merchant, referrer_commerce=referrer_commerce)
    db.session.add(user)
    db.session.commit()

    if is_merchant:
        commerce = Commerce(
            name="Nouveau Commerce",
            type="",
            address="",
            phone="",
            email=email,
            hours="",
            owner_id=user.id
        )
        db.session.add(commerce)
        db.session.commit()

    return jsonify({"message": "Utilisateur enregistré."})

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        return jsonify([
            {
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "is_merchant": u.is_merchant,
                "referrer_commerce": u.referrer_commerce
            } for u in users
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    print("Tentative de connexion pour :", email)  # Ajoute cette ligne
    user = User.query.filter_by(email=email).first()

    if user:
        print("Utilisateur trouvé :", user.email)  # Ajoute cette ligne
        if bcrypt.check_password_hash(user.password, password):
            print("Mot de passe correct")  # Ajoute cette ligne
            token = create_access_token(identity=str(user.id))
            return jsonify({
                "token": token,
                "is_merchant": user.is_merchant,
                "name": user.name,
                "user_id": user.id
            })
        else:
            print("❌ Mot de passe invalide")  # Debug
    else:
        print("❌ Aucun utilisateur trouvé")  # Debug

    return jsonify({"error": "Identifiants invalides"}), 401


@app.route('/commerce', methods=['GET'])
@jwt_required()
def get_commerce():
    user_id = get_jwt_identity()
    commerce = Commerce.query.filter_by(owner_id=user_id).first()
    if not commerce:
        return jsonify({"error": "Commerce non trouvé"}), 404
    return jsonify({
        "id": commerce.id,
        "name": commerce.name,
        "type": commerce.type,
        "address": commerce.address,
        "phone": commerce.phone,
        "email": commerce.email,
        "hours": commerce.hours
    })

@app.route('/commerce', methods=['PUT'])
@jwt_required()
def update_commerce():
    user_id = get_jwt_identity()
    data = request.get_json()
    commerce = Commerce.query.filter_by(owner_id=user_id).first()
    if not commerce:
        return jsonify({"error": "Commerce non trouvé"}), 404
    commerce.name = data.get('name', commerce.name)
    commerce.type = data.get('type', commerce.type)
    commerce.address = data.get('address', commerce.address)
    commerce.phone = data.get('phone', commerce.phone)
    commerce.email = data.get('email', commerce.email)
    commerce.hours = data.get('hours', commerce.hours)
    db.session.commit()
    return jsonify({"message": "Commerce mis à jour"})

@app.route('/rewards', methods=['GET'])
@jwt_required()
def get_rewards():
    user_id = get_jwt_identity()
    commerce = Commerce.query.filter_by(owner_id=user_id).first()
    rewards = Reward.query.filter_by(commerce_id=commerce.id).all()
    return jsonify([
        {"id": r.id, "label": r.label, "threshold": r.threshold} for r in rewards
    ])

@app.route('/rewards', methods=['POST'])
@jwt_required()
def add_reward():
    user_id = get_jwt_identity()
    data = request.get_json()
    commerce = Commerce.query.filter_by(owner_id=user_id).first()
    reward = Reward(
        commerce_id=commerce.id,
        label=data['label'],
        threshold=data.get('threshold', 10)
    )
    db.session.add(reward)
    db.session.commit()
    return jsonify({"message": "Récompense ajoutée."})

@app.route('/commerce/<int:commerce_id>/stats', methods=['GET'])
def get_commerce_stats(commerce_id):
    nb_clients = User.query.filter_by(referrer_commerce=commerce_id).count()
    nb_tampons = Tampon.query.filter_by(commerce_id=commerce_id).with_entities(db.func.sum(Tampon.count)).scalar() or 0
    nb_rewards = Reward.query.filter_by(commerce_id=commerce_id).count()
    return jsonify({
        "clients": nb_clients,
        "tampons": nb_tampons,
        "rewards": nb_rewards
    })

@app.route('/client/<int:user_id>/stats', methods=['GET'])
def get_client_stats(user_id):
    total_points = Point.query.filter_by(user_id=user_id).with_entities(db.func.sum(Point.amount)).scalar() or 0
    total_tampons = Tampon.query.filter_by(user_id=user_id).with_entities(db.func.sum(Tampon.count)).scalar() or 0
    return jsonify({"points": total_points, "tampons": total_tampons})

@app.route('/client/<int:user_id>', methods=['DELETE'])
def delete_client(user_id):
    user = User.query.get(user_id)
    if not user or user.is_merchant:
        return jsonify({"error": "Client introuvable ou invalide"}), 404
    Point.query.filter_by(user_id=user_id).delete()
    Tampon.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Client supprimé."})

@app.route('/user/referrer', methods=['PUT'])
@jwt_required()
def update_referrer():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_commerce_id = data.get('referrer_commerce')

    user = User.query.get(user_id)
    if not user or user.is_merchant:
        return jsonify({"error": "Utilisateur non valide"}), 403

    commerce = Commerce.query.get(new_commerce_id)
    if not commerce:
        return jsonify({"error": "Commerce introuvable"}), 404

    user.referrer_commerce = new_commerce_id
    db.session.commit()
    return jsonify({"message": "Commerce affilié mis à jour."})

@app.route('/generate_android_card/<int:user_id>', methods=['GET'])
@jwt_required()
def generate_android_card(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    # Récupérer le commerce lié
    commerce = Commerce.query.filter_by(id=user.referrer_commerce).first()
    if not commerce:
        return jsonify({"error": "Commerce non trouvé"}), 404

    # Générer le fichier
    filename = generate_enhanced_android_pass(user.name, user.id, commerce.name)

    return jsonify({"url": f"http://localhost:5000/{filename}"})

@app.route('/user/<int:user_id>/assign_commerce', methods=['PATCH'])
@jwt_required()
def assign_commerce(user_id):
    data = request.get_json()
    commerce_id = data.get('commerce_id')
    user = User.query.get(user_id)

    if not user or user.is_merchant:
        return jsonify({"error": "Utilisateur non valide"}), 400

    user.referrer_commerce = commerce_id
    db.session.commit()
    return jsonify({"message": "Commerce assigné"})

@app.route('/assign_user_to_commerce', methods=['POST'])
@jwt_required()
def assign_user_to_commerce():
    data = request.get_json()
    user_id = data.get('user_id')
    commerce_id = data.get('commerce_id')

    user = User.query.get(user_id)
    commerce = Commerce.query.get(commerce_id)

    if not user or not commerce:
        return jsonify({"error": "Utilisateur ou commerce introuvable."}), 404

    if user in commerce.clients:
        return jsonify({"message": "Utilisateur déjà assigné."}), 200

    commerce.clients.append(user)
    db.session.commit()

    return jsonify({"message": "Utilisateur assigné au commerce."})

@app.route('/commerce/<int:commerce_id>/clients', methods=['GET'])
@jwt_required()
def get_clients_for_commerce(commerce_id):
    clients = User.query.filter_by(referrer_commerce=commerce_id, is_merchant=False).all()
    return jsonify([
        {"id": c.id, "name": c.name, "email": c.email} for c in clients
    ])

@app.route('/commerce/<int:commerce_id>/add_points', methods=['POST'])
@jwt_required()
def add_points(commerce_id):
    data = request.json
    user_id = data.get("user_id")
    amount = data.get("amount", 1)
    point = Point(user_id=user_id, commerce_id=commerce_id, amount=amount)
    db.session.add(point)
    db.session.commit()
    return jsonify({"message": f"{amount} point(s) ajouté(s)"})

@app.route('/commerce/<int:commerce_id>/add_tampon', methods=['POST'])
@jwt_required()
def add_tampon(commerce_id):
    data = request.json
    user_id = data.get("user_id")
    tampon = Tampon.query.filter_by(user_id=user_id, commerce_id=commerce_id).first()
    if tampon:
        tampon.count += 1
        tampon.last_updated = datetime.utcnow()
    else:
        tampon = Tampon(user_id=user_id, commerce_id=commerce_id, count=1)
        db.session.add(tampon)
    db.session.commit()
    return jsonify({"message": "Tampon ajouté"})

@app.route('/assigned_users', methods=['GET'])
@jwt_required()
def get_assigned_users():
    user_id = get_jwt_identity()

    # On récupère le commerce du commerçant connecté
    commerce = Commerce.query.filter_by(owner_id=user_id).first()
    if not commerce:
        return jsonify({"error": "Commerce non trouvé"}), 404

    # On récupère les utilisateurs qui sont liés à ce commerce
    users = User.query.filter_by(referrer_commerce=commerce.id, is_merchant=False).all()

    return jsonify([
        {
            "id": user.id,
            "email": user.email,
            "name": user.name
        }
        for user in users
    ])

@app.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    data = request.get_json()
    user_id = data.get('user_id')
    commerce_id = data.get('commerce_id')
    type_ = data.get('type')  # "points" ou "tampons"
    amount = data.get('amount')

    if not user_id or not commerce_id or not type_ or not amount:
        return jsonify({"error": "Champs manquants"}), 400

    transaction = Transaction(
        user_id=user_id,
        commerce_id=commerce_id,
        type=type_,
        amount=amount
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({"message": "Transaction enregistrée."})

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user.is_merchant:
        # Côté commerçant : voir les transactions liées à son commerce
        commerce = Commerce.query.filter_by(owner_id=user_id).first()
        points = Point.query.filter_by(commerce_id=commerce.id).all()
        tampons = Tampon.query.filter_by(commerce_id=commerce.id).all()
    else:
        # Côté client : voir ses propres transactions
        points = Point.query.filter_by(user_id=user_id).all()
        tampons = Tampon.query.filter_by(user_id=user_id).all()

    transactions = []

    for p in points:
        transactions.append({
            "type": "Points",
            "amount": p.amount,
            "timestamp": p.timestamp.strftime("%Y-%m-%d %H:%M"),
            "user_id": p.user_id,
            "commerce_id": p.commerce_id
        })

    for t in tampons:
        transactions.append({
            "type": "Tampons",
            "amount": t.count,
            "timestamp": t.last_updated.strftime("%Y-%m-%d %H:%M"),
            "user_id": t.user_id,
            "commerce_id": t.commerce_id
        })

    # Trier du plus récent au plus ancien
    transactions.sort(key=lambda x: x['timestamp'], reverse=True)

    return jsonify(transactions)

@app.route('/validate_reward/<int:reward_id>', methods=['POST'])
@jwt_required()
def validate_reward(reward_id):
    user_id = get_jwt_identity()
    # Vérifier conditions (points ou tampons)
    # Marquer comme utilisé
    # Ajouter une transaction
    return jsonify({"message": "Récompense validée"})

@app.route('/commerce/<int:commerce_id>/clients', methods=['GET'])
@jwt_required()
def get_commerce_clients(commerce_id):
    commerce = Commerce.query.get(commerce_id)
    if not commerce:
        return jsonify({"error": "Commerce non trouvé."}), 404

    return jsonify([
        {"id": u.id, "name": u.name, "email": u.email}
        for u in commerce.clients
    ])

@app.route('/commerce/<int:commerce_id>/users', methods=['GET'])
@jwt_required()
def get_commerce_users(commerce_id):
    users = db.session.query(User).join(commerce_users).filter(commerce_users.c.commerce_id == commerce_id).all()
    return jsonify([
        {
            "id": user.id,
            "name": user.name,
            "email": user.email
        } for user in users
    ])

@app.route('/transactions/merchant', methods=['GET'])
@jwt_required()
def get_merchant_transactions():
    user_id = get_jwt_identity()

    # Récupérer le commerce du marchand connecté
    commerce = Commerce.query.filter_by(owner_id=user_id).first()
    if not commerce:
        return jsonify({"error": "Commerce non trouvé"}), 404

    # Récupérer toutes les transactions liées à ce commerce
    transactions = Transaction.query.filter_by(commerce_id=commerce.id).order_by(Transaction.timestamp.desc()).all()

    return jsonify([
        {
            "type": t.type,
            "amount": t.amount,
            "user_id": t.user_id,
            "timestamp": t.timestamp.isoformat()
        } for t in transactions
    ])


@app.route('/transactions/client', methods=['GET'])
@jwt_required()
def get_client_transactions():
    user_id = get_jwt_identity()

    points = Point.query.filter_by(user_id=user_id).all()
    tampons = Tampon.query.filter_by(user_id=user_id).all()

    transactions = []

    for p in points:
        transactions.append({
            "id": p.id,
            "commerce_id": p.commerce_id,
            "type": "points",
            "amount": p.amount,
            "timestamp": p.timestamp.isoformat()
        })

    for t in tampons:
        transactions.append({
            "id": t.id,
            "commerce_id": t.commerce_id,
            "type": "tampons",
            "amount": t.count,
            "timestamp": t.last_updated.isoformat()
        })

    transactions.sort(key=lambda x: x["timestamp"], reverse=True)

    return jsonify(transactions)

@app.route('/commerce/create', methods=['POST'])
@jwt_required()
def create_commerce():
    # Ne force pas la lecture du body s’il n’est pas utile
    try:
        _ = request.get_json(force=False, silent=True)  # ← évite erreur si vide
    except Exception:
        pass

    user_id = get_jwt_identity()
    existing = Commerce.query.filter_by(owner_id=user_id).first()
    if existing:
        return jsonify({"error": "Un commerce existe déjà pour cet utilisateur."}), 400

    new_commerce = Commerce(
        name="Nouveau Commerce",
        type="",
        address="",
        phone="",
        email="",
        hours="",
        owner_id=user_id
    )
    db.session.add(new_commerce)
    db.session.commit()
    return jsonify({"message": "Commerce créé avec succès."}), 201

@app.route('/commerce/<int:commerce_id>', methods=['PUT'])
@jwt_required()
def update_specific_commerce(commerce_id):
    user_id = get_jwt_identity()
    commerce = Commerce.query.get(commerce_id)

    if not commerce or commerce.owner_id != user_id:
        return jsonify({"error": "Commerce introuvable ou non autorisé."}), 403

    data = request.get_json()
    commerce.name = data.get("name", commerce.name)
    commerce.type = data.get("type", commerce.type)
    commerce.address = data.get("address", commerce.address)
    commerce.phone = data.get("phone", commerce.phone)
    commerce.email = data.get("email", commerce.email)
    commerce.hours = data.get("hours", commerce.hours)

    db.session.commit()
    return jsonify({"message": "Commerce mis à jour avec succès."})

@app.route('/commerce/<int:commerce_id>', methods=['DELETE'])
@jwt_required()
def delete_commerce(commerce_id):
    user_id = get_jwt_identity()
    commerce = Commerce.query.get(commerce_id)

    if not commerce or commerce.owner_id != user_id:
        return jsonify({"error": "Commerce introuvable ou non autorisé."}), 403

    db.session.delete(commerce)
    db.session.commit()
    return jsonify({"message": "Commerce supprimé avec succès."})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
