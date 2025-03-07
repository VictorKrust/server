from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# Configurações
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Troque por uma chave secreta real
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Decorador para verificar o token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token não fornecido!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token inválido!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Rota de registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'message': 'Dados incompletos!'}), 400

    # Verifica se usuário já existe
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Nome de usuário já existe!'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email já cadastrado!'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    new_user = User(
        username=data['username'],
        password=hashed_password,
        email=data['email']
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuário registrado com sucesso!'}), 201
    except:
        return jsonify({'message': 'Erro ao registrar usuário!'}), 500

# Rota de login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Dados incompletos!'}), 400

    user = User.query.filter_by(username=data['username']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    if check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])

        return jsonify({
            'message': 'Login realizado com sucesso!',
            'token': token
        }), 200

    return jsonify({'message': 'Senha incorreta!'}), 401

# Rota protegida de exemplo
@app.route('/perfil', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'created_at': current_user.created_at
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Cria o banco de dados e as tabelas
    app.run(debug=True) 