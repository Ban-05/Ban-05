import os
from flask import Flask, request, jsonify, send_from_directory
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timedelta
import jwt
from functools import wraps

app = Flask(__name__)

# Configuration à partir des variables d'environnement
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')  # Clé secrète pour JWT
UPLOAD_FOLDER = 'uploads'
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')  # URL de la base MongoDB

# Initialisation de MongoDB
mongo_client = MongoClient(MONGO_URI)
db = mongo_client['file_storage']
users_collection = db['users']
files_collection = db['files']

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Middleware pour vérifier les tokens JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token manquant'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({"_id": data['user_id']})
            if not current_user:
                return jsonify({'message': 'Utilisateur non trouvé'}), 403
        except Exception:
            return jsonify({'message': 'Token invalide'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Routes pour l'inscription, connexion, upload et téléchargement
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    user = {'username': data['username'], 'password': hashed_password}
    users_collection.insert_one(user)
    return jsonify({'message': 'Utilisateur créé avec succès'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = users_collection.find_one({'username': data['username']})
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Nom d\'utilisateur ou mot de passe incorrect'}), 401

    token = jwt.encode(
        {'user_id': str(user['_id']), 'exp': datetime.utcnow() + timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )
    return jsonify({'token': token})

@app.route('/upload', methods=['POST'])
@token_required
def upload_files(current_user):
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Aucun fichier trouvé'}), 400

    files = request.files.getlist('file')
    uploaded_files = []

    for file in files:
        filename = file.filename
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)

        file_document = {
            'filename': filename,
            'path': file_path,
            'user_id': current_user['_id'],
            'createdAt': datetime.now()
        }
        files_collection.insert_one(file_document)
        uploaded_files.append(unique_filename)

    return jsonify({'success': True, 'files': uploaded_files}), 200

@app.route('/download/<filename>', methods=['GET'])
@token_required
def download_file(current_user, filename):
    file_record = files_collection.find_one({'filename': filename, 'user_id': current_user['_id']})
    if not file_record:
        return jsonify({'message': 'Fichier non trouvé'}), 404

    return send_from_directory(UPLOAD_FOLDER, file_record['filename'])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
