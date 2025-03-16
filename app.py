from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from pymongo import MongoClient
import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

client = MongoClient("mongodb+srv://karthikmakkam:mkk_1817@project.e5qxv.mongodb.net/?retryWrites=true&w=majority&appName=Project")
db = client["digital_land_registry"]
users_collection = db["users"]

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    if not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"msg": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity=username, expires_delta=datetime.timedelta(hours=1))
    return jsonify({"access_token": access_token})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if users_collection.find_one({"username": username}):
        return jsonify({"msg": "User already exists"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({"username": username, "password": hashed_password})
    return jsonify({"msg": "User registered successfully"})

if __name__ == '__main__':
    app.run(debug=True)
