from flask import Flask, request, jsonify, session
import re
import json
from datetime import timedelta


app = Flask(__name__)

#Session Configuration
app.config['SECRET_KEY'] = '449project'
app.config['SESSION_COOKIE_NAME'] = '449_session'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = False

#Inventory dataset
with open('inventory.json','r') as file:
    data = json.load(file)
print(data)

registered_user = {}

# Helper function to find an item by its ID
def find_item_id(item_id):
    return next((id for id in data if data["id"] == item_id), None)


def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)


"""User Register,Login,and Logout endpoint"""
@app.route('/register',methods=['POST'])
def register():
    if not request.json or 'username' not in request.json or 'password' not in request.json or 'email' not in request.json:
        return jsonify({'Error': 'Username, Password, and E-mail are required'},400)
    
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$'
    if not re.match(email_pattern, email):
        return jsonify({'Error': 'Invalid email format. Must be a valid email address (e.g., example@email.com)'}), 400
    
    # Check if username or email is already registered
    if username in registered_user or any(user[1] == email for user in registered_user.values()):
        return jsonify({'Error': 'User with this username or email already exists'}), 400
    
    # Validate password complexity
    if len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({'Error': 'Password must be at least 8 characters long and contain at least one special character'}), 400
    
    
    #Otherwise, store user credential by default
    registered_user[username] = [password,email]  
    return jsonify({'Message': 'User registered successfully'}), 201

@app.route('/login',methods=['POST'])
def login():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'Error': 'Username and password are required'}), 400
    
    username = request.json['username']
    password = request.json['password']
    
    if registered_user.get(username)[0] != password:
        return jsonify({'Error': 'Invalid credentials'}), 401
    
    #Store user session and set session cookie
    session['user'] = username  
    response = jsonify({'Message': 'Login successful'})
    response.set_cookie('Username', username, httponly=True, max_age=1800)  
    return response, 200

@app.route('/logout',methods=['POST'])
def logout():
    #Remove user session
    session.pop('user', None) 
    response = jsonify({'Message': 'Logout successful'})

    #Clears session cookie
    response.set_cookie('username', '', expires=0)  
    return response, 200

@app.before_request
def require_login():
    allowed_routes = ['login', 'register']  # Routes that don't require authentication
    if request.endpoint not in allowed_routes and 'user' not in session:
        return jsonify({'Error': 'Unauthorized access. Please log in to view this resource.'}), 401


"""CRUD Operations"""

#Creates new inventory items using ID
@app.route('/inventory', methods=['POST'])
def create_item():
    #TO-DO
    required_fields = ['item_name', 'description', 'quantity', 'price']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'Error': 'All fields are required'}), 400
    
    item_id = max(item['id'] for item in data) + 1 if data else 1
    item = {**request.json, 'id': item_id}
    data.append(item)
    
    return jsonify(item), 201

#Lists all inventory items using ID
@app.route('/inventory/<int:item_id>', methods=['GET'])
def get_items(item_id):
    #TO-DO
    item_id = find_item_id(item_id)
    if item_id is None:
        return jsonify({'Error': 'Student not found'}), 404
    return jsonify(item_id)

#Updates item using ID
@app.route('/inventory/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    #TO-DO
    id = find_item_id(item_id)
    if id is None:
        return jsonify({'Error': 'Item ID not found'}), 404
    
    id.update(request.json)
    return jsonify(id)

#Deletes item using ID
@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    #TO-DO
    id = find_item_id(item_id)
    if id is None:
        return jsonify({'Error': 'Item ID not found'}), 404
    
    data.remove(id)
    return jsonify({'Message': 'Item ID deletion successful'}), 200

