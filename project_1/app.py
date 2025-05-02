from flask import Flask, request, jsonify, session, render_template_string
import re
import jwt
import json
from datetime import timedelta
from functools import wraps
import datetime

app = Flask(__name__)

# Session Configuration
app.config['SECRET_KEY'] = '449project'
app.config['SESSION_COOKIE_NAME'] = '449_session'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True  

# In-memory data stores
data = []  # List of inventory items
registered_user = {}  # Keys are usernames; values are dicts with password, email, role, and id.
next_user_id = 1  # Global user id counter

# Helper: Find an item by its ID
def find_item_id(item_id):
    return next((item for item in data if item["id"] == item_id), None)

def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

# JWT Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'Message': 'Token is missing!'}), 401
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = decoded['username']
            role = decoded['role']
        except Exception as e:
            return jsonify({'Message': 'Token is invalid!', 'Error': str(e)}), 401
        return f(current_user, role, *args, **kwargs)
    return decorated

""" User Registration, Login, and Logout Endpoints """
@app.route('/register', methods=['POST'])
def register():
    global next_user_id
    if not request.json or 'username' not in request.json or 'password' not in request.json or 'email' not in request.json:
        return jsonify({'Error': 'Username, Password, and E-mail are required'}), 400
    
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    role = request.json.get('role', 'user')  # Default role is 'user'

    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$'
    if not re.match(email_pattern, email):
        return jsonify({'Error': 'Invalid email format. Must be a valid email address (e.g., example@email.com)'}), 400
    
    if username in registered_user or any(user["email"] == email for user in registered_user.values()):
        return jsonify({'Error': 'User with this username or email already exists'}), 400

    if len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({'Error': 'Password must be at least 8 characters long and contain at least one special character'}), 400

    registered_user[username] = {
        "id": next_user_id,
        "password": password,
        "email": email,
        "role": role
    }
    next_user_id += 1

    return jsonify({'Message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'Error': 'Username and password are required'}), 400
    
    username = request.json['username']
    password = request.json['password']
    
    if username not in registered_user or registered_user[username]['password'] != password:
        return jsonify({'Error': 'Invalid credentials'}), 401
    
    session['user'] = username  
    token = jwt.encode({
            'username': username, 
            'role': registered_user[username]['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
    
    response = jsonify({
        'Message': 'Login successful', 
        'token': token,
        'role': registered_user[username]['role']
    })
    response.set_cookie('Username', username, httponly=True, max_age=1800)
    return response, 200

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    response = jsonify({'Message': 'Logout successful'})
    response.set_cookie('username', '', expires=0)
    return response, 200

@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'index', 'static']
    if request.endpoint not in allowed_routes and 'user' not in session:
        return jsonify({'Error': 'Unauthorized access. Please log in to view this resource.'}), 401

""" Inventory CRUD Endpoints """
@app.route('/inventory', methods=['POST'])
@token_required
def create_item(current_user, role):
    required_fields = ['item_name', 'description', 'quantity', 'price', 'manufacturer', 'rating']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'Error': 'All fields are required'}), 400
    
    item_id = max([item['id'] for item in data], default=0) + 1
    item = {**request.json, 'id': item_id}
    
    # Bind the new item to the creator.
    if role != "admin":
        item['owner'] = current_user
    else:
        # Admin can supply an owner field. Otherwise, default to admin.
        item['owner'] = item.get('owner', current_user)
    
    data.append(item)
    return jsonify(item), 201

@app.route('/inventory', methods=['GET'])
@token_required
def get_all_items(current_user, role):
    if role != "admin":
        # Non-admin only sees their own items.
        user_items = [item for item in data if item.get('owner') == current_user]
        return jsonify(user_items), 200
    return jsonify(data), 200

@app.route('/inventory/<int:item_id>', methods=['GET'])
@token_required
def get_item(current_user, role, item_id):
    item = find_item_id(item_id)
    if item is None:
        return jsonify({'Error': 'Item not found'}), 404
    if role != "admin" and item.get('owner') != current_user:
        return jsonify({'Error': 'Unauthorized. You can only view your own inventory item!'}), 403
    return jsonify(item)

@app.route('/inventory/<int:item_id>', methods=['PUT'])
@token_required
def update_item(current_user, role, item_id):
    if not request.json:
        return jsonify({'Error': 'Request body must be JSON'}), 400

    item = find_item_id(item_id)
    if item is None:
        return jsonify({'Error': 'Item ID not found'}), 404

    # Non-admin can only update their own items.
    if role != "admin" and item.get('owner') != current_user:
        return jsonify({'Error': 'Unauthorized. You can only update your own inventory item!'}), 403

    allowed_fields = ['item_name', 'description', 'quantity', 'price', 'manufacturer', 'rating']
    for field in allowed_fields:
        if field in request.json:
            item[field] = request.json[field]
    
    return jsonify(item), 200

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@token_required
def delete_item(current_user, role, item_id):
    item = find_item_id(item_id)
    if item is None:
        return jsonify({'Error': 'Item ID not found'}), 404
    if role != "admin" and item.get('owner') != current_user:
        return jsonify({'Error': 'Unauthorized. You can only delete your own inventory item!'}), 403
    
    data.remove(item)
    return jsonify({'Message': 'Item deletion successful'}), 200

@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user, role):
    return jsonify({
        'message': f'Hello, {current_user}! Welcome to the Inventory Management Backend!',
        'role': role
    })

""" Front-End Route with Embedded HTML, CSS, and JavaScript """
@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Inventory Management</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    form { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }
    input, button, select { padding: 5px; margin: 5px; }
    .message { color: green; }
    .error { color: red; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <h1>Inventory Management Frontend</h1>
  
  <!-- Registration Form -->
  <section id="register-section">
    <h2>Register</h2>
    <form id="register-form">
      <input type="text" id="register-username" placeholder="Username" required>
      <input type="email" id="register-email" placeholder="Email" required>
      <input type="password" id="register-password" placeholder="Password" required>
      <select id="register-role">
        <option value="user" selected>User</option>
        <option value="admin">Admin</option>
      </select>
      <button type="submit">Register</button>
    </form>
    <div id="register-msg"></div>
  </section>
  
  <!-- Login Form -->
  <section id="login-section">
    <h2>Login</h2>
    <form id="login-form">
      <input type="text" id="login-username" placeholder="Username" required>
      <input type="password" id="login-password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
    <div id="login-msg"></div>
  </section>
  
  <!-- Logout Section -->
  <section id="logout-section" class="hidden">
    <button id="logout-btn">Logout</button>
  </section>
  
  <!-- Admin Inventory Management Section -->
  <section id="admin-inventory-section" class="hidden">
    <h2>All Inventories (Admin)</h2>
    <!-- Create Item Form -->
    <form id="create-admin-item-form">
      <h3>Create Item</h3>
      <input type="text" id="admin-item-name" placeholder="Item Name" required>
      <input type="text" id="admin-item-desc" placeholder="Description" required>
      <input type="number" id="admin-item-quantity" placeholder="Quantity" required>
      <input type="number" id="admin-item-price" placeholder="Price" step="0.01" required>
      <input type="text" id="admin-item-manu" placeholder="Manufacturer" required>
      <input type="text" id="admin-item-rating" placeholder="Rating" required>
      <!-- Optional: Specify owner -->
      <input type="text" id="admin-item-owner" placeholder="Owner (optional)">
      <button type="submit">Create Item</button>
    </form>
    <div id="create-admin-item-msg"></div>
    
    <!-- CRUD Operations for Admin -->
    <form id="admin-crud-item-form">
      <h3>Get / Delete Item</h3>
      <input type="number" id="admin-crud-item-id" placeholder="Item ID" required>
      <button type="button" id="admin-get-all-items-btn">Get All Items</button>
      <button type="button" id="admin-get-item-btn">Get Item</button>
      <button type="button" id="admin-delete-item-btn">Delete Item</button>
    </form>
    <form id="admin-update-item-form">
      <h3>Update Item</h3>
      <input type="number" id="admin-update-item-id" placeholder="Item ID" required>
      <input type="text" id="admin-upd-item-name" placeholder="New Item Name">
      <input type="text" id="admin-upd-item-desc" placeholder="New Description">
      <input type="number" id="admin-upd-item-quantity" placeholder="New Quantity">
      <input type="number" id="admin-upd-item-price" placeholder="New Price" step="0.01">
      <input type="text" id="admin-upd-item-manu" placeholder="New Manufacturer">
      <input type="text" id="admin-upd-item-rating" placeholder="New Rating">
      <button type="button" id="admin-update-item-btn">Update Item</button>
    </form>
    <div id="admin-crud-item-msg"></div>
    <pre id="admin-item-result"></pre>
  </section>
  
  <!-- User Inventory Management Section -->
  <section id="user-inventory-section" class="hidden">
    <h2>My Inventory</h2>
    <!-- Create Item Form -->
    <form id="create-user-item-form">
      <h3>Create Item</h3>
      <input type="text" id="user-item-name" placeholder="Item Name" required>
      <input type="text" id="user-item-desc" placeholder="Description" required>
      <input type="number" id="user-item-quantity" placeholder="Quantity" required>
      <input type="number" id="user-item-price" placeholder="Price" step="0.01" required>
      <input type="text" id="user-item-manu" placeholder="Manufacturer" required>
      <input type="text" id="user-item-rating" placeholder="Rating" required>
      <button type="submit">Create Item</button>
    </form>
    <div id="create-user-item-msg"></div>
    
    <!-- CRUD Operations for User -->
    <form id="user-crud-item-form">
      <h3>Get / Delete Item</h3>
      <input type="number" id="user-crud-item-id" placeholder="Item ID" required>
      <button type="button" id="user-get-all-items-btn">Get My Items</button>
      <button type="button" id="user-get-item-btn">Get Item</button>
      <button type="button" id="user-delete-item-btn">Delete Item</button>
    </form>
    <form id="user-update-item-form">
      <h3>Update Item</h3>
      <input type="number" id="user-update-item-id" placeholder="Item ID" required>
      <input type="text" id="user-upd-item-name" placeholder="New Item Name">
      <input type="text" id="user-upd-item-desc" placeholder="New Description">
      <input type="number" id="user-upd-item-quantity" placeholder="New Quantity">
      <input type="number" id="user-upd-item-price" placeholder="New Price" step="0.01">
      <input type="text" id="user-upd-item-manu" placeholder="New Manufacturer">
      <input type="text" id="user-upd-item-rating" placeholder="New Rating">
      <button type="button" id="user-update-item-btn">Update Item</button>
    </form>
    <div id="user-crud-item-msg"></div>
    <pre id="user-item-result"></pre>
  </section>
  
  <script>
    let authToken = null;
    let userRole = null;
    function displayMessage(elementId, message, isError=false) {
      const el = document.getElementById(elementId);
      el.textContent = message;
      el.className = isError ? 'error' : 'message';
    }
    
    // Registration submission
    document.getElementById('register-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        username: document.getElementById('register-username').value,
        email: document.getElementById('register-email').value,
        password: document.getElementById('register-password').value,
        role: document.getElementById('register-role').value
      };
      const response = await fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('register-msg', resData.Message);
      } else {
        displayMessage('register-msg', resData.Error, true);
      }
    });
    
    // Login submission
    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        username: document.getElementById('login-username').value,
        password: document.getElementById('login-password').value
      };
      const response = await fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('login-msg', resData.Message);
        authToken = resData.token;
        userRole = resData.role;
        document.getElementById('login-section').classList.add('hidden');
        document.getElementById('register-section').classList.add('hidden');
        document.getElementById('logout-section').classList.remove('hidden');
        if (userRole === "admin") {
          document.getElementById('admin-inventory-section').classList.remove('hidden');
        } else {
          document.getElementById('user-inventory-section').classList.remove('hidden');
        }
      } else {
        displayMessage('login-msg', resData.Error, true);
      }
    });
    
    // Logout handler
    document.getElementById('logout-btn').addEventListener('click', async () => {
      const response = await fetch('/logout', { method: 'POST' });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('login-msg', 'Logged out successfully');
        authToken = null;
        userRole = null;
        document.getElementById('login-section').classList.remove('hidden');
        document.getElementById('register-section').classList.remove('hidden');
        document.getElementById('logout-section').classList.add('hidden');
        document.getElementById('admin-inventory-section').classList.add('hidden');
        document.getElementById('user-inventory-section').classList.add('hidden');
      }
    });
    
    // ---------- Admin Inventory Event Listeners ----------
    // Create Item (Admin)
    document.getElementById('create-admin-item-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        item_name: document.getElementById('admin-item-name').value,
        description: document.getElementById('admin-item-desc').value,
        quantity: parseInt(document.getElementById('admin-item-quantity').value),
        price: parseFloat(document.getElementById('admin-item-price').value),
        manufacturer: document.getElementById('admin-item-manu').value,
        rating: document.getElementById('admin-item-rating').value
      };
      const ownerVal = document.getElementById('admin-item-owner').value.trim();
      if(ownerVal !== "") {
        payload.owner = ownerVal;
      }
      const response = await fetch('/inventory', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'x-access-token': authToken},
        body: JSON.stringify(payload)
      });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('create-admin-item-msg', 'Item created successfully');
      } else {
        displayMessage('create-admin-item-msg', resData.Error || resData.Message, true);
      }
    });
    
    // Get all items (Admin)
    document.getElementById('admin-get-all-items-btn').addEventListener('click', async () => {
      const response = await fetch('/inventory', { method: 'GET', headers: {'x-access-token': authToken} });
      const resData = await response.json();
      if (response.ok) {
        document.getElementById('admin-item-result').textContent = JSON.stringify(resData, null, 2);
        displayMessage('admin-crud-item-msg', 'All items fetched');
      } else {
        displayMessage('admin-crud-item-msg', resData.Error || 'Error fetching items', true);
      }
    });
    
    // Get single item (Admin)
    document.getElementById('admin-get-item-btn').addEventListener('click', async () => {
      const itemId = document.getElementById('admin-crud-item-id').value;
      const response = await fetch(`/inventory/${itemId}`, { method: 'GET', headers: {'x-access-token': authToken} });
      const resData = await response.json();
      if (response.ok) {
        document.getElementById('admin-item-result').textContent = JSON.stringify(resData, null, 2);
        displayMessage('admin-crud-item-msg', 'Item fetched');
      } else {
        displayMessage('admin-crud-item-msg', resData.Error || 'Error fetching item', true);
      }
    });
    
    // Delete item (Admin)
    document.getElementById('admin-delete-item-btn').addEventListener('click', async () => {
      const itemId = document.getElementById('admin-crud-item-id').value;
      const response = await fetch(`/inventory/${itemId}`, { method: 'DELETE', headers: {'x-access-token': authToken} });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('admin-crud-item-msg', resData.Message);
        document.getElementById('admin-item-result').textContent = "";
      } else {
        displayMessage('admin-crud-item-msg', resData.Error || 'Error deleting item', true);
      }
    });
    
    // Update item (Admin)
    document.getElementById('admin-update-item-btn').addEventListener('click', async () => {
      const itemId = document.getElementById('admin-update-item-id').value;
      let payload = {};
      let nameVal = document.getElementById('admin-upd-item-name').value.trim();
      if(nameVal !== "") { payload.item_name = nameVal; }
      let descVal = document.getElementById('admin-upd-item-desc').value.trim();
      if(descVal !== "") { payload.description = descVal; }
      let quantityVal = document.getElementById('admin-upd-item-quantity').value.trim();
      if(quantityVal !== "") { payload.quantity = parseInt(quantityVal); }
      let priceVal = document.getElementById('admin-upd-item-price').value.trim();
      if(priceVal !== "") { payload.price = parseFloat(priceVal); }
      let manuVal = document.getElementById('admin-upd-item-manu').value.trim();
      if(manuVal !== "") { payload.manufacturer = manuVal; }
      let ratingVal = document.getElementById('admin-upd-item-rating').value.trim();
      if(ratingVal !== "") { payload.rating = ratingVal; }
      
      const response = await fetch(`/inventory/${itemId}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json', 'x-access-token': authToken},
        body: JSON.stringify(payload)
      });
      const resData = await response.json();
      if (response.ok) {
        document.getElementById('admin-item-result').textContent = JSON.stringify(resData, null, 2);
        displayMessage('admin-crud-item-msg', 'Item updated');
      } else {
        displayMessage('admin-crud-item-msg', resData.Error || 'Error updating item', true);
      }
    });
    
    // ---------- User Inventory Event Listeners ----------
    // Create Item (User)
    document.getElementById('create-user-item-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        item_name: document.getElementById('user-item-name').value,
        description: document.getElementById('user-item-desc').value,
        quantity: parseInt(document.getElementById('user-item-quantity').value),
        price: parseFloat(document.getElementById('user-item-price').value),
        manufacturer: document.getElementById('user-item-manu').value,
        rating: document.getElementById('user-item-rating').value
      };
      const response = await fetch('/inventory', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'x-access-token': authToken},
        body: JSON.stringify(payload)
      });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('create-user-item-msg', 'Item created successfully');
      } else {
        displayMessage('create-user-item-msg', resData.Error || resData.Message, true);
      }
    });
    
    // Get all items (User – only their own)
    document.getElementById('user-get-all-items-btn').addEventListener('click', async () => {
      const response = await fetch('/inventory', { method: 'GET', headers: {'x-access-token': authToken} });
      const resData = await response.json();
      if (response.ok) {
        document.getElementById('user-item-result').textContent = JSON.stringify(resData, null, 2);
        displayMessage('user-crud-item-msg', 'My items fetched');
      } else {
        displayMessage('user-crud-item-msg', resData.Error || 'Error fetching items', true);
      }
    });
    
    // Get a single item (User)
    document.getElementById('user-get-item-btn').addEventListener('click', async () => {
      const itemId = document.getElementById('user-crud-item-id').value;
      const response = await fetch(`/inventory/${itemId}`, { method: 'GET', headers: {'x-access-token': authToken} });
      const resData = await response.json();
      if (response.ok) {
        document.getElementById('user-item-result').textContent = JSON.stringify(resData, null, 2);
        displayMessage('user-crud-item-msg', 'Item fetched');
      } else {
        displayMessage('user-crud-item-msg', resData.Error || 'Error fetching item', true);
      }
    });
    
    // Delete item (User)
    document.getElementById('user-delete-item-btn').addEventListener('click', async () => {
      const itemId = document.getElementById('user-crud-item-id').value;
      const response = await fetch(`/inventory/${itemId}`, { method: 'DELETE', headers: {'x-access-token': authToken} });
      const resData = await response.json();
      if (response.ok) {
        displayMessage('user-crud-item-msg', resData.Message);
        document.getElementById('user-item-result').textContent = "";
      } else {
        displayMessage('user-crud-item-msg', resData.Error || 'Error deleting item', true);
      }
    });
    
    // Update item (User)
    document.getElementById('user-update-item-btn').addEventListener('click', async () => {
      const itemId = document.getElementById('user-update-item-id').value;
      let payload = {};
      let nameVal = document.getElementById('user-upd-item-name').value.trim();
      if(nameVal !== "") { payload.item_name = nameVal; }
      let descVal = document.getElementById('user-upd-item-desc').value.trim();
      if(descVal !== "") { payload.description = descVal; }
      let quantityVal = document.getElementById('user-upd-item-quantity').value.trim();
      if(quantityVal !== "") { payload.quantity = parseInt(quantityVal); }
      let priceVal = document.getElementById('user-upd-item-price').value.trim();
      if(priceVal !== "") { payload.price = parseFloat(priceVal); }
      let manuVal = document.getElementById('user-upd-item-manu').value.trim();
      if(manuVal !== "") { payload.manufacturer = manuVal; }
      let ratingVal = document.getElementById('user-upd-item-rating').value.trim();
      if(ratingVal !== "") { payload.rating = ratingVal; }
      
      const response = await fetch(`/inventory/${itemId}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json', 'x-access-token': authToken},
        body: JSON.stringify(payload)
      });
      const resData = await response.json();
      if (response.ok) {
        document.getElementById('user-item-result').textContent = JSON.stringify(resData, null, 2);
        displayMessage('user-crud-item-msg', 'Item updated');
      } else {
        displayMessage('user-crud-item-msg', resData.Error || 'Error updating item', true);
      }
    });
  </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(debug=True)
