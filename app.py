from flask import Flask, request, jsonify, session
import re
import json
from datetime import timedelta


app = Flask(__name__)

#Session Configuration
app.config['SECRET KEY'] = '449project'
app.config['SESSION_COOKIE_NAME'] = '449_session'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = False

#Inventory dataset
with open('inventory.json','r') as file:
    data = json.load(file)
print(data)



"""User Register,Login,and Logout endpoint"""
@app.route('/register',methods=['POST'])
def register():
    #TO-DO

@app.route('/login',methods=['POST'])
def login():
    #TO-DO

@app.route('/logout',methods=['POST'])
def logout():
    #TO-DO


"""CRUD Operations"""

#Creates new inventory items using ID
@app.route('/inventory', methods=['POST'])
def create_item():

#Lists all inventory items using ID
@app.route('/inventory/<int:item_id>', methods=['GET'])
def get_items(item_id):
    #TO-DO

#Updates item using ID
@app.route('/inventory/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    #TO-DO
#Deletes item using ID
@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    #TO-DO

