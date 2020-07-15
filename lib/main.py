#!../venv/bin/python

from flask import Flask, jsonify, abort, make_response, request, url_for, g
from flask_sqlalchemy import SQLAlchemy
import jwt as jwt
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import time
from functools import wraps

path = os.path.abspath(os.path.dirname(__file__))
df_filename = 'todo.db'

app = Flask(__name__, static_url_path="")
app.config['SECRET_KEY'] = 'someSecretHere'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+path+'/'+df_filename
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), index=True)
    password_hash = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'public_id': self.public_id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

def build_user_data(user):
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['password_hash'] = user.password_hash
    user_data['admin'] = user.admin
    user_data['created_on'] = user.created_on
    user_data['updated_on'] = user.updated_on
    return user_data

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50))
    description = db.Column(db.Text)
    done = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

def build_task_data(task, ext=True):
    task_data = {}
    task_data['id'] = task.id
    task_data['title'] = task.title
    task_data['description'] = task.description
    task_data['done'] = task.done
    if not ext:
        task_data['user_id'] = task.user_id
    task_data['created_on'] = task.created_on
    task_data['updated_on'] = task.updated_on
    task_data['uri'] = url_for('get_task', task_id=task.id, _external=True)
    return task_data

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403
        
        g.user = user

        return f(*args, **kwargs)
    return decorated

@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.route('/')
def index():
    return ('Welcome to Tasks API. Login <a href="login">here</a>.')

@app.route('/users', methods=['GET'])
@token_required
def get_all_users():
    # allowed only for admins
    if not g.user.admin:
        return jsonify({'message' : 'Not having permission to perform this action!'})
    
    users = User.query.all()
    output = []
    for user in users:
        output.append(build_user_data(user))
    return jsonify({'users' : output})

@app.route('/users', methods=['POST'])
@token_required
def create_user():
    if not g.user.admin:
        return jsonify({'message' : 'Not having permission to perform this action!'})
    
    data = request.get_json() or {}
    if 'username' not in data or 'password' not in data:
        return bad_request('must include username and password fields')
    if User.query.filter_by(username=data['username']).first():
        return bad_request('please use a different username')

    user = User()
    user.username = data['username']
    user.public_id = str(uuid.uuid4())
    user.hash_password(data['password'])
    user.admin = False

    db.session.add(user)
    db.session.commit()

    return (jsonify(build_user_data(user)), 201)

@app.route('/users/<public_id>', methods=['GET'])
@token_required
def get_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        abort(400)
    return jsonify(build_user_data(user), 201)

@app.route('/users/<public_id>', methods=['PUT'])
@token_required
def update_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    data = request.get_json() or {}
    if not user:
        abort(400)
    if not data:
        abort(400)
    if 'password' in data and type(data['password']) != str:
        abort(400)
    if 'admin' in data and type(data['admin']) is not bool:
        abort(400)

    if 'password' in data :
        user.hash_password(data['password'])
    if 'admin' in data and g.user.admin: 
        user.admin = data['admin']
    
    db.session.commit()
    return (jsonify(build_user_data(user)), 201)

@app.route('/users/<public_id>', methods=['DELETE'])
@token_required
def delete_user(public_id):
    if not g.user.admin:
        return jsonify({'message' : 'Not having permission to perform this action!'})
    
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        abort(400)
    db.session.delete(user)
    db.session.commit()

    return (jsonify({'message' : 'User deleted!'}), 201)

@app.route('/login')
def login():
    auth = request.authorization

    # Check for correct request
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 403, {'WWW-Authenticate':'Basic realm="Login required!"'})

    # Check if user exists then verify password
    user = User.query.filter_by(username=auth.username).first()
    if not user or not user.verify_password(auth.password):
        return make_response('Could not verify', 403, {'WWW-Authenticate':'Basic realm="Login required!"'})
    g.user = user #save user to global

    # Return the token
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


#### TASKS ####

@app.route('/api/v1.0/tasks', methods=['GET'])
@token_required
def get_all_tasks():
    tasks = Task.query.filter_by(user_id=g.user.id).all()
    output = []
    for task in tasks:
        output.append(build_task_data(task))
    return jsonify({'tasks' : output})

@app.route('/api/v1.0/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.user.id).first()
    if not task:
        abort(400)
    return (jsonify({"task":build_task_data(task)}))

@app.route('/api/v1.0/tasks', methods=['POST'])
@token_required
def create_task():
    if not request.json or not 'title' in request.json:
        abort(400)

    task = Task()
    task.title = request.json.get('title')
    task.description = request.json.get('description',"")
    task.user_id = g.user.id
    task.done = False

    db.session.add(task)
    db.session.commit()

    return (jsonify({"task":build_task_data(task)}), 201)


@app.route('/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.user.id).first()
    if not task:
        abort(400) 
    if not request.json:
        abort(400)
    if 'title' in request.json and type(request.json['title']) != str:
        abort(400)
    if 'description' in request.json and type(request.json['description']) is not str:
        abort(400)
    if 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)
    task.title = request.json.get('title', task.title)
    task.description = request.json.get('description', task.description)
    task.done = request.json.get('done', task.done)

    db.session.commit()

    return (jsonify({"task":build_task_data(task)}), 200)

@app.route('/api/v1.0/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=g.user.id).first()
    if not task:
        abort(400) 
    db.session.delete(task)
    db.session.commit()

    return jsonify({'message' : 'Task deleted'}), 200


if (__name__) == '__main__':
    app.run(debug=True) 