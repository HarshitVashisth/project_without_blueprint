from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os 
app = Flask(__name__)


basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'sqlite.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    posts = db.relationship('BlogPost', backref='author')

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    text= db.Column(db.Text())
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])

def create_user():


    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    user_public_id = str(uuid.uuid4())
    new_user = User(public_id=user_public_id, name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!', 'public-id':user_public_id})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def update_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()
    data = request.get_json()

    if not user:
        return jsonify({'message' : 'No user found!'})

    # user.admin = True
    hashed_password = generate_password_hash(data['password'], method='sha256')
    user.name = data['name']
    user.password = hashed_password

    db.session.commit()

    return jsonify({'message' : 'The user has been updated!'})

@app.route('/user/<public_id>', methods=['PATCH'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/post', methods=['GET'])
@token_required
def get_all_posts(current_user):
    posts = BlogPost.query.filter_by(author_id=current_user.id).all()

    output = []

    for post in posts:
        post_data = {}
        post_data['id'] = post.id
        post_data['title'] = post.title
        post_data['text'] = post.text
        output.append(post_data)

    return jsonify({'posts' : output})

@app.route('/post/<post_id>', methods=['GET'])
@token_required
def get_one_post(current_user, post_id):
    post = BlogPost.query.filter_by(id=post_id, author_id=current_user.id).first()

    if not post:
        return jsonify({'message' : 'No post found!'}), 404

    post_data = {}
    post_data['id'] = post.id
    post_data['title'] = post.title
    post_data['text'] = post.text

    return jsonify(post_data)

@app.route('/post', methods=['POST'])
@token_required
def create_post(current_user):
    data = request.get_json()

    new_post = BlogPost(title=data['title'], text=data['text'], author_id=current_user.id)
    db.session.add(new_post)
    db.session.commit()

    return jsonify({'message' : "New post created!"})


@app.route('/post/<post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    post = BlogPost.query.filter_by(id=post_id, author_id=current_user.id).first()

    if not post:
        return jsonify({'message' : 'No post found!'})

    db.session.delete(post)
    db.session.commit()

    return jsonify({'message' : 'Post deleted!'})

if __name__ == '__main__':
    app.run(debug=True)