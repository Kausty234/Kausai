from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
import sympy as sp
from paraphrase_detection import is_paraphrase  # Custom module for paraphrase detection

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kausai.db'  # Change to PostgreSQL for production
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins='*')

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    chat_history = db.Column(db.Text, default='')
    profile_picture = db.Column(db.String(255), default='default.png')
    bio = db.Column(db.Text, default='')

# Solve Mathematical Equations
@app.route('/solve', methods=['POST'])
def solve_equation():
    data = request.json
    equation = data.get('equation')
    if not equation:
        return jsonify({'error': 'No equation provided'}), 400
    try:
        solution = sp.solve(equation)
        return jsonify({'solution': str(solution)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Chatbot Logic
@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_input = data.get('message')
    if not user_input:
        return jsonify({'error': 'No message provided'}), 400
    
    # Custom AI logic (Replace with advanced NLP if needed)
    responses = {
        "hello": "Hi! How can I assist you today?",
        "how are you": "I'm just a chatbot, but I'm here to help!",
        "bye": "Goodbye! Have a great day!"
    }
    response = responses.get(user_input.lower(), "I'm not sure about that. Can you rephrase?")
    return jsonify({'response': response})

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        return jsonify({'message': 'Login successful'})
    return jsonify({'error': 'Invalid credentials'}), 401

# Update User Profile
@app.route('/update_profile', methods=['POST'])
def update_profile():
    data = request.json
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.bio = data.get('bio', user.bio)
    user.profile_picture = data.get('profile_picture', user.profile_picture)
    db.session.commit()
    return jsonify({'message': 'Profile updated successfully'})

# WebSocket for Real-time Chat
@socketio.on('send_message')
def handle_message(data):
    message = data['message']
    emit('receive_message', {'message': message}, broadcast=True)

# Run the App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
