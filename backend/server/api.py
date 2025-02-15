from flask import Flask, jsonify, request, render_template
import quizgenerator as quizgenerator
import db.database as database
import os
import jwt  # Ensure this is PyJWT
import uuid
import datetime
import bcrypt

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your_secret_key")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def generate_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def generate_jwt_token(username):
    """Generates a JWT token with an expiration time."""
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        "username": username,
        "exp": expiration_time
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
    return token


@app.before_request
def jwt_auth_middleware():
    """Middleware to validate JWT token on protected routes."""
    if request.path == "/scholarstack/login" or request.path == "/scholarstack/register":
        return

    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    try:
        token = token.split("Bearer ")[-1]
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route("/scholarstack/quiz-generator", methods=["GET"])
def getQuestions():
    qz = quizgenerator.DynamicTest()
    data = request.get_json()
    data = dict(data)
    return jsonify(qz.fetch_questions(data["category"], data["difficulty"], data["questions"]))


@app.route("/scholarstack/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    role = data["role"]
    if not database.check_user(username, password, role):
        return jsonify({"error": "Invalid credentials."}), 401
    token = generate_jwt_token(username)
    return jsonify({"success": "User login successful", "token": token})

@app.route("/scholarstack/register", methods=["POST"])
def register():
    """Registers a new user by storing their credentials in the database."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "All fields (username, password, role) are required."}), 400

    # Check if the user already exists
    if database.check_user_exists(username):
        return jsonify({"error": "User already exists."}), 409

    # Hash the password
    hashed_password = generate_password_hash(password).decode('utf-8')

    # Insert the new user into the database
    database.insert_user(username, hashed_password, role)
    return jsonify({"message": "User registered successfully."}), 201

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_unique_filename(filename):
    """Generate a unique filename using UUID while keeping the original extension."""
    name, extension = os.path.splitext(filename)
    unique_id = str(uuid.uuid4())
    return f"{name}_{unique_id}{extension}"


@app.route("/scholarstack/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if file and allowed_file(file.filename):
        unique_filename = generate_unique_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        filetype = file.content_type
        filesize = os.path.getsize(filepath)
        database.insert_upload_details(unique_filename, filetype, filesize)

        return jsonify({"message": f"File '{unique_filename}' uploaded successfully"}), 200

    return jsonify({"error": "File type not allowed"}), 400

@app.route("/scholarstack/get-all-uploads", methods = ["GET"])
def get_all_upload_files():
    return jsonify({"uploads": database.get_all_uploads()}), 200

@app.route("/scholarstack/delete-uploads/<string:file_name>", methods = ["DELETE"])
def del_upload(file_name):
    try:
        database.delete_upload_details()
        return jsonify({"success": "data deleted successfully"})
    except BaseException as e:
        return jsonify({"error": {e}})

if __name__ == "__main__":
    app.run(debug=True)
