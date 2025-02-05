from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_login import login_required
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo import MongoClient
from itsdangerous import URLSafeTimedSerializer
import random
import smtplib
from functools import wraps
from flask import abort
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson.objectid import ObjectId
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.oauth2.service_account import Credentials
from datetime import datetime
from io import BytesIO
from googleapiclient.http import MediaIoBaseUpload



app = Flask(__name__)
app.config['SECRET_KEY'] = '1f8b0823a45b17bc6b34c9d8635df4b8dc11f00faac0874d71f3df9d20368d2f'  # Replace with a secure key

# MongoDB Setup
client = MongoClient("mongodb://localhost:27017/kalasuttra")  # Replace with your MongoDB URI
db = client['kalasuttra']
users_collection = db['users']
upcycle_collection = db['upcycle']


# Flask-Mail Configuration
EMAIL_ADDRESS = "kalasuttra@gmail.com"
EMAIL_PASSWORD = "svau jkwo fphb kprf"



# login manager to track current user
login_manager = LoginManager()
login_manager.init_app(app)


# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

    def get_id(self):
        print(self.id)
        return self.id

@login_manager.user_loader
def load_user(user_id):
    print(f"Loading user with id: {user_id}")
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    print(f"User loaded: {user}")
    if user:
        print(f"User loaded: {user['_id']}")
        return User(user_id=str(user['_id']), username=user['email'])
    print("User not found in load_user")
    # user = db.users_collection.find_one({"_id": user_id})
    # if user:
    #     return User(str(user["_id"]))
    return None

# Function to generate a unique 9-digit user ID
def generate_unique_user_id():
    while True:
        user_id = str(random.randint(100000000, 999999999))  # Generate 9-digit number
        if not users_collection.find_one({"user_id": user_id}):
            return user_id

# decorator function to provide admin privilages
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# decorator function to provide logged in privilages
def logged_in_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


def send_email(email, subject, body, EMAIL_ADDRESS, EMAIL_PASSWORD):
    try:
        # Create the email content
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Connect to Gmail SMTP server and send email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Secure the connection
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def initialize_drive():
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
    creds = Credentials.from_service_account_file('credentials.json', scopes=SCOPES)
    drive_service = build('drive', 'v3', credentials=creds)
    return drive_service

def create_folder_in_drive(folder_name, parent_folder_id=None):
    drive_service = initialize_drive()
    folder_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_folder_id:
        folder_metadata['parents'] = [parent_folder_id]

    folder = drive_service.files().create(body=folder_metadata, fields='id').execute()
    return folder.get('id')

# Upload file to a specific folder in Google Drive
def upload_to_drive_in_folder(file_stream, file_name, folder_id):
    drive_service = initialize_drive()
    file_metadata = {
        'name': file_name,
        'parents': [folder_id]
    }
    media = MediaIoBaseUpload(file_stream, mimetype='image/jpeg', resumable=True)
    file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()

    # Make the file publicly accessible
    file_id = file.get('id')
    drive_service.permissions().create(
        fileId=file_id,
        body={'type': 'anyone', 'role': 'reader'}
    ).execute()

    # Generate shareable link
    shareable_link = f"https://drive.google.com/uc?id={file_id}&export=download"
    return shareable_link

# Dictionary to store OTPs temporarily
otp_storage = {}

# Flask-Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Serializer for generating tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = users_collection.find_one({"email": email.upper()})


        if user and check_password_hash(user["password"], password):

            login_user(User(user_id=str(user['_id']), username=user['email']),remember=False)
            print("login_user called successfully")


            session["user"] = user["email"].upper()
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password!", "error")

    return render_template("login.html")


from datetime import datetime

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].upper()
        password = request.form["password"]
        name = request.form["name"]

        if users_collection.find_one({"email": email}):
            flash("Email already exists. Please log in.", "error")
            return redirect(url_for("login"))

        user_id = generate_unique_user_id()

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "user_id": user_id,
            "created_on": datetime.utcnow()  # Add creation date
        })
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")




@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = users_collection.find_one({"email": email})
        if user:
            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)
            otp_storage[email] = otp

            # Send the OTP to the user's email
            subject = "Your Password Reset OTP"
            body = f"Your OTP for password reset is: {otp}. It is valid for 10 minutes."
            send_email(email, subject, body, EMAIL_ADDRESS, EMAIL_PASSWORD)

            flash("An OTP has been sent to your email. Please verify.", "info")
            return redirect(url_for("verify_otp", email=email))
        else:
            flash("Email not found!", "error")
    return render_template("forgot-password.html")


@app.route("/reset-password/<email>", methods=["GET", "POST"])
def reset_password(email):
    if request.method == "POST":
        new_password = request.form["password"]
        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the password in the database
        result = users_collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password}}
        )

        if result.modified_count > 0:
            flash("Password reset successfully!", "success")
            return redirect(url_for("login"))
        else:
            flash("Failed to update password. Please try again.", "error")
            return redirect(url_for("forgot_password"))
    return render_template("reset-password.html", email=email)


@app.route("/verify-otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    if request.method == "POST":
        otp = request.form["otp"]
        if otp_storage.get(email) == int(otp):
            del otp_storage[email]  # Clear the OTP after successful verification
            flash("OTP verified successfully. You can reset your password.", "success")
            return redirect(url_for("reset_password", email=email))
        else:
            flash("Invalid OTP or expired!", "error")
    return render_template("verify-otp.html", email=email)


@app.route("/logout")
def logout():
    logout_user()
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route('/saved-address', methods=['GET', 'POST'])
@logged_in_only
def saved_address():
    if request.method == 'POST':
        # Add a new address
        address = {
            "user_id": current_user.get_id(),
            "name": request.form.get('name'),
            "address_line_1": request.form.get('address_line_1'),
            "address_line_2": request.form.get('address_line_2'),
            "city": request.form.get('city'),
            "state": request.form.get('state'),
            "pincode": request.form.get('pincode')
        }
        db.saved_addresses.insert_one(address)
        flash("Address added successfully!", "success")
        return redirect(url_for('saved_address'))

    # Fetch saved addresses for the logged-in user
    addresses = list(db.saved_addresses.find({"user_id": current_user.get_id()}))
    return render_template('saved-address.html', addresses=addresses, active_page='saved_address')


# Home route
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about-kalasuttra')
def about():
    return render_template('about-me.html')

@app.route('/my-account')
@logged_in_only
def My_account():
    user_id = current_user.get_id()
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    account_details = {
        "username": user_data.get("name"),
        "email": user_data.get("email"),
        "created_on": user_data.get("created_on", "Not Available")
    }
    return render_template('my-account.html', account=account_details, active_page='my_account')



@app.route('/order-history')
@logged_in_only
def order_history():
    # Replace with actual logic to fetch orders
    orders = [
        {"id": "ORD123", "date": "2023-12-10", "status": "Delivered"},
        {"id": "ORD124", "date": "2023-12-15", "status": "In Transit"}
    ]
    return render_template('order-history.html', orders=orders, active_page='order_history')

@app.route('/settings', methods=['GET', 'POST'])
@logged_in_only
def settings():
    user_id = current_user.get_id()
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    if request.method == 'POST':
        # Update logic
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {
            "name": request.form.get("username"),
            "email": request.form.get("email")
        }})
        flash("Settings updated successfully!", "success")
        return redirect(url_for('settings'))
    account_details = {
        "username": user_data.get("name"),
        "email": user_data.get("email")
    }
    return render_template('settings.html', account=account_details, active_page='settings')



@app.route('/cart')
@logged_in_only
# @login_required
def cart():
    return render_template('cart.html')

@app.route('/contact-me', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        date = request.form.get('date')
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # Debug: Print form data to the console
        print(f"Date: {date}")
        print(f"Name: {name}")
        print(f"Email: {email}")
        print(f"Message: {message}")

        # Optionally, add logic to process the form (e.g., save to DB, send email)
        return "Thank you for reaching out!"

    return render_template('contact-me.html')


@app.route('/upcycle')
def upcycle():
    # Example projects for carousel
    projects = [
        {"image_url": "static/images/project1.jpg", "title": "Project 1", "description": "Denim recycle"},
        {"image_url": "static/images/project2.jpg", "title": "Project 2", "description": "Denim Recycle"},
        {"image_url": "static/images/project3.jpg", "title": "Project 3", "description": "Eco-friendly innovation"},
        {"image_url": "static/images/project4.jpg", "title": "Project 4", "description": "Sustainable fashion"}
        ]
    return render_template('upcycle.html', projects=projects)


@app.route('/submit-upcycle', methods=['POST'])
@logged_in_only
def submit_upcycle():
    if not current_user.is_authenticated:
        flash("Please log in to submit an upcycle request.", "error")
        return redirect(url_for("login"))

    # Retrieve current user's ID and details
    user_id = current_user.get_id()
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    unique_user_id = user_data["user_id"]

    # Extract form data
    name = request.form.get("name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    description = request.form.get("description")
    images = request.files.getlist("images")

    # Create a folder in Google Drive for this user
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    folder_name = f"{unique_user_id}_{date_str}"
    parent_folder_id = "1dBWRSUtpkdyu61oFITLXu7-Qz3R-UkgN"  # Replace with your root Drive folder ID
    user_folder_id = create_folder_in_drive(folder_name, parent_folder_id)

    # Upload images to the user's folder
    image_links = []
    for image in images:
        file_stream = BytesIO(image.read())
        shareable_link = upload_to_drive_in_folder(image.stream, image.filename, user_folder_id)
        image_links.append(shareable_link)

    # Save to the upcycle collection
    upcycle_request = {
        "user_id": unique_user_id,
        "name": name,
        "email": email,
        "phone": phone,
        "description": description,
        "images": image_links,
        "submitted_at": datetime.utcnow()
    }
    upcycle_collection.insert_one(upcycle_request)

    # Send email
    email_subject = "New Upcycle Request Submitted"
    email_body = f"""
    A new upcycle request has been submitted:

    Name: {name}
    Email: {email}
    Phone: {phone}
    Description: {description}

    Attached images:
    {', '.join(image_links)}
    """
    send_email("shubhamsheshank63@gmail.com", email_subject, email_body, EMAIL_ADDRESS, EMAIL_PASSWORD)

    flash("Your request has been submitted successfully!", "success")
    return redirect(url_for("upcycle"))



@app.route('/debug')
def debug():
    return {
        "is_authenticated": current_user.is_authenticated,
        "id": current_user.get_id() if current_user.is_authenticated else None
    }

if __name__ == '__main__':
    app.run(debug=True)

