from flask import Flask, render_template, redirect, url_for, flash, session, request, jsonify
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
from google.oauth2.service_account import Credentials
from datetime import datetime
from io import BytesIO
from googleapiclient.http import MediaIoBaseUpload
import uuid
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from googleapiclient.discovery import build
from google.oauth2 import service_account
from googleapiclient.http import MediaIoBaseUpload
import io

SCOPES = ['https://www.googleapis.com/auth/drive.file']
SERVICE_ACCOUNT_FILE = 'credentials.json'


# Initialize Google Drive API with Shared Drive support
def initialize_drive():
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    return build('drive', 'v3', credentials=creds)


drive_service = initialize_drive()


# Function to find folder ID in Shared Drive
def get_folder_id(folder_name, shared_drive_id):
    query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    results = drive_service.files().list(
        q=query,
        fields="files(id, name)",
        includeItemsFromAllDrives=True,
        supportsAllDrives=True,
        corpora="drive",
        driveId=shared_drive_id
    ).execute()
    folders = results.get('files', [])
    return folders[0]['id'] if folders else None


# Function to create folder in Shared Drive
def create_folder_in_drive(folder_name, parent_folder_id):
    folder_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder',
        'parents': [parent_folder_id],
    }
    folder = drive_service.files().create(
        body=folder_metadata,
        fields='id',
        supportsAllDrives=True
    ).execute()

    folder_id = folder['id']
    folder_link = f"https://drive.google.com/drive/folders/{folder_id}"
    return folder_id, folder_link



# Function to upload a file to a folder in Shared Drive
def upload_to_drive_in_folder(file_stream, file_name, folder_id):
    file_metadata = {
        'name': file_name,
        'parents': [folder_id]
    }
    media = MediaIoBaseUpload(file_stream, mimetype='image/jpeg', resumable=True)
    file = drive_service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id',
        supportsAllDrives=True
    ).execute()

    file_id = file.get('id')
    drive_service.permissions().create(
        fileId=file_id,
        body={'type': 'anyone', 'role': 'reader'},
        supportsAllDrives=True
    ).execute()

    shareable_link = f"https://drive.google.com/uc?export=view&id={file_id}"
    return shareable_link, file_id


app = Flask(__name__)
app.config['SECRET_KEY'] = '1f8b0823a45b17bc6b34c9d8635df4b8dc11f00faac0874d71f3df9d20368d2f'  # Replace with a secure key

# MongoDB Setup
client = MongoClient("mongodb://localhost:27017/kalasuttra")  # Replace with your MongoDB URI
db = client['kalasuttra']
users_collection = db['users']
upcycle_collection = db['upcycle']
appointments_collection = db['appointments']
cart = db['cart']
orders = db['orders']
subscribers = db["subscribers"]


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

def get_unique_user_id():
    if current_user.is_authenticated:
        user_data = users_collection.find_one({"_id": ObjectId(current_user.get_id())})
        return user_data["user_id"] if user_data and "user_id" in user_data else None
    return None


@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    if email:
        # Insert into MongoDB
        subscribers.insert_one({"email": email})
        return jsonify({"status": "success", "message": "Subscribed successfully"}), 200
    return jsonify({"status": "error", "message": "Invalid email"}), 400

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

# # def initialize_drive():
# #     SCOPES = ['https://www.googleapis.com/auth/drive.file']
# #     creds = Credentials.from_service_account_file('credentials.json', scopes=SCOPES)
# #     drive_service = build('drive', 'v3', credentials=creds)
# #     return drive_service
#
# def create_folder_in_drive(folder_name, parent_folder_id=None):
#     drive_service = initialize_drive()
#     folder_metadata = {
#         'name': folder_name,
#         'mimeType': 'application/vnd.google-apps.folder'
#     }
#     if parent_folder_id:
#         folder_metadata['parents'] = [parent_folder_id]
#
#     folder = drive_service.files().create(body=folder_metadata, fields='id').execute()
#     folder_id = folder.get('id')
#
#     drive_service.permissions().create(
#         fileId=folder_id,
#         body={'type': 'anyone', 'role': 'reader'}
#     ).execute()
#
#     folder_link = f"https://drive.google.com/drive/folders/{folder_id}"
#     return folder_id, folder_link
#
# # Upload file to a specific folder in Google Drive
# def upload_to_drive_in_folder(file_stream, file_name, folder_id):
#
#
#     drive_service = initialize_drive()
#     file_metadata = {
#         'name': file_name,
#         'parents': [folder_id]
#     }
#     media = MediaIoBaseUpload(file_stream, mimetype='image/jpeg', resumable=True)
#     file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
#
#     # Make the file publicly accessible
#     file_id = file.get('id')
#     drive_service.permissions().create(
#         fileId=file_id,
#         body={'type': 'anyone', 'role': 'reader'},
#         fields = "id"
#     ).execute()
#
#     # Generate shareable link
#     shareable_link = f"https://drive.google.com/uc?export=view&id={file_id}"
#     return shareable_link, file_id

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


@app.route('/update-phone', methods=['GET', 'POST'])
@logged_in_only
def update_phone():
    user_id = current_user.get_id()

    if request.method == 'POST':
        new_phone = request.form.get("phone")
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"phone": new_phone}})
        flash("Phone number updated successfully!", "success")
        return redirect(url_for('settings'))

    return render_template('update-phone.html')


@app.route('/update-email', methods=['GET', 'POST'])
@logged_in_only
def update_email():
    user_id = current_user.get_id()

    if request.method == 'POST':
        new_email = request.form.get("email")
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"email": new_email}})
        flash("Email updated successfully!", "success")
        return redirect(url_for('settings'))

    return render_template('update-email.html')


@app.route('/update-password', methods=['GET', 'POST'])
@logged_in_only
def update_password():
    user_id = current_user.get_id()
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})

    if request.method == 'POST':
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not check_password_hash(user_data["password"], current_password):
            flash("Current password is incorrect!", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match!", "error")
        else:
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"password": generate_password_hash(new_password)}}
            )
            flash("Password changed successfully!", "success")
            return redirect(url_for('settings'))

    return render_template('update-password.html')


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
    user_id = get_unique_user_id()

    # Fetch saved addresses for the logged-in user
    addresses = list(db.saved_addresses.find({"user_id": user_id}))

    return render_template('saved-address.html', addresses=addresses, active_page='saved_address')


@app.route('/add-address', methods=['GET', 'POST'])
@logged_in_only
def add_address():
    user_id = get_unique_user_id()

    if request.method == 'POST':
        address = {
            "user_id": user_id,
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

    return render_template('add-address.html')

@app.route('/edit-address/<address_id>', methods=['GET', 'POST'])
@logged_in_only
def edit_address(address_id):
    address = db.saved_addresses.find_one({"_id": ObjectId(address_id)})

    if request.method == 'POST':
        db.saved_addresses.update_one(
            {"_id": ObjectId(address_id)},
            {"$set": {
                "name": request.form.get('name'),
                "address_line_1": request.form.get('address_line_1'),
                "address_line_2": request.form.get('address_line_2'),
                "city": request.form.get('city'),
                "state": request.form.get('state'),
                "pincode": request.form.get('pincode')
            }}
        )
        flash("Address updated successfully!", "success")
        return redirect(url_for('saved_address'))

    return render_template('edit-address.html', address=address)


# Home route
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about-kalasuttra')
def about():
    return render_template('about-me.html')


@app.route('/my-account', methods=['GET', 'POST'])
@logged_in_only
def my_account():
    user_id = current_user.get_id()
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})

    if request.method == 'POST':
        phone = request.form.get("phone")
        if phone:
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"phone": phone}}
            )
            flash("Phone number updated successfully!", "success")
            return redirect(url_for('my_account'))

    account_details = {
        "username": user_data.get("name"),
        "email": user_data.get("email"),
        "phone": user_data.get("phone"),  # Will be None if missing
        "created_on": user_data.get("created_on", "Not Available")
    }

    return render_template('my-account.html', account=account_details, active_page='my_account')



@app.route('/order-history')
@logged_in_only
def order_history():
    user_id = get_unique_user_id()
    orders = list(db.orders.find({"user_id": user_id}))

    # Convert ObjectId to string for template rendering
    for order in orders:
        order["_id"] = str(order["_id"])

        # Ensure images is a list
        if isinstance(order["images"], str):
            try:
                order["images"] = json.loads(order["images"])
            except:
                order["images"] = []

        # Process each image in the list
        for img in order["images"]:
            if "resized_url" not in img:  # If resized image doesn't exist, use original
                img["resized_url"] = resize_image_from_url(img["image_url"])

    print("Order History Data:", orders)  # Debugging log

    return render_template("order-history.html", orders=orders)



@app.route('/settings', methods=['GET', 'POST'])
@logged_in_only
def settings():
    user_id = current_user.get_id()
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})

    if request.method == 'POST':
        action = request.form.get("action")

        if action == "update_profile":
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {
                    "name": request.form.get("username"),
                    "email": request.form.get("email"),
                    "phone": request.form.get("phone"),
                    "marketing_emails": request.form.get("marketing_emails") == "on"
                }}
            )
            flash("Profile updated successfully!", "success")

        elif action == "change_password":
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            if not check_password_hash(user_data["password"], current_password):
                flash("Current password is incorrect!", "error")
            elif new_password != confirm_password:
                flash("New passwords do not match!", "error")
            else:
                users_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {"password": generate_password_hash(new_password)}}
                )
                flash("Password changed successfully!", "success")

        elif action == "delete_account":
            users_collection.delete_one({"_id": ObjectId(user_id)})
            logout_user()
            flash("Your account has been deleted.", "info")
            return redirect(url_for("home"))

        return redirect(url_for('settings'))

    account_details = {
        "username": user_data.get("name"),
        "email": user_data.get("email"),
        "phone": user_data.get("phone", ""),
        "marketing_emails": user_data.get("marketing_emails", False)
    }

    return render_template('settings.html', account=account_details, active_page='settings')

import json

@app.route('/move-to-checkout/<cart_id>', methods=['POST'])
@logged_in_only
def move_to_checkout(cart_id):
    user_id = get_unique_user_id()
    cart_item = db.cart.find_one({"_id": ObjectId(cart_id), "user_id": user_id})

    if not cart_item:
        flash("Item not found in cart!", "error")
        return redirect(url_for("cart"))

    # Ensure images is a list
    if isinstance(cart_item["images"], str):
        try:
            cart_item["images"] = json.loads(cart_item["images"])
        except:
            cart_item["images"] = []

    cart_item["_id"] = str(cart_item["_id"])

    # Process each image in the list
    for img in cart_item["images"]:
        # Save the resized URL in each image dictionary
        img["resized_url"] = resize_image_from_url(img["image_url"])
        print("Resized URL:", img["resized_url"])  # Debug log

    return render_template("checkout.html", cart_items=[cart_item])




@app.route('/place-order', methods=['POST'])
@logged_in_only
def place_order():
    user_id = get_unique_user_id()
    cart_items = list(db.cart.find({"user_id": user_id, "status": "In Cart"}))
    selected_address_id = session.get("selected_address")

    if not selected_address_id:
        flash("Please select a delivery address!", "error")
        return redirect(url_for("select_address"))

    selected_address = db.saved_addresses.find_one({"_id": ObjectId(selected_address_id)})

    if not selected_address:
        flash("Address not found!", "error")
        return redirect(url_for("select_address"))

    if not cart_items:
        flash("Your cart is empty!", "warning")
        return redirect(url_for("cart"))

    order_id = str(uuid.uuid4())[:9]

    for item in cart_items:
        price_key = f"price_{item['_id']}"
        price = request.form.get(price_key, 0)

        delivery_address = {
            "name": selected_address["name"],
            "address_line_1": selected_address["address_line_1"],
            "address_line_2": selected_address["address_line_2"],
            "city": selected_address["city"],
            "state": selected_address["state"],
            "pincode": selected_address["pincode"]
        }

        del_address = f"{selected_address.get('name', '')}, {selected_address.get('address_line_1', '')}, " \
                      f"{selected_address.get('address_line_2', '')}, {selected_address.get('city', '')}, " \
                      f"{selected_address.get('state', '')} - {selected_address.get('pincode', '')}"

        # Update order in orders collection
        order = {
            "order_id": order_id,
            "user_id": user_id,
            "description": item["description"],
            "images": item["images"],
            "folder_link": item["folder_link"],
            "price": float(price),
            "status": "Ordered",
            "payment": "Unpaid",
            "delivery_status": "Pending",
            "delivery_address": delivery_address,
            "del_add": del_address,
            "ordered_at": datetime.utcnow()
        }
        db.orders.insert_one(order)

        # Update cart item status
        db.cart.update_one(
            {"_id": ObjectId(item["_id"])},
            {"$set": {"status": "Ordered", "order_id": order_id, "ordered_at": datetime.utcnow()}}
        )

    flash("Order placed successfully!", "success")
    return redirect(url_for("order_history"))


from PIL import Image
import requests
from io import BytesIO


@app.route('/select-address', methods=['GET', 'POST'])
@logged_in_only
def select_address():
    user_id = get_unique_user_id()

    # Fetch saved addresses & convert _id to string for Jinja rendering
    saved_addresses = list(db.saved_addresses.find({"user_id": user_id}))
    for address in saved_addresses:
        address["_id"] = str(address["_id"])  # Convert ObjectId to string

    if request.method == 'POST':
        selected_address_id = request.form.get("selected_address")

        if not selected_address_id:
            flash("Please select an address!", "error")
            return redirect(url_for("select_address"))

        # Store the selected address in session for order placement
        session["selected_address"] = str(selected_address_id)

        print(f"Selected Address ID: {selected_address_id}")

        return redirect(url_for("place_order"))  # Redirect back to checkout

    return render_template("select_address.html", saved_addresses=saved_addresses)



def resize_image_from_url(image_url, size=(200, 200)):
    """Fetches an image from URL, resizes it, and returns the new image URL."""
    try:
        response = requests.get(image_url, stream=True)
        response.raise_for_status()  # Raise an exception for HTTP errors
        image = Image.open(BytesIO(response.content))

        # Convert RGBA (PNG with transparency) to RGB
        if image.mode == "RGBA":
            image = image.convert("RGB")

        image.thumbnail(size)  # Resize while maintaining aspect ratio

        # Convert resized image to bytes
        img_io = BytesIO()
        image.save(img_io, format="JPEG", quality=85)
        img_io.seek(0)

        # Create a filename based on the file id extracted from the URL
        # Ensure that the URL contains 'id=' to extract a proper file id.
        file_id_part = image_url.split('id=')[-1]
        resized_filename = f"resized_{file_id_part}.jpg"

        # Save resized image in the static folder
        # IMPORTANT: Use a leading slash so that the browser can resolve it
        resized_path = f"/static/{resized_filename}"
        with open("static/" + resized_filename, "wb") as f:
            f.write(img_io.getbuffer())

        return resized_path
    except Exception as e:
        print("Image Resize Error:", e)
        return image_url  # Return the original URL if resizing fails


@app.route('/cart')
@logged_in_only
def cart():
    user_id = get_unique_user_id()
    cart_items = list(db.cart.find({"user_id": user_id, "status": "In Cart"}))  # Fetch only active cart items

    # Convert ObjectId to string for template rendering
    for item in cart_items:
        for img in item["images"]:
            img["resized_url"] = resize_image_from_url(img["image_url"])

    return render_template('cart.html', cart_items=cart_items)

@app.route('/remove-from-cart/<cart_id>', methods=['POST'])
@logged_in_only
def remove_from_cart(cart_id):
    db.cart.delete_one({"_id": ObjectId(cart_id)})
    flash("Item removed from cart.", "success")
    return redirect(url_for("cart"))



@app.route('/contact-me', methods=['GET', 'POST'])
@logged_in_only  # Ensures only logged-in users can make appointments
def contact():
    if request.method == 'POST':
        # Retrieve current user's ID
        user_id = current_user.get_id()
        user_data = users_collection.find_one({"_id": ObjectId(user_id)})
        unique_user_id = user_data["user_id"]

        # Extract form data
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        message = request.form.get("message")
        appointment_date = datetime.utcnow()

        # Store appointment details in MongoDB
        appointment = {
            "user_id": unique_user_id,
            "name": name,
            "email": email,
            "phone": phone,
            "message": message,
            "appointment_date": appointment_date
        }
        appointments_collection.insert_one(appointment)

        # Send email notification
        email_subject = "New Appointment Request"
        email_body = f"""
        A new appointment has been requested:

        Name: {name}
        Email: {email}
        Phone: {phone}
        Message: {message}
        Appointment Date: {appointment_date.strftime('%Y-%m-%d %H:%M:%S')}
        """
        send_email("shubhamsheshank63@gmail.com", email_subject, email_body, EMAIL_ADDRESS, EMAIL_PASSWORD)

        flash("Your appointment request has been submitted!", "success")
        return redirect(url_for("contact"))

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
    upcycle_id = str(uuid.uuid4())[:9]

    # Extract form data
    name = request.form.get("name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    description = request.form.get("description")
    images = request.files.getlist("file[]")

    # Create a folder in Google Drive for this user
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    folder_name = f"{unique_user_id}_{date_str}"
    parent_folder_id = "1dBWRSUtpkdyu61oFITLXu7-Qz3R-UkgN"  # Replace with your root Drive folder ID
    user_folder_id, folder_link = create_folder_in_drive(folder_name, parent_folder_id)

    # Upload images to the user's folder
    image_links = []
    for image in images:
        file_stream = BytesIO(image.read())
        image_link, file_id = upload_to_drive_in_folder(file_stream, image.filename, user_folder_id)
        image_links.append({"file_id": file_id, "image_url": image_link})

    # Save to the upcycle collection
    upcycle_request = {
        "upcycle_id": upcycle_id,
        "user_id": unique_user_id,
        "name": name,
        "email": email,
        "phone": phone,
        "description": description,
        "images": image_links,
        "folder_link": folder_link,
        "submitted_at": datetime.utcnow()
    }
    upcycle_collection.insert_one(upcycle_request)

    cart_item = {
        "upcycle_id": upcycle_id,
        "user_id": unique_user_id,
        "description": description,
        "images": image_links,
        "folder_link": folder_link,
        "status": "In Cart",
        "price": None  # Admin will update price
    }
    db.cart.insert_one(cart_item)

    # Send email
    email_subject = "New Upcycle Request Submitted"
    email_body = f"""
    A new upcycle request has been submitted:

    Name: {name}
    Email: {email}
    Phone: {phone}
    Description: {description}
    Google Drive Folder with Uploaded Images:
    {folder_link} 

    
    """
    send_email("shubhamsheshank63@gmail.com", email_subject, email_body, EMAIL_ADDRESS, EMAIL_PASSWORD)

    flash("Your request has been submitted successfully!", "success")
    return redirect(url_for("upcycle"))

@app.route('/upcycle-measurement-form')
@logged_in_only
def upcycle_measurement():
    return render_template('upcycle-measurement.html')

@app.route('/submit-measurements', methods=['POST'])
@logged_in_only
def submit_measurements():
    data = {
        "user_id": get_unique_user_id(),
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "bust": request.form.get("bust"),
        "waist": request.form.get("waist"),
        "hip": request.form.get("hip"),
        "height": request.form.get("height"),
        "submitted_at": datetime.utcnow()
    }
    db.measurements.insert_one(data)
    send_email("shubhamsheshank63@gmail.com", "New Measurement Submission", str(data), EMAIL_ADDRESS, EMAIL_PASSWORD)
    flash("Measurements submitted!", "success")
    return redirect(url_for("upcycle"))

@app.route('/catalog')
def catalog():
    return render_template('catalog.html')




@app.route('/debug')
def debug():
    return {
        "is_authenticated": current_user.is_authenticated,
        "id": current_user.get_id() if current_user.is_authenticated else None
    }

if __name__ == '__main__':
    app.run(debug=True)
