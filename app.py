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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        name = request.form["name"]

        # Check if user already exists
        if users_collection.find_one({"email": email}):
            flash("Email already exists. Please log in.", "error")
            return redirect(url_for("login"))

        # Create new user
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password
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
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# Home route
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about-kalasuttra')
def about():
    return render_template('about-me.html')

@app.route('/my-account')
@logged_in_only
def Myaccount():
    return render_template('my-account.html')

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
@logged_in_only
# @login_required
def upcycle():
    # if not current_user.is_authenticated:
    #         flash("You need to login or register")
    #         return redirect(url_for("login"))
 
    return render_template('upcycle.html')



@app.route('/debug')
def debug():
     return {
         "is_authenticated": current_user.is_authenticated,
         "id": current_user.get_id() if current_user.is_authenticated else None
     }

if __name__ == '__main__':
    app.run(debug=True)
