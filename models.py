# IMPORTS
from datetime import datetime
import pyotp
from flask_login import UserMixin
from app import db, app
import bcrypt
from cryptography.fernet import Fernet


# User DB Table
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    # Users ID
    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    pinkey = db.Column(db.String(100), nullable=False)

    # User personal information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    # Users Security information
    role = db.Column(db.String(100), nullable=False, default='user')
    registered_on = db.Column(db.DateTime, nullable=False)
    current_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

    # Initialises users information
    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        self.pinkey = pyotp.random_base32()
        self.registered_on = datetime.now()
        self.current_login = None
        self.last_login = None


# Encrypts data
def encrypt(data, key):
    return Fernet(key).encrypt(bytes(data, 'utf-8'))


# Decrypts data
def decrypt(data, key):
    return Fernet(key).decrypt(data).decode('utf-8')


# Initialises DB
def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        # Creates admin account
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')
        # Updates DB
        db.session.add(admin)
        db.session.commit()
