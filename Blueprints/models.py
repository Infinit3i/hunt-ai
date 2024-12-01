from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import check_password_hash

# Initialize SQLAlchemy
db = SQLAlchemy()

# Define the User model
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=True)
    theme = db.Column(db.String(50), nullable=True, default='dark')
    team = db.Column(db.String(50), nullable=True, default='Unknown')
    manager = db.Column(db.String(50), nullable=True, default='Unknown')

    def __repr__(self):
        return f"<User {self.username}>"

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
