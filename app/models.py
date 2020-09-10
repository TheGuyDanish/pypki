""" Database models for servervault """
from hashlib import md5
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login
from datetime import datetime

class User(UserMixin, db.Model):
    """ Database model for users """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(256), index=True, unique=True)
    title = db.Column(db.String(128), index=True)
    password_hash = db.Column(db.String(128))
    isAdmin = db.Column(db.Boolean(), server_default="0")
    country = db.Column(db.String(2))
    state = db.Column(db.String(64))
    locality = db.Column(db.String(64))
    org_name = db.Column(db.String(128))
    ou_name = db.Column(db.String(64))

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        """ Set the password to a generated hash, based on input password """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """ Check input password against stored hash """
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        """ Return a gravatar URL based on the users email """
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

@login.user_loader
def load_user(user_id):
    """ Load a user into current_user for usage in logic """
    return User.query.get(int(user_id))

class RootCertificate(db.Model):
    """ Database model for Root Certs (temp until a better implementation) """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), index=True)
    pubkey = db.Column(db.Text)
    privkey = db.Column(db.Text)
    children = db.relationship('IntermediateCertificate', backref='issuer', lazy='dynamic')

class IntermediateCertificate(db.Model):
    """ Database model for Intermediate Certs (temp until a better implementation) """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), index=True)
    pubkey = db.Column(db.Text)
    privkey = db.Column(db.Text)
    root = db.Column(db.Integer, db.ForeignKey('root_certificate.id'))
    children = db.relationship('Certificate', backref='issuer', lazy='dynamic')

class Certificate(db.Model):
    """ Database model for Intermediate Certs (temp until a better implementation) """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), index=True)
    pubkey = db.Column(db.Text)
    privkey = db.Column(db.Text)
    intermediate = db.Column(db.Integer, db.ForeignKey('intermediate_certificate.id'))