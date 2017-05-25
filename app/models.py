import os
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

from app import db

auth = HTTPBasicAuth()


class Users(db.Model):
    """Class represents the users table"""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(90))
    date_registered = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_password = db.Column(db.String(200))
    bucket_lists = db.relationship("Bucketlists", backref="user", lazy="dynamic")

    def __init__(self, username, password):
        """initialize with username and password"""
        self.user_name = username
        self.user_password = pwd_context.encrypt(password)

    def hash_password(self, password):
        """hash user password"""
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """verify user password"""
        return pwd_context.verify(password, self.user_password)

    def generate_auth_token(self, expiration=600):
        """generates authorization token"""
        s = Serializer(os.getenv("SECRET"), expires_in=expiration)
        return s.dumps({"id": self.id})

    @staticmethod
    def verify_auth_token(token):
        """verifies authorization token"""
        s = Serializer(os.getenv("SECRET"))
        try:
            data = s.loads(token)
        except SignatureExpired:
            return "expired"    # valid token, but expired
        except BadSignature:
            return "invalid"   # invalid token
        user = Users.query.get(data["id"])
        return user

    def save(self):
        """saves new user object"""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all():
        """gets all user objects"""
        return Users.query.all()

    @staticmethod
    def get_one(user_id):
        """get's single user object given id"""
        return Users.query.filter_by(id=user_id).first()

    def delete(self):
        """deletes current user object"""
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        """user object string representation"""
        return "<Users: {}>".format(self.user_name)


class Bucketlists(db.Model):
    """This class represents the bucketlist table."""

    __tablename__ = "bucketlists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(
        db.DateTime, default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp())
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    items = db.relationship("BucketListItems", backref="bucketlist",
                            cascade="save-update, merge, delete", lazy="dynamic")

    def __init__(self, name, user_id):
        """initialize with name and user id"""
        self.name = name
        self.created_by = user_id

    def save(self):
        """save new bucketlist object"""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all_for_user(user_id=0):
        """get all bucketlists for user with given id"""
        return Bucketlists.query.filter_by(created_by=user_id)

    def delete(self):
        """delete current object"""
        db.session.delete(self)
        db.session.commit()

    def update(self):
        """update current object"""
        db.session.commit()

    def __repr__(self):
        """bucketlist object string representation"""
        return "<Bucketlists: {}>".format(self.name)


class BucketListItems(db.Model):
    """Reepresents table bucket_list_items"""

    __tablename__ = "bucket_list_items"

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(
        db.DateTime, default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp())
    done = db.Column(db.Boolean, default=False)
    bucket_id = db.Column(db.Integer, db.ForeignKey("bucketlists.id"))

    def __init__(self, description, bucket_id):
        """initialize with description and bucketlist id"""
        self.description = description
        self.bucket_id = bucket_id

    def save(self):
        """save new bucketlist item object"""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all_for_bucket(bucket_id):
        """get all items in bucket with given id"""
        return BucketListItems.query.filter(created_by=bucket_id)

    def delete(self):
        """delete current object"""
        db.session.delete(self)
        db.session.commit()

    def update(self):
        """update current object"""
        db.session.commit()

    def __repr__(self):
        """string representation for object"""
        return "<Bucketlists: {}>".format(self.name)
