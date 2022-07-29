import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
import app_config
import os

def gen_session_token(length=24):
    token = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])
    return token

class User:
    def __init__(self, db, username, password,avatar = None, token=None):
        self.db = db
        self.username = username
        self.password = password
        self.avatar = avatar
        self.token = token
    
    @classmethod
    def new(cls, db, username, password, avatar):
        password = generate_password_hash(password)

        db.users.insert({ "username": username, "password": password, "avatar": avatar })

        return cls(db, username, password, avatar)

    @staticmethod
    def find_user(db, username):
        
        return len(list(db.users.find({"username": username}))) > 0

    @classmethod
    def get_user(cls, db, username):
        data = db.users.find_one({"username": username})
        if "token" not in data.keys() or data["token"] == None:
            if("avatar" not in data.keys()):
                return cls(db, data["username"], data["password"])
            return cls(db, data["username"], data["password"], data["avatar"])
        else:
            if("avatar" not in data.keys()):
                return cls(db, data["username"], data["password"], data["token"])
            return cls(db, data["username"], data["password"], data["avatar"], data["token"])
    
    def authenticate(self, password):
        return check_password_hash(self.password, password)

    def update_password(self, password):
        self.password = generate_password_hash(password)
        self.db.users.update_one({"username": self.username}, {"$set": {"password": self.password}})
    
    def init_session(self):
        self.token = gen_session_token()
        self.db.users.update_one({"username": self.username}, {"$set": {"token": self.token}})
        return self.token
    
    def authorize(self, token):
        return token == self.token
    
    def terminate_session(self):
        self.token = None
        self.db.users.update_one({"username": self.username}, {"$set": {"token": None}})

    def update_avatar(self, avatar):
        self.avatar = avatar
        self.db.users.update_one({"username": self.username}, {"$set": {"avatar": self.avatar}})

    def get_avatar(self):
        return self.avatar
    
    def __str__(self):
        return f'{self.username};{self.password};{self.avatar};{self.token}'
    
    def dump(self, db):
        db.users.update_one({"username": self.username},{'$set': {"username": self.username, "password": self.password, "token":self.token, "avatar": self.avatar}},upsert=True)