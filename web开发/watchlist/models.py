from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from watchlist import db

class User(db.Model, UserMixin):
    email = db.Column(db.String(30), primary_key=True)
    password_hash = db.Column(db.String(128))  # 密码散列值
    schedule = db.relationship('Schedule', backref='user', lazy=True)

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值

    def get_id(self):
        return str(self.email)


class Schedule(db.Model):
    begindate = db.Column(db.DateTime, primary_key=True)
    endate = db.Column(db.DateTime, primary_key=True)
    scheduleEvent = db.Column(db.Text)
    location = db.Column(db.Text)
    user_email = db.Column(db.String(30), db.ForeignKey('user.email'),
                           nullable=False, primary_key=True)