from datetime import datetime
import random
from smtplib import SMTPException

from sqlalchemy.exc import SQLAlchemyError
from validate_email import validate_email
from watchlist import app, db, LLM_API_URL, memcache_client, mail
from watchlist.models import User, Schedule
from flask_login import login_user, login_required, logout_user, current_user
from flask import render_template, request, url_for, redirect, flash, session, jsonify
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp

from watchlist.views import validate_registration_manually, generate_verification_code, send_verification_email, \
    basic_register, basic_send_verification_code


def validate_login_manually(email, password):
    errors = {}
    if not validate_email(email):
        errors['email'] = '请输入有效的邮箱地址，比如：username@domain.com'

    if not password:
        errors['password'] = '密码不能为空'
    elif len(password) < 1 or len(password) > 10:
        errors['password'] = '密码长度必须为1到10位'
    return errors


@app.route("/login_for_app", methods=["POST"])
def app_login():
    data = request.get_json()
    user_email = data.get('email')
    password = data.get('password')

    # 验证邮箱是否有效
    errors = validate_login_manually(user_email, password)
    if errors:
        return jsonify(errors), 400

    user = User.query.get(user_email)
    if user is not None and user.validate_password(password):
        login_user(user)  # 登入用户
        return jsonify({"success": True, "message": "Login success."}), 200
    return jsonify(
        {"success": False, "message": "Email or Password Invalid"}  # 如果验证失败，显示错误消息
    ), 400


@app.route("/register_for_app", methods=["POST"])
def app_register():
    data = request.get_json()
    user_email = data.get('email')
    password = data.get('password')
    repeat_password = data.get('repeatPassword')
    verification_code = data.get('verification_code')
    cached_verification_code = memcache_client.get('email')

    errors = validate_registration_manually(user_email, password, repeat_password)  # 不能使用Flask-WTF的自动验证, 只能手动验证
    if errors:
        return jsonify(errors), 400

    basic_register(user_email, cached_verification_code, verification_code, password)


@app.route("/send_verification_code_for_app", methods=["POST"])
def send_verification_code():
    data = request.get_json()
    email = data.get('email')
    # password = data.get('password')
    # repeat_password = data.get('repeatPassword')

    # 验证邮箱是否有效
    # errors = validate_registration_manually(email, password, repeat_password)
    # if errors:
    #   return jsonify(errors), 400
    basic_send_verification_code(email)
