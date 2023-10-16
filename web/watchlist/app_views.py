from datetime import datetime

from smtplib import SMTPException

from sqlalchemy.exc import SQLAlchemyError
from validate_email import validate_email
from watchlist import app, db, LLM_API_URL, memcache_client
from watchlist.models import User, Schedule
from flask_login import login_user, login_required, logout_user, current_user
from flask import request, url_for, redirect, session, jsonify

from watchlist.views import validate_registration_manually, basic_register, basic_send_verification_code, basic_login, \
    check_verification_code


def validate_login_manually(email, password):
    errors = {}
    if not validate_email(email):
        errors['email'] = '请输入有效的邮箱地址，比如：username@domain.com'

    if not password:
        errors['password'] = '密码不能为空'
    elif len(password) < 1 or len(password) > 10:
        errors['password'] = '密码长度必须为1到10位'
    return errors


@app.route("/app_login", methods=["POST"])
def app_login():
    data = request.get_json()
    user_email = data.get('email')
    password = data.get('password')

    # 验证邮箱是否有效
    # errors = validate_login_manually(user_email, password)
    # if errors:
    # return jsonify(errors), 400

    basic_login(user_email, password)


@app.route("/app_register", methods=["POST"])
def app_register():
    data = request.get_json()
    user_email = data.get('email')
    password = data.get('password')
    verification_code = data.get('verification_code')
    cached_verification_code = memcache_client.get(user_email)

    basic_register(user_email, cached_verification_code, verification_code, password)


@app.route("/app_send_verification_code", methods=["POST"])
def app_send_verification_code():
    data = request.get_json()
    email = data.get('email')
    if validate_email(email):
        basic_send_verification_code(email)


@app.route("/app_login_with_CAPTCHA", methods=["POST"])
def app_login_with_code():
    data = request.get_json()
    user_email = data.get('email')
    verification_code = data.get('verification_code')
    cached_verification_code = memcache_client.get(user_email)
    verification_code_error = {}

    user = User.query.get(user_email)
    if user is None:
        return jsonify({"success": False, "message": "The user does not exist."})

    check_verification_code(verification_code_error, cached_verification_code, verification_code)
    if verification_code_error:
        return jsonify(verification_code_error), 400

    login_user(user_email)
    return jsonify({"success": True, "message": "Login success"}), 200
