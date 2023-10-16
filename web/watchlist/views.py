from datetime import datetime
import random
from smtplib import SMTPException

from flask_mail import Message
from sqlalchemy.exc import SQLAlchemyError
from validate_email import validate_email
from watchlist import app, db, LLM_API_URL, memcache_client, mail
from watchlist.models import User, Schedule
from flask_login import login_user, login_required, logout_user, current_user
from flask import render_template, request, url_for, redirect, flash, session, jsonify
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_wtf import FlaskForm


class LoginForm(FlaskForm):
    email = StringField(
        "邮箱",
        validators=[
            DataRequired(message="邮箱不能为空"),
            Length(1, 64),
            Email(message="请输入有效的邮箱地址，比如：username@domain.com"),
        ],
    )
    password = PasswordField("密码", validators=[DataRequired(message="密码不能为空")])
    submit = SubmitField("登录")


class RegisterForm(FlaskForm):
    email = StringField(
        "邮箱",
        validators=[
            DataRequired(message="邮箱不能为空"),
            Length(1, 64),
            Email(message="请输入有效的邮箱地址，比如：username@domain.com"),
        ],
    )
    password = PasswordField(
        "密码", validators=[DataRequired(message="密码不能为空"), Length(1, 10)]
    )
    repeatPassword = PasswordField(
        "确认密码",
        validators=[
            DataRequired(message="确认密码不能为空"),
            EqualTo("password", message="两次输入的密码不一致"),
        ],
    )
    verification_code = StringField("验证码", validators=[DataRequired(message="验证码不能为空")])
    submit = SubmitField("注册")


@app.route("/", methods=["GET"])
def beginpage():
    return render_template("beginpage.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate():
            user_email = form.email.data
            password = form.password.data
            basic_login(user_email, password)
        errors = {}
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息
        return jsonify(errors), 400

    return render_template("login.html", form=form)


@app.route("/send_verification_code", methods=["POST"])
def send_verification_code():
    data = request.form
    if not data:
        data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    repeat_password = data.get('repeatPassword')

    # 验证邮箱是否有效
    errors = validate_registration_manually(email, password, repeat_password)
    if errors:
        return jsonify(errors), 400
    basic_send_verification_code(email)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        if form.validate():
            user_email = form.email.data
            password = form.password.data
            verification_code = form.verification_code.data
            cached_verification_code = memcache_client.get(user_email)
            basic_register(user_email, cached_verification_code, verification_code, password)
        errors = {}
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息，可以根据需要修改此处
        return jsonify(errors), 400

    return render_template("register.html", form=form)


@app.route("/logout", methods=["GET"])
@login_required  # 视图保护
def logout():
    logout_user()  # 登出用户
    return jsonify({"success": True, "message": "Log out successful"}), 200


@app.route("/index", methods=["GET"])
@login_required  # 视图保护
def index():
    return render_template("index.html")


def basic_login(user_email, password):
    user = User.query.get(user_email)
    if user is not None and user.validate_password(password):
        login_user(user)  # 登入用户
        # 清除会话中的保存信息
        # session.pop("saved_email", None)
        # session.pop("saved_password", None)
        return jsonify({"success": True, "message": "Login success."})
    return jsonify(
        {"success": False, "message": "Email or Password Invalid"}  # 如果验证失败，显示错误消息
    )


def send_verification_email(email, verification_code):
    try:
        email_content = render_template('email_verification.html', email_text=email,
                                        verification_code=verification_code)
        msg = Message('verification for your ScheduleMaster account', sender=app.config["MAIL_USERNAME"],
                      recipients=[email])
        msg.html = email_content
        mail.send(msg)
        return True  # 邮件发送成功，返回 True
    except SMTPException as e:

        return False  # 邮件发送失败，返回 False


def generate_verification_code():
    verification_code = ''.join(random.choice('0123456789') for _ in range(6))
    return verification_code


def basic_register(user_email, cached_verification_code, verification_code, password):
    verification_code_error = {}
    if User.query.filter_by(email=user_email).first():
        return jsonify(
            {"success": False, "message": "Email already registered"}
        ), 200

    check_verification_code(verification_code_error, cached_verification_code, verification_code)
    if verification_code_error:
        return jsonify(verification_code_error), 400

    user = User(email=user_email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    memcache_client.delete(user_email)
    # 返回一个json
    return jsonify({"success": True, "message": "register success"})


def validate_registration_manually(email, password, repeat_password):
    errors = {}

    if not validate_email(email):
        errors['email'] = '请输入有效的邮箱地址，比如：username@domain.com'

    if not password:
        errors['password'] = '密码不能为空'
    elif len(password) < 1 or len(password) > 10:
        errors['password'] = '密码长度必须为1到10位'

    if not repeat_password:
        errors['repeatPassword'] = '确认密码不能为空'
    elif password != repeat_password:
        errors['repeatPassword'] = '两次输入的密码不一致'

    return errors


def basic_send_verification_code(email):
    # 生成验证码
    verification_code = generate_verification_code()

    # 保存验证码到 Memcache
    memcache_client.set(email, verification_code, time=120)  # 保存2分钟，可以根据需求修改

    # 发送验证码邮件
    if send_verification_email(email, verification_code):
        return jsonify({"success": True, 'message': 'Verification code sent successfully'}), 200
    else:
        return jsonify({"success": False, "message": "Failed to send verification code"}), 200


def check_verification_code(verification_code_error, cached_verification_code, verification_code):
    if cached_verification_code is None:
        verification_code_error['success'] = 'False'
        verification_code_error['message'] = 'Not send verification code yet'

    if cached_verification_code != verification_code:
        verification_code_error['success'] = 'False'
        verification_code_error['message'] = 'Wrong verification code'
    return verification_code_error
