from datetime import datetime, timedelta
import random
from smtplib import SMTPException

import requests
from flask_mail import Message
from flask_wtf.csrf import generate_csrf
from sqlalchemy.exc import SQLAlchemyError
from validate_email import validate_email
from watchlist import app, db, Alpaca_API_URL, mail, Session, memcache_client
from watchlist.models import User, Schedule, Share
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
            Email(message="请输入有效的邮箱地址，比如：email@domain.com"),
        ],
    )
    password = PasswordField("密码", validators=[DataRequired(message="密码不能为空")])
    submit = SubmitField("登录")


class LoginFormCAPTCHA(FlaskForm):
    email = StringField(
        "邮箱",
        validators=[
            DataRequired(message="邮箱不能为空"),
            Length(1, 64),
            Email(message="请输入有效的邮箱地址，比如：email@domain.com"),
        ],
    )
    verification_code = PasswordField("验证码", validators=[DataRequired(message="验证码不能为空"), Length(6)])
    submit = SubmitField("登录")


class RegisterForm(FlaskForm):
    email = StringField(
        "邮箱",
        validators=[
            DataRequired(message="邮箱不能为空"),
            Length(1, 64),
            Email(message="请输入有效的邮箱地址，比如：email@domain.com"),
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


@app.route('/csrf_token', methods=['GET'])
def get_csrf_token():
    # Generate and return a CSRF token
    csrf_token = generate_csrf()
    return jsonify({'csrf_token': csrf_token})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        form = LoginForm(data=data)
        if form.validate():
            user_email = form.email.data
            password = form.password.data
            login_message = dict()

            basic_login(user_email, password, login_message)
            return login_message, 200
        errors = dict()
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息
        return jsonify(errors), 400

    return render_template("login.html")


@app.route("/login_with_CAPTCHA", methods=["GET", "POST"])
def login_with_CAPTCHA():
    form = LoginFormCAPTCHA()
    if request.method == "POST":
        if form.validate():
            user_email = form.email.data
            verification_code = form.verification_code.data
            verification_code_error = {}
            cached_verification_code = memcache_client.get(user_email)

            user = User.query.filter_by(email=user_email).first
            if user is None:
                return jsonify({"success": False, "message": "The user does not exist."})

            check_verification_code(verification_code_error, cached_verification_code, verification_code)
            if verification_code_error:
                return jsonify(verification_code_error), 400

            login_user(user_email)
            return jsonify({"success": True, "message": "Login success"}), 200

        errors = dict()
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息
        return jsonify(errors), 400


@app.route("/send_verification_code", methods=["POST"])
def send_verification_code():
    data = request.form
    email = data.get('email')

    # 验证邮箱是否有效
    if not validate_email(email):
        return jsonify({'success': False, 'message': "请输入有效的邮箱地址，比如：email@domain.com"}), 400
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
            verification_code_error = dict()

            check_verification_code(verification_code_error, cached_verification_code, verification_code)
            if verification_code_error:
                return jsonify(verification_code_error), 200

            basic_register(user_email, cached_verification_code, verification_code, password)
        errors = dict()
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


@app.route("/share_schedule", methods=["POST"])
@login_required  # 视图保护
def share_schedule():
    data = request.get_json()
    schedule_id = data.get("id")
    schedule = Schedule.query.filter_by(id=schedule_id).first()
    if schedule and schedule.state == "启用":
        one_week_later = datetime.now() + timedelta(days=7)
        shared_schedule = Share(schedule_id, one_week_later)

        db.session.add(shared_schedule)
        db.session.commit()
        return jsonify({"success": True,
                        "message": "share schedule successful", "share_code": shared_schedule.share_code}), 200
    return jsonify({"success": False, "message": " schedule is overdue", "share_code": "null"}), 200


@app.route("/add_share_schedule", methods=["POST"])
@login_required  # 视图保护
def add_share_schedule():
    data = request.get_json()
    share_code = data.get("share_code")
    shared_schedule = Share.query.filter_by(share_code=share_code).first()
    if datetime.now() < shared_schedule.expiration_date:
        session['shared_schedule_id'] = shared_schedule.schedule_id
        return jsonify({"success": True, "message": "add shared_schedule successful"}), 200
    return jsonify({"success": False, "message": "The share code has expired"}), 200


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


def generate_random_code():
    verification_code = ''.join(random.choice('0123456789') for _ in range(6))
    return verification_code


def basic_register(user_email, password, registration_message):
    if User.query.filter_by(email=user_email).first():
        registration_message['success'] = False
        registration_message['message'] = "Email already registered"
        return registration_message

    user = User(email=user_email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    memcache_client.delete(user_email)
    # 返回一个json
    registration_message['success'] = True
    registration_message['message'] = "register success"

    return registration_message


def basic_login(user_email, password, login_message):
    user = User.query.filter_by(email=user_email).first()
    if user is not None and user.validate_password(password):
        login_user(user)  # 登入用户
        login_message['success'] = True
        login_message['message'] = "Login success."

    else:
        login_message['success'] = False
        login_message['message'] = "Email or Password Invalid."
    return login_message


def validate_registration_manually(email, password, repeat_password):
    errors = dict()

    if not validate_email(email):
        errors['email'] = '请输入有效的邮箱地址，比如：email@domain.com'

    if not password:
        errors['password'] = '密码不能为空'
    elif len(password) < 1 or len(password) > 10:
        errors['password'] = '密码长度必须为1到10位'

    if not repeat_password:
        errors['repeatPassword'] = '确认密码不能为空'
    elif password != repeat_password:
        errors['repeatPassword'] = '两次输入的密码不一致'

    return errors


def basic_send_verification_code(message, email):
    # 生成验证码
    verification_code = generate_random_code()

    # 保存验证码到 Memcache
    memcache_client.set(email, verification_code, time=120)  # 保存2分钟，可以根据需求修改

    # 发送验证码邮件
    if send_verification_email(email, verification_code):
        message['success'] = True
        message['message'] = 'Verification code sent successfully'

    else:
        message['success'] = False
        message['message'] = 'Failed to send verification code'
    return message


def check_verification_code(verification_code_error, cached_verification_code, verification_code):
    if cached_verification_code is None:
        verification_code_error['success'] = 'False'
        verification_code_error['message'] = 'Not send verification code yet'

    if cached_verification_code != verification_code:
        verification_code_error['success'] = 'False'
        verification_code_error['message'] = 'Wrong verification code'
    return verification_code_error


def send_data_to_alpaca(input_data, user_preference):
    request_data = {
        "messages": [
            {"role": "user", "content": "日程信息:" + input_data + ";" + "用户偏好:" + user_preference + ";"}
        ],
        "repetition_penalty": 1.0
    }
    url = Alpaca_API_URL
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=request_data, headers=headers)
    if response.status_code == 200:
        return True, response.json()
    else:
        return False, {"error": f"HTTP请求失败，状态码: {response.status_code}"}


def extract_data_from_alpaca(response_data):
    try:
        # 校验JSON返回体是否包含必要的字段
        required_keys = ["choices"]
        for key in required_keys:
            if key not in response_data:
                raise ValueError(f"Missing required key: {key}")

        choices = response_data["choices"]

        if not isinstance(choices, list) or len(choices) == 2:
            raise ValueError("Choices should be a list with at least two elements")

        answer_content = choices[1].get("message", {}).get("content", "")

        # 检查 content 是否包含 "^" 分隔符。
        if "^" not in answer_content or ":" not in answer_content:
            raise ValueError("Invalid content format")

        parts = answer_content.split('^')

        # 创建一个dic来存储各个属性的内容
        attributes = {}

        # 遍历分割后的部分并提取属性内容
        for part in parts:
            # 使用 ':' 分割每个部分
            key_value = part.split(':')

            # 如果成功分割成两部分，将内容添加到字典中
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip()
                attributes[key] = value

        return attributes

    except (KeyError, IndexError, ValueError) as e:
        # 如果键不存在、索引越界或者格式不符合预期，返回 None
        print(f"Error extracting data: {e}")
        return None


def create_schedule(schedule_attributes):
    schedule = {
        'time_type': schedule_attributes['time_type'],
        'start_time': schedule_attributes['start_time'],
        'end_time': schedule_attributes['end_time'],
        'schedule_brief': schedule_attributes['schedule_brief'],
        'schedule_detail': schedule_attributes['schedule_detail'],
        'schedule_type': schedule_attributes['time_type']
    }
    return schedule
