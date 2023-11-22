import calendar
from datetime import datetime, timedelta
import random
from smtplib import SMTPException

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Message
from flask_wtf.csrf import generate_csrf
from sqlalchemy.exc import SQLAlchemyError
from validate_email import validate_email
from watchlist import app, db, Alpaca_API_URL, mail, Session, memcache_client, celery
from watchlist.models import User, Schedule, Share, ScheduleState, Reminder
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


def check_reminders():
    current_time = datetime.now()
    reminders = Reminder.query.filter(Reminder.reminder_time <= current_time).all()

    for reminder in reminders:
        send_result = send_reminder.apply_async(args=[reminder.schedule_id])
        if send_result.successful():
            # Delete the reminder from the database
            db.session.delete(reminder)
            db.session.commit()


scheduler = BackgroundScheduler()
scheduler.add_job(func=check_reminders, trigger="interval", minutes=1)
scheduler.start()


def send_reminder_email(user, schedule):
    # 构造邮件消息
    subject = f'提醒：{schedule.schedule_brief}日程即将开始'
    body = f'亲爱的 {user.username}，您的日程即将在 {schedule.start_time} 开始。请注意安排您的时间。'
    recipients = [user.email]

    # 创建邮件对象
    message = Message(subject=subject, body=body, recipients=recipients)

    # 发送邮件
    try:
        mail.send(message)
        return True
    except Exception as e:
        # 发送失败时的处理
        print(f"Error sending email: {str(e)}")
        return False


@celery.task
def send_reminder(schedule_id):
    schedule = Schedule.query.filter_by(schedule_id=schedule_id).first()
    user = schedule.user.first()
    result = send_reminder_email(user, schedule)
    if result:
        return True
    return False


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


@app.route("/login_verification", methods=["GET", "POST"])
def login_verification():
    if request.method == "POST":
        data = request.form
        form = LoginFormCAPTCHA(data=data)
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
    return render_template("login_verification.html")


@app.route("/send_verification_code", methods=["POST"])
def send_verification_code():
    data = request.form
    email = data.get('email')
    message = {}
    # 验证邮箱是否有效
    if not validate_email(email):
        return jsonify({'success': False, 'message': "请输入有效的邮箱地址，比如：email@domain.com"}), 400
    basic_send_verification_code(email=email, message=message)
    return message


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        form = RegisterForm(data=data)
        if form.validate():
            user_email = form.email.data
            password = form.password.data
            verification_code = form.verification_code.data
            cached_verification_code = memcache_client.get(user_email)
            verification_code_error = dict()
            registration_message = dict()

            check_verification_code(verification_code_error, cached_verification_code, verification_code)
            if verification_code_error:
                return jsonify(verification_code_error), 200

            basic_register(user_email=user_email, password=password, registration_message=registration_message)
        errors = dict()
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息，可以根据需要修改此处
        return jsonify(errors), 400

    return render_template("register.html")


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
        if not user.is_authenticated:
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


def generate_remind_times(schedule):     # 将所有提醒时间批量加入Reminder中
    occurrences = calculate_schedule_occurrences(schedule=schedule)
    reminder_times = calculate_reminder(occurrence=occurrences, schedule=schedule)
    try:
        for remind in reminder_times:
            db.session.add(remind)
        db.session.commit()
        return True

    except SQLAlchemyError as e:
        # 如果发生异常，回滚数据库并记录错误
        db.session.rollback()
        print(f"Error adding reminders to the database: {str(e)}")
        return False


def calculate_reminder(occurrence, schedule: Schedule):
    notify = schedule.notice.first()
    reminder_times = []
    if schedule.if_remind_message and schedule.schedule_status == ScheduleState.ENABLED:
        # 遍历每个发生时间
        for event_time in occurrence:
            # 计算提前多少时间发送提醒
            reminder_time = event_time - timedelta(seconds=notify.before_time)

            # 添加第一次提醒时间
            reminder_times.append((reminder_time, schedule.schedule_id))

    return reminder_times


def calculate_schedule_occurrences(schedule):
    occurrences = []

    # 设置起始时间为日程开始时间
    current_time = schedule.start_time
    if schedule.if_remind_message and schedule.schedule_status == ScheduleState.ENABLED:
        occurrences.append(current_time)
        while current_time.year <= 2071:
            next_occurrence = calculate_next_occurrence_based_on_type(schedule, current_time)  # 计算下一次发生的时间
            occurrences.append(next_occurrence)  # 添加到结果列表
            current_time = next_occurrence  # 更新当前时间为下一次发生的时间
    filtered_occurrences = [dt for dt in occurrences if dt >= datetime.now()]
    return filtered_occurrences


def calculate_next_occurrence_based_on_type(schedule, current_time):
    # 映射不同的日程类型到相应的计算方法
    type_mapping = {
        'SINGLE': calculate_single_occurrence,
        'CYCLE': calculate_cycle_occurrence,
        'EVERY_DAY': calculate_every_day_occurrence,
        'EVERY_WEEK': calculate_every_week_occurrence,
        'EVERY_MONTH': calculate_every_month_occurrence,
        'EVERY_YEAR': calculate_every_year_occurrence,
    }

    # 获取对应日程类型的计算方法，默认为 None
    calculate_method = type_mapping.get(schedule.schedule_type, None)

    # 调用计算方法并返回结果
    if calculate_method:
        return calculate_method(schedule, current_time)
    else:
        return None


def calculate_single_occurrence(schedule, current_time):
    # 如果是单次日程，则返回空
    return None


def calculate_cycle_occurrence(schedule, current_time):
    next_time = current_time + timedelta(seconds=schedule.date)
    return current_time + next_time


def calculate_every_day_occurrence(schedule, current_time):
    # 如果是每天发生，则根据date_num计算下一次发生的时间
    return current_time + timedelta(days=schedule.date)


def calculate_every_week_occurrence(schedule, current_time):
    # 如果是每周发生，则根据date_num计算下一次发生的时间
    return current_time + timedelta(weeks=schedule.date)


def calculate_every_month_occurrence(schedule, current_time):
    # 如果是每月发生，则根据date_num计算下一次发生的时间
    next_occurrence_month = current_time.month + schedule.date
    next_occurrence_year = current_time.year + (next_occurrence_month - 1) // 12
    next_occurrence_month = (next_occurrence_month - 1) % 12 + 1
    next_occurrence_day = min(current_time.day, calendar.monthrange(next_occurrence_year, next_occurrence_month)[1])
    next_occurrence = datetime(next_occurrence_year, next_occurrence_month, next_occurrence_day,
                               current_time.hour, current_time.minute, current_time.second)
    return next_occurrence


def calculate_every_year_occurrence(schedule, current_time):
    # 如果是每年发生，则根据date_num计算下一次发生的时间
    return current_time.replace(year=current_time.year + schedule.date)
