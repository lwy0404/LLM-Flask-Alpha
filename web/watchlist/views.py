import asyncio
import base64
import calendar
import concurrent
import copy
import json
import os
import re
import socket
from datetime import datetime, timedelta
import random
from functools import partial
from smtplib import SMTPException
from typing import Optional, Dict
import concurrent.futures
import threading

import aiohttp
import pytz
import requests

from flask_mail import Message
from flask_wtf.csrf import generate_csrf
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from validate_email import validate_email
from watchlist import app, db, Alpaca_API_URL, mail, Session, memcache_client, celery, scheduler, GLM_API_URL, \
    CHECK_PATH
from watchlist.models import User, Schedule, Share, ScheduleState, Reminder, ScheduleDate, Notify, ScheduleType, \
    TimeType, InputData, LanguageModel
from flask_login import login_user, login_required, logout_user, current_user
from flask import render_template, request, url_for, redirect, flash, session, jsonify, current_app
from wtforms import StringField, SubmitField, PasswordField, IntegerField, validators, DateField, BooleanField
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
    user_name = StringField("用户名",
                            validators=[
                                DataRequired(message="用户名不能为空"),
                                Length(1, 40, message="用户名不能为空"), ])
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


class LLMForm(FlaskForm):  # 提交至语言模型的数据
    description = StringField(
        "描述",
        validators=[
            DataRequired(message="日程描述不能为空"),
            Length(1, 2000)
        ]
    )
    preference = StringField("用户偏好",
                             validators=[
                                 Length(0, 1000, message="用户偏好长度为1-1000")])

    submit = SubmitField("提交")


class AddScheduleForm(FlaskForm):  # 添加日程
    notify_id = IntegerField("提醒设置")
    original_data_id = IntegerField("初始数据", validators=[DataRequired(message="初始数据不能为空")])
    schedule_status = StringField(
        "日程状态",
        validators=[DataRequired(message="日程状态不能为空"),
                    validators.AnyOf(['启用', '禁用', '过期'])]
    )
    schedule_brief = StringField(
        "日程简述",
        validators=[DataRequired(message="日程状态不能为空"),
                    Length(1, 1000, message="日程简述长度为1-1000")]
    )
    schedule_detail = StringField(
        "日程详细描述",
        validators=[DataRequired(message="日程详细描述不能为空"),
                    Length(1, 2000, message="日程详细描述长度为1-2000")]
    )
    time_type = StringField(
        "日程时间精度",
        validators=[DataRequired(message="日程时间精度不能为空"),
                    validators.AnyOf(['Day', 'Minute'])]
    )
    start_time = DateField(
        "开始时间",
        validators=[DataRequired(message="开始时间不能为空")]
    )
    end_time = DateField(
        "结束时间",
        validators=[DataRequired(message="结束时间不能为空")]
    )
    if_remind_message = BooleanField(
        "是否提醒",
        validators=[DataRequired(message="请确认是否提醒")]
    )
    schedule_type = StringField(
        "日程类型",
        validators=[DataRequired(message="日程类型不能为空"),
                    validators.AnyOf(['SINGLE', 'CYCLE', 'EVERY_DAY', 'EVERY_WEEK', "EVERY_MONTH", "EVERY_YEAR",
                                      "AT_SPECIFIC_WEEKDAY", 'AT_SPECIFIC_MONTHDAY'])]
    )


class ModifyScheduleForm(FlaskForm):  # 修改日程
    schedule_id = IntegerField(
        "日程编号",
        validators=[DataRequired(message="日程编号不能为空")]
    )
    schedule_status = StringField(
        "日程状态",
        validators=[DataRequired(message="日程状态不能为空"),
                    validators.AnyOf(['启用', '禁用', '过期'])]
    )
    schedule_detail = StringField(
        "日程详细描述",
        validators=[DataRequired(message="日程详细描述不能为空"),
                    Length(1, 2000, message="日程详细描述长度为1-2000")]
    )
    start_time = DateField(
        "开始时间",
        validators=[DataRequired(message="开始时间不能为空")]
    )
    end_time = DateField(
        "结束时间",
        validators=[DataRequired(message="结束时间不能为空")]
    )
    if_remind_message = BooleanField(
        "是否提醒",
        validators=[DataRequired(message="请确认是否提醒")]
    )
    schedule_type = StringField(
        "日程类型",
        validators=[DataRequired(message="日程类型不能为空"),
                    validators.AnyOf(['SINGLE', 'CYCLE', 'EVERY_DAY', 'EVERY_WEEK', "EVERY_MONTH", "EVERY_YEAR",
                                      "AT_SPECIFIC_WEEKDAY", 'AT_SPECIFIC_MONTHDAY'])]
    )


@scheduler.task('interval', id='send_remind_email', minutes=1)
def check_reminders():
    with app.app_context():
        china_tz = pytz.timezone('Asia/Shanghai')
        current_time = datetime.now(china_tz)
        reminders = Reminder.query.filter(Reminder.reminder_time <= current_time).all()
        for reminder in reminders:
            send_result = send_reminder.apply_async(args=[reminder.schedule_id])
            if send_result.result is not None:
                # 任务失败，处理结果或记录错误
                print(f"发送提醒失败: {send_result.result}")
            else:
                # 任务成功，从数据库中删除提醒
                db.session.delete(reminder)
                db.session.commit()


def send_reminder_email(user, schedule):
    with app.app_context():
        # 构造邮件消息
        subject = f'提醒：{schedule.schedule_brief}日程即将开始'
        body = f'亲爱的 {user.user_name}，您的日程即将在 {schedule.start_time} 开始。请注意安排您的时间。'
        recipients = [user.email]

        # 创建邮件对象
        message = Message(subject=subject, body=body, recipients=recipients, sender=app.config["MAIL_USERNAME"], )

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
    with app.app_context():
        schedule = Schedule.query.filter_by(schedule_id=schedule_id).first()
        user = schedule.user
        result = send_reminder_email(user, schedule)
        if result:
            return True
        else:
            return False


@app.route("/", methods=["GET"])
def beginpage():
    return render_template("beginpage.html")


@app.route('/csrf_token', methods=['GET'])
def csrf_token():
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

            result = basic_login(user_email, password, login_message)
            if result:
                user = User.query.filter_by(email=user_email).first()
                login_result = login_user(user)
                session[current_user.email] = False
            return login_message, 200  # 可能成功也可能不成功, 主要看success
        errors = dict()
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息
        return jsonify(errors), 400  # 数据本身不符合格式, 比如邮箱格式错误

    return render_template("login.html")  # 渲染页面


@app.route("/verify_login", methods=["GET", "POST"])
def verify_login():
    if request.method == "POST":
        data = request.form
        form = LoginFormCAPTCHA(data=data)
        if form.validate():
            user_email = form.email.data
            verification_code = form.verification_code.data
            verification_code_error = {}
            cached_verification_code = memcache_client.get(user_email)

            user = User.query.filter_by(email=user_email).first()
            if user is None:
                return jsonify({"success": False, "message": "The user does not exist."})  # 用户不存在

            check_verification_code(verification_code_error, cached_verification_code, verification_code)
            if verification_code_error:
                return jsonify(verification_code_error), 400

            login_user(user)
            return jsonify({"success": True, "message": "Login success"}), 200  # 登录成功

        errors = dict()
        for field, messages in form.errors.items():
            errors[field] = messages[0]  # 使用第一个错误消息
        return jsonify(errors), 400  # 数据不符合要求
    return render_template("verify_login.html")


@app.route("/send_code", methods=["POST"])
def send_verification_code():
    data = request.get_json()
    email = data.get('email')
    print(email)
    message = {}
    # 验证邮箱是否有效
    if not validate_email(email=email, check_mx=True, verify=True) or not email:
        return jsonify({'success': False, 'message': "请输入有效的邮箱地址，比如：email@domain.com"}), 400
    result = basic_send_verification_code(email=email, message=message)
    if result:
        return jsonify(message), 200
    return jsonify(message), 400


@app.route("/signup", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        form = RegisterForm(data=data)
        if form.validate():
            user_email = form.email.data
            password = form.password.data
            verification_code = form.verification_code.data
            user_name = form.user_name.data
            cached_verification_code = memcache_client.get(user_email)
            verification_code_error = dict()
            registration_message = dict()

            check_verification_code(verification_code_error, cached_verification_code, verification_code)
            if verification_code_error:
                return jsonify(verification_code_error), 200

            user = basic_register(user_email=user_email, password=password, registration_message=registration_message,
                                  user_name=user_name)
            if user:
                origin_notify = Notify(notify_name="默认提醒", if_repeat=False, default=True, interval=None, before=300,
                                       user_id=user.user_id, notify_sync=False)
                db.session.add(origin_notify)
                db.session.commit()
            return jsonify(registration_message)
    return render_template("signup.html")


@app.route("/logout", methods=["GET"])
@login_required  # 视图保护
def logout():
    logout_user()  # 登出用户
    return jsonify({"success": True, "message": "Log out successful"}), 200


@app.route("/main", methods=["GET"])
@login_required  # 视图保护
def main():
    return render_template("main.html")


@app.route("/change_email_send", methods=["POST"])
@login_required
def change_email_send():
    data = request.get_json()
    email = data.get('email')
    message = {}
    # 验证邮箱是否有效
    if not validate_email(email=email, check_mx=True, verify=True):
        return jsonify({'success': False, 'message': "请输入有效的邮箱地址，比如：email@domain.com"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': "Email already registered"}), 400
    result = basic_send_verification_code(message, email)
    if result:
        return jsonify(message), 200
    return jsonify(message), 400


@app.route("/settings", methods=["GET"])
@login_required
def settings():
    return render_template("settings.html")


@app.route("/get_username", methods=["GET"])
@login_required
def get_username():
    return jsonify({'success': True, 'current_username': current_user.user_name})


@app.route("/submit_username", methods=["POST"])
@login_required
def set_username():
    data = request.get_json()
    name = data.get('username')
    current_user.user_name = name
    db.session.commit()
    return jsonify({'success': True, 'current_username': current_user.user_name})


@app.route("/get_email", methods=["GET"])
@login_required
def get_email():
    return jsonify({'success': True, 'current_email': current_user.email})


@app.route("/get_prefer", methods=["GET"])
@login_required
def get_prefer():
    return jsonify({'success': True, 'current_prefer': current_user.user_preference})


@app.route("/submit_prefer", methods=["POST"])
@login_required
def submit_prefer():
    data = request.get_json()
    prefer = data.get('prefer')
    current_user.user_preference = prefer
    db.session.commit()
    return jsonify({'success': True, 'message': 'Preferences successfully modified'})


@app.route("/submit_email", methods=["POST"])
@login_required  # 视图保护
def change_email():
    data = request.get_json()
    message = dict()

    result = basic_change_email(data=data, message=message)
    if not result:
        return jsonify(message), 400
    return jsonify(message), 200


@app.route("/change_password_send", methods=["POST"])
@login_required  # 视图保护
def change_password_send():
    email = current_user.email
    message = dict()
    result = basic_send_verification_code(message=message, email=email)
    return jsonify(message)


@app.route("/submit_password", methods=["POST"])
@login_required  # 视图保护
def change_password():
    data = request.get_json()
    data['user_email'] = current_user.email
    message = dict()
    result = basic_change_password(data=data, message=message)
    if result:
        return jsonify(message), 200
    return jsonify(message), 400


@app.route("/signout", methods=["POST"])
@login_required  # 视图保护
def delete_account():
    email = current_user.email
    logout_user()
    delete_user = User.query.filter_by(email=email).first()
    db.session.delete(delete_user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Preferences successfully modified'})


@app.route("/schedule_addition", methods=["GET"])  # 渲染"提交至语言模型"页面
@login_required  # 视图保护
def submit_to_LLM():
    return render_template("schedule_addition.html")


@app.route("/schedule_modification", methods=["GET"])  # 渲染"提交至语言模型"页面
@login_required
def schedule_modification():
    return render_template("schedule_modification.html")


@app.route("/submit_datetext", methods=["POST"])  # 这个函数的真实作用相当于submit_to_LLM
@login_required  # 视图保护
def submit_datetext1():
    data = request.get_json()
    form = LLMForm(data=data)
    errors = dict()

    if form.validate():
        origin_input, preference = form.description.data, form.preference.data
        result_alpaca, alpaca_response, result_glm, glm_response = asyncio.run(
            run_tasks_wrapper(origin_input, preference))
        wrong_format, all_origin, all_schedule = 0, {'alpaca_origin': None, 'glm_origin': None}, {'alpaca_result': None,
                                                                                                  'glm_result': None}

        def process_result(model, attributes):
            nonlocal wrong_format, all_origin, all_schedule
            if not attributes:
                wrong_format += 1
            else:
                use_model_enum = LanguageModel.Chinese_Alpaca if model == 'alpaca' else LanguageModel.ChatGLM
                input_data = {"input_type": "TEXT",
                              "data": base64.b64encode(origin_input.encode('utf-8')).decode('utf-8'),
                              'now_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "original_text": origin_input,
                              "use_model": use_model_enum, "pretrainable": False}
                all_origin[f'{model}_origin'], all_schedule[f'{model}_result'] = input_data, create_schedule(attributes)

        if result_alpaca:
            process_result('alpaca', extract_data_from_alpaca(alpaca_response))
        if result_glm:
            process_result('glm', extract_data_from_glm(glm_response))

        response_data = {"success": False,
                         'message': "The model output does not comply with the standard format."} if wrong_format == 2 else {
            "success": True, 'message': "Success submit to Language Model"}

        if not result_alpaca and not result_glm:
            return jsonify({"success": False, 'message': "Failed To submit to Language Model",
                            'wrong message': "Language model service"
                                             "is not started."}), 200
        if wrong_format == 2 or (wrong_format == 1 and (not result_alpaca or not result_glm)):
            return jsonify(response_data), 200
        session["EXTRACT_RESPONSE"] = json.dumps(
            {"success": True, 'message': "Success submit to Language Model", "schedule": all_schedule,
             "all_origin": all_origin})
        return jsonify(response_data), 200

    for field, messages in form.errors.items():
        errors[field] = messages[0]  # 使用第一个错误消息
    return jsonify(errors), 400  # 数据本身不符合格式


def submit_datetext():
    data = request.get_json()
    form = LLMForm(data=data)
    if form.validate():
        origin_input = form.description.data
        preference = form.preference.data
        success, alpaca_response = send_data_to_alpaca(origin_input, preference)  # 向alpaca发送数据, success指示是否成功得到解析结果
        if success:
            alpaca_attributes = extract_data_from_alpaca(alpaca_response)  # 从response中提取日程属性
            if not alpaca_attributes:
                return jsonify(
                    {"success": False, 'message': "The model output does not comply with the standard format."}), 400

            alpaca_input = {"input_type": "TEXT", "data": "empty",
                            'now_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "original_text": origin_input, "use_model": 0, "pretrainable": False}

            all_origin = {'alpaca_origin': alpaca_input}
            alpaca_schedule = create_schedule(alpaca_attributes)
            all_schedule = {'alpaca_result': alpaca_schedule}

            session["EXTRACT_RESPONSE"] = json.dumps(
                {"success": True, 'message': "Success submit to Language Model", "schedule": all_schedule,
                 "all_origin": all_origin})

            return jsonify({"success": True, 'message': "Success submit to Language Model"}), 200
        else:
            return jsonify(
                {"success": False, 'message': "Failed To submit to Language Model",
                 'wrong message': alpaca_response}), 200
    errors = dict()
    for field, messages in form.errors.items():
        errors[field] = messages[0]  # 使用第一个错误消息
    return jsonify(errors), 400  # 数据本身不符合格式


@app.route("/add_schedule", methods=["POST"])
@login_required
def add_schedule():
    data = request.get_json()
    message = dict()

    data['date_num'] = process_string(data.get("date_list"))
    errors = check_data_validity(data=data)
    if errors:
        return jsonify(errors), 400

    input_key = ['now_time', 'original_text', 'use_model']
    input_values = [data.get(key) for key in input_key]
    now_time, original_text, use_model = input_values
    alpaca_input = InputData(input_type="TEXT", data="empty", now_time=now_time,
                             original_text=original_text,
                             use_model=LanguageModel.Chinese_Alpaca, pretrainable=False)
    db.session.add(alpaca_input)
    db.session.commit()

    new_schedule = basic_add_a_schedule(data=data, message=message, user_id=current_user.user_id, schedule_sync=False)
    if not new_schedule:
        return jsonify(message), 200
    # sync部分
    notify = new_schedule.notice
    if new_schedule.schedule_status == ScheduleState.ENABLED and new_schedule.if_remind_message:
        generate_remind_times(new_schedule)
    return jsonify(
        {"success": True, "message": "Successful add a schedule.", "schedule_id": new_schedule.schedule_id}), 200


@app.route("/schedule_management", methods=["GET"])
@login_required
def schedule_management():
    return render_template("schedule_management.html")


@app.route("/delete_schedule", methods=["POST"])
@login_required
def delete_schedule():
    data = request.get_json()
    delete_id = data.get('schedule_id')
    del_schedule: Optional[Schedule] = Schedule.query.filter_by(schedule_id=delete_id).first()
    if not del_schedule:
        return jsonify({"success": False, 'message': "No such schedule"})
    Reminder.query.filter_by(schedule_id=delete_id).delete(synchronize_session='fetch')
    db.session.delete(del_schedule)
    db.session.commit()
    return jsonify({"success": True, "message": "Successful delete a schedule.", "schedule_id": delete_id}), 200


@app.route("/submit_schedule", methods=["POST"])  # 不要被名字骗了, 这个函数的意思是修改日程
@login_required
def submit_schedule():
    data = request.get_json()
    print(data)
    data['data_num'] = process_string(data.get("date_list"))
    errors = check_data_validity(data=data)
    if errors:
        return jsonify(errors), 400

    schedule_id = data.get("schedule_id")
    message = dict()
    old_schedule = basic_modify_a_schedule(data=data, message=message)
    if not old_schedule:
        return jsonify(message), 200

    # sync部分
    Reminder.query.filter_by(schedule_id=schedule_id).delete()
    if old_schedule.if_remind_message:
        generate_remind_times(old_schedule)
        db.session.commit()
    return jsonify(
        {"success": True, "message": "Successful modify a schedule", "schedule_id": old_schedule.schedule_id}), 200


@app.route("/get_result", methods=["GET"])
def get_result():
    if session.get(current_user.email):
        session[current_user.email] = False
        return jsonify({'success': True})
    return jsonify({'success': False})


@app.route("/get_schedulejson", methods=["GET"])
@login_required
def get_schedule_json():
    print(session.get("EXTRACT_RESPONSE"))
    result = json.loads(session.get("EXTRACT_RESPONSE"))

    # 检查键是否存在
    if "EXTRACT_RESPONSE" in session:
        # 获取值后删除键
        session.pop("EXTRACT_RESPONSE")

        # 返回 JSON 响应
        if result is not None:
            return jsonify(result), 200
        else:
            return jsonify({"error": "No data found"}), 404
    else:
        return jsonify({"error": "Key not found in session"}), 404


@app.route("/get_schedule_list", methods=["GET"])
def get_schedule_list():
    schedule_list = current_user.schedule
    all_schedule = []
    for schedule in schedule_list:
        day_format = '%Y-%m-%d %H:%M:%S'
        schedule_data = {
            'schedule_id': schedule.schedule_id,
            'start_time': schedule.start_time.strftime(day_format),
            'end_time': schedule.end_time.strftime(day_format),
            'schedule_brief': schedule.schedule_brief,
            'time_type': schedule.time_type.value
        }
        # sync部分: 什么也不做
        all_schedule.append(schedule_data)
    return jsonify({"success": True, "schedule_amount": len(schedule_list), "all_schedule": all_schedule})


@app.route("/get_schedule", methods=["POST"])
def get_schedule():
    data = request.get_json()
    schedule_id = data.get("schedule_id")

    schedule: Optional[Schedule] = Schedule.query.filter_by(schedule_id=schedule_id).first()
    if not schedule:
        return jsonify({'success': False, 'message': "没有这个日程"})
    expiration_date_aware = pytz.timezone('Asia/Shanghai').localize(schedule.end_time)
    if datetime.now(
            pytz.timezone('Asia/Shanghai')) > expiration_date_aware and schedule.schedule_type == ScheduleType.SINGLE:
        schedule.schedule_status = ScheduleState.EXPIRED
        db.session.commit()
    day_format = '%Y-%m-%d %H:%M:%S'
    date_nums = [date.date_num for date in schedule.date]
    schedule_data = {
        'schedule_id': schedule.schedule_id,
        'schedule_status': schedule.schedule_status.value,
        'schedule_brief': schedule.schedule_brief,
        'schedule_detail': schedule.schedule_detail,
        'time_type': schedule.time_type.value,
        'start_time': schedule.start_time.strftime(day_format),
        'end_time': schedule.end_time.strftime(day_format),
        'if_remind_message': schedule.if_remind_message,
        'schedule_type': schedule.schedule_type.value,
        'notify_id': schedule.notify_id,
        'input_id': schedule.original_data_id,
        'date': date_nums
    }
    return jsonify({'success': True, 'schedule': schedule_data})


@app.route("/switch_notify_repeat", methods=["POST"])
def switch_notify_repeat():
    data = request.get_json()
    notify_id = data.get("notify_id")
    repeat: Optional[bool] = data.get("repeat")
    notify: Optional[Notify] = Notify.query.filter_by(notify_id=notify_id).first()
    if not notify:
        return jsonify({"success": False, "message": "No such a notify"})
    notify.if_repeat = repeat
    db.session.commit()
    return jsonify(
        {"success": True, "message": "Successful modify a notify"}), 200


@app.route("/get_notify_list", methods=["GET"])
@login_required
def get_notify_list():
    notify_list = current_user.notice_setting
    all_notify = []
    for notify in notify_list:
        notify_data = {
            'notify_id': notify.notify_id,
            'notify_name': notify.notify_name
        }
        # sync部分: 什么也不做
        all_notify.append(notify_data)
    return jsonify({"success": True, "notify_amount": len(notify_list), "all_notify": all_notify})


@app.route("/get_notify", methods=["POST"])
@login_required
def get_notify():
    data = request.get_json()
    notify_id = data.get('notify_id')
    notify: Optional[Notify] = Notify.query.filter_by(notify_id=notify_id).first()
    if not notify:
        return jsonify({"success": False, "message": "No such a notify"})
    notify_data = {
        'notify_id': notify.notify_id,
        'notify_name': notify.notify_name,
        'if_repeat': notify.if_repeat,
        'default_notify': notify.default_notify,
        'repeat_interval': notify.repeat_interval,
        'before_time': notify.before_time,
    }
    return jsonify({"success": True, 'notify': notify_data})


@app.route("/delete_notify", methods=["POST"])
@login_required
def delete_a_notify():
    data = request.get_json()
    notify_id = data.get('notify_id')
    delete_notify: Optional[Notify] = Notify.query.filter_by(notify_id=notify_id).first()
    if not delete_notify:
        return jsonify({"success": False, "message": "No such a notify"})

    related_schedules = delete_notify.schedule
    # sync部分
    Reminder.query.filter(
        Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).delete(
        synchronize_session='fetch')
    Schedule.query.filter(
        Schedule.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).update(
        {"if_remind_message": False, "schedule_sync": False}, synchronize_session='fetch')
    db.session.delete(delete_notify)
    db.session.commit()
    return jsonify({"success": True, "message": "Successfully deleted the notify referenced by notify_id.",
                    "notify_id": notify_id})


@app.route("/add_notify", methods=["POST"])
def add_notify():
    data = request.get_json()
    message = dict()

    new_notify = basic_add_a_notify(data=data, message=message, user_id=current_user.user_id, notify_sync=False)
    if not new_notify:
        return jsonify(message), 400

    return jsonify({"success": True, "message": "Successful add a notify", "notify_id": new_notify.notify_id}), 200


@app.route("/update_notify", methods=["POST"])
def submit_a_notify():
    data = request.get_json()
    message = dict()
    old_notify = basic_modify_a_notify(data=data, message=message, notify_sync=False)
    if not old_notify:
        return jsonify(message), 400

    related_schedules = old_notify.schedule
    # sync部分: 从 Reminder 表中删除所有 schedule_id 在 related_schedules 中的记录, 并根据schedule_if_remind判断是否应该加入邮件提醒
    old_notify.notify_sync = False
    Reminder.query.filter(
        Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).delete(
        synchronize_session='fetch')
    [generate_remind_times(schedule) for schedule in related_schedules if
     schedule.if_remind and schedule.schedule_status == ScheduleState.ENABLED]
    return jsonify(
        {"success": True, "message": "Successful modify a notify", "notify_id": old_notify.notify_id}), 200


@app.route("/schedule_addiction_by_share", methods=["GET"])
def schedule_addiction_by_share():
    return render_template("schedule_addiction_by_share.html")


@app.route("/get_share_code", methods=["POST"])
def get_share_code():
    data = request.get_json()
    schedule_id = int(data.get("schedule_id"))
    expire_time: Optional[str] = (data.get("expire_time"))
    share_cascade = data.get("share_cascade")
    schedule = Schedule.query.filter_by(schedule_id=schedule_id).first()
    if not schedule:
        return jsonify({"success": False, "message": " No such a schedule", "share_code": None}), 200
    if schedule.schedule_status == ScheduleState.EXPIRED:
        return jsonify({"success": False, "message": " schedule is overdue", "share_code": None}), 200
    old_share = Share.query.filter_by(schedule_id=schedule_id).filter(
        pytz.timezone('Asia/Shanghai').localize(Share.expiration_date) > datetime.now(
            pytz.timezone('Asia/Shanghai'))).first()
    if old_share:
        return jsonify({"success": False,
                        "message": "The sharing code has not expired yet.", "share_code": old_share.share_code}), 200
    new_share = Share(schedule_id=schedule_id, expiration_date=expire_time, share_cascade=share_cascade)
    db.session.add(new_share)
    db.session.commit()
    return jsonify({"success": True,
                    "message": "share schedule successful", "share_code": new_share.share_code}), 200


@app.route("/get_schedule_by_share", methods=["POST"])
def get_schedule_by_share():
    data = request.get_json()
    share_code: Optional[str] = data.get("share_code")
    shared_schedule = Share.query.filter_by(share_code=share_code).first()
    if not shared_schedule:
        return jsonify(
            {"success": False, "message": " The shared schedule corresponding to this code does not exist."}), 200
    expiration_date_aware = pytz.timezone('Asia/Shanghai').localize(shared_schedule.expiration_date)
    if datetime.now(pytz.timezone('Asia/Shanghai')) > expiration_date_aware:
        return jsonify({"success": False, "message": "The share code has expired"}), 200
    original_schedule = shared_schedule.schedule
    schedule_data = {
        'share_cascade': shared_schedule.share_cascade,
        'schedule_id': original_schedule.schedule_id
    }
    return jsonify({"success": True, "message": "Successfully retrieved information for the shared schedule!",
                    'schedule_data': schedule_data}), 200


@app.route("/add_schedule_by_share", methods=["POST"])
def add_schedule_by_share():
    data = request.get_json()
    share_cascade: Optional[bool] = data.get('cascade')  # 是否复制原始数据
    original_schedule_id: Optional[int] = data.get('orischedule_id')
    original_schedule: Optional[Schedule] = Schedule.query.filter_by(schedule_id=original_schedule_id).first()
    if not original_schedule:
        return jsonify(
            {"success": False, "message": "No such a schedule.", "schedule_id": None}), 200

    data['input_id'] = original_schedule.original_data_id
    message = dict()

    if not share_cascade:
        old_input = InputData.query.filter_by(input_id=data.get('input_id'))
        share_input: Optional[InputData] = copy.copy(old_input)
        share_input.input_id = None
        share_input.pretrainable = False
        db.session.add(share_input)
        db.session.commit()
        data['input_id'] = share_input.input_id

    data['date_num'] = process_string(data.get('data_list'))
    error = check_data_validity(data=data)
    if error:
        return jsonify(error), 400
    new_schedule = basic_add_a_schedule(data=data, message=message, user_id=current_user.user_id, schedule_sync=False)
    if not new_schedule:
        return jsonify(message), 400
    # sync部分
    notify = new_schedule.notice
    if (new_schedule.schedule_status == ScheduleState.ENABLED and new_schedule.if_remind_message
            and not notify.notify_sync):
        generate_remind_times(new_schedule)
    return jsonify(
        {"success": True, "message": "Successful add a schedule.", "schedule_id": new_schedule.schedule_id}), 200


def basic_change_email(data: Dict, message: Dict):
    data_keys = ['verification_code', 'email']
    values = [data.get(key) for key in data_keys]
    print(values)
    # 确保所有变量都有值
    if any(v is None for v in values):
        message["success"] = False
        message["message"] = "Missing required data"
        return False
    (verification_code, email) = values

    cached_verification_code = memcache_client.get(email)
    print(cached_verification_code)
    check_verification_code(verification_code_error=message,
                            cached_verification_code=cached_verification_code, verification_code=verification_code)
    memcache_client.delete(email)
    if message:
        return False
    change_user: Optional[User] = User.query.filter_by(email=email).first()
    if not User.query.filter_by(email=email).first():
        message["success"] = False
        message["message"] = "Email already registered"
        return False
    change_user.email = email
    message["success"] = True
    message["message"] = "Email already registered"
    return False


def basic_change_password(data: Dict, message: Dict):
    data_keys = ['user_email', 'verification_code', 'new_password']
    values = [data.get(key) for key in data_keys]
    # 确保所有变量都有值
    if any(v is None for v in values):
        message["success"] = False
        message["message"] = "Missing required data"
        return False

    (user_email, verification_code, new_password) = values
    cached_verification_code = memcache_client.get(user_email)
    check_verification_code(verification_code_error=message,
                            cached_verification_code=cached_verification_code, verification_code=verification_code)
    memcache_client.delete(user_email)
    if message:
        return False

    change_user: Optional[User] = User.query.filter_by(email=user_email).first()

    change_user.set_password(new_password)
    db.session.commit()
    message['success'] = True
    message['message'] = "Email successfully changed."
    return True


def send_verification_email(email: str, verification_code: str):
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


def basic_register(user_email: str, password: str, registration_message: Dict, user_name: str):
    if User.query.filter_by(email=user_email).first():
        registration_message['success'] = False
        registration_message['message'] = "Email already registered"
        registration_message['user_id'] = ""
        return None

    user = User(email=user_email, name=user_name)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    memcache_client.delete(user_email)
    # 返回一个json
    registration_message['success'] = True
    registration_message['message'] = "register success"
    registration_message['user_id'] = user.user_id
    return user


def basic_login(user_email: str, password: str, login_message: Dict):
    user = User.query.filter_by(email=user_email).first()
    if user is not None and user.validate_password(password):
        login_message['success'] = True
        login_message['message'] = "Login success."
        login_message['user_id'] = user.user_id
        return True

    else:
        login_message['success'] = False
        login_message['message'] = "Email or Password Invalid."
        login_message['user_id'] = None
        return False


def validate_registration_manually(email: str, password: str, repeat_password: str):
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


def basic_send_verification_code(message: Dict, email: str):
    # 生成验证码
    verification_code = generate_random_code()

    # 保存验证码到 Memcache
    memcache_client.set(email, verification_code, time=120)  # 保存2分钟，可以根据需求修改

    # 发送验证码邮件
    if send_verification_email(email, verification_code):
        message['success'] = True
        message['message'] = 'Verification code sent successfully'
        return True

    else:
        message['success'] = False
        message['message'] = 'Failed to send verification code'
        return False


def check_verification_code(verification_code_error: Dict, cached_verification_code: str, verification_code: str):
    if cached_verification_code is None:
        verification_code_error['success'] = False
        verification_code_error['message'] = 'Not send verification code yet'

    if cached_verification_code != verification_code:
        print(cached_verification_code, verification_code)
        verification_code_error['success'] = False
        verification_code_error['message'] = 'Wrong verification code'
    return verification_code_error


async def send_data_to_alpaca(input_data: str, user_preference: str):
    flag_file_path = os.path.join(CHECK_PATH, "flag_llama")
    print("alpaca")
    if not os.path.exists(flag_file_path):
        return False, {"error": "llama model service is not started."}
    # 获取当前时间
    cst = pytz.timezone('Asia/Shanghai')
    current_time = datetime.now(cst)

    # 将当前时间格式化为字符串
    current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
    prompt = ("提取日程信息中的时间、概要、事件细节、周期. 输出格式为“time_type:[时间精度（天/分）]^start_time:[起始时间]^end_time:[结束时间]^schedule_brief:["
              "事件概要]^schedule_detail:[事件细节]^schedule_type:[是否重复]（单次/重复）. ")
    formatted_content = f"{prompt}日程信息:{input_data};用户偏好:{user_preference};当前时间:{current_time_str}"

    request_data = {
        "messages": [
            {"role": "user",
             "content": formatted_content
             }

        ],
        "repetition_penalty": 1.0
    }
    headers = {"Content-Type": "application/json"}
    print("prepare to send alpaca")
    async with aiohttp.ClientSession() as async_session:
        async with async_session.post(Alpaca_API_URL, json=request_data, headers=headers) as response:
            if response.status == 200:
                print("alpaca return successfully")
                return True, await response.json()
            else:
                return False, {"error": f"Alpaca请求失败，状态码: {response.status}"}


async def send_data_to_glm(input_data: str, user_preference: str):
    flag_file_path = os.path.join(CHECK_PATH, "flag_glm3")
    if not os.path.exists(flag_file_path):
        return False, {"error": "ChatGLM3 model service is not started."}

    # 获取当前时间
    cst = pytz.timezone('Asia/Shanghai')
    current_time = datetime.now(cst)

    # 将当前时间格式化为字符串
    current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
    prompt = ("提取日程信息中的时间、概要、事件细节、周期. 输出格式为“time_type:[时间精度（天/分）]^start_time:[起始时间]^end_time:[结束时间]^schedule_brief:["
              "事件概要]^schedule_detail:[事件细节]^schedule_type:[是否重复]（单次/重复）. "
              "time_type有以下映射规则：0对应精确到天，1对应精确到分钟；对于schedule_type:0对应单次日程，1对应重复日程。")
    formatted_content = f"{prompt}日程信息:{input_data};用户偏好:{user_preference};当前时间:{current_time_str}"
    request_data = {
        "model": "chatglm3-6b",
        "messages": [
            {
                "role": "user",
                "content": formatted_content
            }
        ],
        "repetition_penalty": 1.0,
        "temperature": 0.8,
        "top_p": 0.9,
        "max_tokens": 150
    }
    url = GLM_API_URL
    headers = {"Content-Type": "application/json"}
    print("Prepare to send glm")
    async with aiohttp.ClientSession() as async_session:
        async with async_session.post(url, json=request_data, headers=headers) as response:
            if response.status == 200:
                print("glm return successfully")
                return True, await response.json()
            else:
                return False, {"error": f"GLM请求失败，状态码: {response.status}"}


def extract_data_from_alpaca(response_data: Dict):
    try:
        # 校验JSON返回体是否包含必要的字段
        required_keys = ["choices"]
        for key in required_keys:
            if key not in response_data:
                raise ValueError(f"Missing required key: {key}")

        choices = response_data["choices"]

        if not isinstance(choices, list) or len(choices) < 2:
            raise ValueError("Choices should be a list with at one elements")

        answer_content = choices[1].get("message", {}).get("content", "")

        # 检查 content 是否包含 "^"分隔符。
        if "^" not in answer_content or ":" not in answer_content:
            raise ValueError("Invalid content format")

        parts = answer_content.split('^')

        # 创建一个dic来存储各个属性的内容
        attributes = {}

        # 遍历分割后的部分并提取属性内容
        for part in parts:
            # 使用 ':' 分割每个部分
            key_value = part.split(':', 1)

            # 如果成功分割成两部分，将内容添加到字典中
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip()
                attributes[key] = value

        attributes['time_type'] = 1 if attributes.get('time_type', '') == '分' else 0
        attributes['schedule_type'] = 0 if attributes.get('schedule_type', '') == "单次" else 1

        start_value = attributes.get('start_time', datetime.now(pytz.timezone('Asia/Shanghai')).strftime(
            "%04Y-%02m-%02d %20H:%02M:%02S")) or datetime.now(pytz.timezone('Asia/Shanghai')).strftime("%04Y-%02m"
                                                                                                       "-%02d "
                                                                                                       "%20H:%02M:%02S")
        end_value = attributes.get('end_time', start_value) or start_value
        attributes['start_time'] = parse_datetime(start_value)
        attributes['end_time'] = parse_datetime(end_value)
        return attributes

    except (KeyError, IndexError, ValueError) as e:
        # 如果键不存在、索引越界或者格式不符合预期，返回 None
        print(f"Error extracting data: {e}")
        return None


def extract_data_from_glm(response_data: Dict):
    try:
        # 校验JSON返回体是否包含必要的字段
        required_keys = ["choices"]
        for key in required_keys:
            if key not in response_data:
                raise ValueError(f"Missing required key: {key}")

        choices = response_data["choices"]

        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError("Choices should be a list with at least two elements")

        answer_content = choices[0].get("message", {}).get("content", "")

        # 检查 content 是否包含 "^" 分隔符。
        if "^" not in answer_content or ":" not in answer_content:
            raise ValueError("Invalid content format")

        parts = answer_content.split('^')
        attributes = {}

        # 遍历分割后的部分并提取属性内容
        for part in parts:
            # 使用 ':' 分割每个部分
            key_value = part.split(':', 1)
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip()
                attributes[key] = value

        attributes['time_type'] = int(attributes.get('time_type', ''))
        attributes['schedule_type'] = int(attributes.get('schedule_type', ''))

        start_value = attributes.get('start_time', datetime.now(pytz.timezone('Asia/Shanghai')).strftime(
            "%04Y-%02m-%02d %20H:%02M:%02S")) or datetime.now(pytz.timezone('Asia/Shanghai')).strftime("%04Y-%02m"
                                                                                                       "-%02d "
                                                                                                       "%20H:%02M:%02S")
        end_value = attributes.get('end_time', start_value) or start_value
        attributes['start_time'] = parse_datetime(start_value)
        attributes['end_time'] = parse_datetime(end_value)
        return attributes

    except (KeyError, IndexError, ValueError) as e:
        # 如果键不存在、索引越界或者格式不符合预期，返回 None
        print(f"Error extracting data: {e}")
        return None


def create_schedule(schedule_attributes: Dict):
    schedule = {
        'time_type': schedule_attributes['time_type'],
        'start_time': schedule_attributes['start_time'],
        'end_time': schedule_attributes['end_time'],
        'schedule_brief': schedule_attributes['schedule_brief'],
        'schedule_detail': schedule_attributes['schedule_detail'],
        'schedule_type': schedule_attributes['schedule_type']
    }
    return schedule


def basic_add_a_notify(data: Dict, message: Dict, user_id: int, notify_sync: bool):
    data_keys = ['if_repeat', 'default_notify', 'repeat_interval', 'before_time', 'notify_name']

    # 使用列表推导式获取所有的值
    values = [data.get(key) for key in data_keys]

    # 确保所有变量都有值，否则进行适当的错误处理
    if any(v is None for v in values):
        message["success"] = False
        message["error"] = "Missing required data"
        return None
    (if_repeat, default_notify, repeat_interval, before_time, notify_name) = values
    try:
        new_notify = Notify(if_repeat=if_repeat, default=default_notify, interval=repeat_interval, before=before_time,
                            user_id=user_id, notify_sync=notify_sync, notify_name=notify_name)
        db.session.add(new_notify)
        db.session.commit()
    except ValueError as e:
        # 输入值无效或不符合预期
        db.session.rollback()
        message["success"] = False
        message["error"] = "ValueError: {}".format(str(e))
        return None

    except IntegrityError as e:
        # 违反了数据库表的唯一性约束、外键约束
        db.session.rollback()
        message["success"] = False
        message["error"] = "IntegrityError: {}".format(str(e))
        return None
    return new_notify


def basic_modify_a_notify(data: Dict, message: Dict, notify_sync: bool):
    notify_id = data.get('notify_id')
    old_notify: Optional[Notify] = Notify.query.filter_by(notify_id=notify_id).first()
    if not old_notify:
        message["success"] = False
        message["error"] = "No schedule referenced by this notify_id"
        return None

    data_keys = ['if_repeat', 'default_notify', 'repeat_interval', 'before_time', 'notify_name']
    values = [data.get(key) for key in data_keys]
    # 确保所有变量都有值
    if any(v is None for v in values):
        message["success"] = False
        message["error"] = "Missing required data"
        return None
    try:
        for key, value in zip(data_keys, values):
            setattr(old_notify, key, value)
        db.session.commit()
    except ValueError as e:
        # 输入值无效或不符合预期
        db.session.rollback()
        message["success"] = False
        message["error"] = "ValueError: {}".format(str(e))
        return None
    return old_notify


def basic_add_a_schedule(data: Dict, message: Dict, user_id: int, schedule_sync: bool):
    data_keys = ['schedule_status', 'schedule_brief', 'schedule_detail', 'time_type', 'start_time', 'end_time',
                 'schedule_type', 'input_id', 'if_remind_message', 'date_num', 'notify_id', ]
    enum_mapping = {
        'schedule_status': ScheduleState,
        'time_type': TimeType,
        'schedule_type': ScheduleType
    }
    values = [int(data.get(key, 0)) if key in enum_mapping else data.get(key) for key in data_keys]

    # 确保所有变量都有值，否则进行适当的错误处理
    if any(v is None for v in values[:-1]):
        message["success"] = False
        message["error"] = "Missing required data"
        return None

    (status, brief, detail, time_type, start, end, schedule_type, original_data_id,
     if_remind_message, date_list, notify_id,) = values

    try:
        new_schedule = Schedule(schedule_status=status, schedule_brief=brief, schedule_detail=detail,
                                time_type=time_type,
                                start_time=start, end_time=end, schedule_type=schedule_type, user_id=user_id,
                                notify_id=notify_id, original_data_id=original_data_id, if_remind=if_remind_message,
                                schedule_sync=schedule_sync)
        db.session.add(new_schedule)
        db.session.commit()

    except ValueError as e:
        # 输入值无效或不符合预期
        db.session.rollback()
        message["success"] = False
        message["error"] = "ValueError: {}".format(str(e))
        return None

    except IntegrityError as e:
        # 违反了数据库表的唯一性约束、外键约束
        db.session.rollback()
        message["success"] = False
        message["error"] = "IntegrityError: {}".format(str(e))
        return None

    for date in date_list:
        new_date = ScheduleDate(date_num=date, schedule_id=new_schedule.schedule_id)
        db.session.add(new_date)
        db.session.commit()
    return new_schedule


def basic_modify_a_schedule(data: Dict, message: Dict):
    schedule_id = data.get('schedule_id')
    old_schedule: Optional[Schedule] = Schedule.query.filter_by(schedule_id=schedule_id).first()
    date_list = data.get('date_num')

    if not old_schedule:
        message["success"] = False
        message["error"] = "No such a schedule."
        return None
    enum_mapping = {
        'schedule_status': ScheduleState,
        'time_type': TimeType,
        'schedule_type': ScheduleType
    }
    data_keys = ['schedule_status', 'schedule_brief', 'schedule_detail', 'time_type', 'start_time', 'end_time',
                 'schedule_type', 'input_id', 'if_remind_message', 'notify_id', ]
    values = [enum_mapping[key](int(data.get(key))) if key in enum_mapping else data.get(key) for key in data_keys]

    # 确保所有变量都有值，否则进行适当的错误处理
    if any(v is None for v in values[:-1]):
        message["success"] = False
        message["error"] = "Missing required data"
        return None

    for key, value in zip(data_keys, values):
        setattr(old_schedule, key, value)
    ScheduleDate.query.filter_by(schedule_id=old_schedule.schedule_id).delete()
    try:
        db.session.commit()

    except ValueError as e:
        message["success"] = False
        message["error"] = "ValueError: {}".format(str(e))
        return None

    except IntegrityError as e:
        # 违反了数据库表的唯一性约束、外键约束
        message["success"] = False
        message["error"] = "IntegrityError: {}".format(str(e))
        return None

    for date in date_list:
        new_date = ScheduleDate(date_num=date, schedule_id=schedule_id)
        db.session.add(new_date)
    db.session.commit()
    return old_schedule


def generate_remind_times(schedule: Schedule):  # 将所有提醒时间批量加入Reminder中
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


def calculate_reminder(occurrence: list, schedule: Schedule):
    notify = schedule.notice
    reminder_times = []
    if schedule.if_remind_message and schedule.schedule_status == ScheduleState.ENABLED:
        # 遍历每个发生时间
        for event_time in occurrence:
            # 计算提前多少时间发送提醒
            reminder_time = event_time - timedelta(seconds=notify.before_time)

            # 添加第一次提醒时间
            reminder_times.append((reminder_time, schedule.schedule_id))

    return reminder_times


def calculate_schedule_occurrences(schedule: Schedule):
    occurrences = []

    # 设置起始时间为日程开始时间
    current_time = schedule.start_time
    if schedule.if_remind_message and schedule.schedule_status == ScheduleState.ENABLED:
        occurrences.append(current_time)
        while current_time.year <= 2071:
            next_occurrence = calculate_next_occurrence_based_on_type(schedule, current_time)  # 计算下一次发生的时间
            if isinstance(next_occurrence, list):
                for occurrence in next_occurrence:
                    occurrences.append(occurrence)

                # 将数组中的最后一个值设为 current_time
                current_time = next_occurrence[-1]

            else:
                occurrences.append(next_occurrence)
                current_time = next_occurrence
    filtered_occurrences = [dt for dt in occurrences if dt >= datetime.now()]
    return filtered_occurrences


def calculate_next_occurrence_based_on_type(schedule: Schedule, current_time: datetime):
    # 映射不同的日程类型到相应的计算方法
    type_mapping = {
        'SINGLE': calculate_single_occurrence,
        'CYCLE': calculate_cycle_occurrence,
        'EVERY_DAY': calculate_every_day_occurrence,
        'EVERY_WEEK': calculate_every_week_occurrence,
        'EVERY_MONTH': calculate_every_month_occurrence,
        'EVERY_YEAR': calculate_every_year_occurrence,
        'AT_SPECIFIC_WEEKDAY': calculate_specific_weekday_occurrence,
        'AT_SPECIFIC_MONTHDAY': calculate_specific_monthday_occurrence,
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


def calculate_specific_weekday_occurrence(schedule, current_time):
    date_nums = [date.date_num for date in schedule.date]
    result_list = []
    for date_num in date_nums:
        result = single_calculate_specific_weekday(current_time, date_num)
        result_list.append(result)
        current_time = result
    return result_list


def single_calculate_specific_weekday(current_time: datetime, date_num: int):
    current_weekday = current_time.weekday()
    days_until_target_weekday = (date_num - current_weekday + 7) % 7
    next_occurrence = current_time + timedelta(days=days_until_target_weekday)
    return next_occurrence


def calculate_specific_monthday_occurrence(schedule: Schedule, current_time):
    date_nums = [date.date_num for date in schedule.date]
    result_list = []
    for date_num in date_nums:
        result = single_calculate_specific_monthday(current_time, date_num)
        result_list.append(result)
        current_time = result
    return result_list


def single_calculate_specific_monthday(current_time: datetime, date_num: int):
    current_month_days = calendar.monthrange(current_time.year, current_time.month)[1]
    date_num += 1
    if date_num > current_month_days:
        date_num = current_month_days

        # 计算距离下一个特定日期的天数
    days_until_target_date = date_num - current_time.day
    # 如果日期已经过去，将其调整为下一个月
    if days_until_target_date <= 0:
        next_month = current_time.replace(day=1) + timedelta(days=32)
        days_until_target_date = date_num - next_month.day

    next_occurrence = current_time + timedelta(days=days_until_target_date)
    return next_occurrence


def check_format(input_string):
    pattern = r'^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$'
    if re.match(pattern, input_string):
        return True
    else:
        return False


def process_string(input_string: str):
    print(input_string)
    if not input_string:
        return []
    try:
        print(1)
        # 尝试将输入字符串转换为数字
        number_value = float(input_string)
        return [number_value]
    except ValueError:
        print(2)
        # 如果无法转换为数字，则假设是用分号分隔的多个数字
        split_values = input_string.split(';')
        # 将分割的子串转换为数字，并过滤掉无法转换的部分
        # number_values = sorted([int(value) for value in split_values if value.strip().isdigit()])
        number_values = sorted(
            list(set(float(value) for value in split_values if value.strip().isdigit())))
        print(3)
        return number_values


def parse_datetime(value: str, default=datetime.now().astimezone(pytz.timezone('Asia/Shanghai'))):
    formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).strftime("%02Y-%02m-%02d %02H:%02M:%02S")
        except ValueError:
            pass
    return default.strftime("%02Y-%02m-%02d %02H:%02M:%02S")


async def run_tasks_wrapper(origin_input: str, preference: str):
    result_alpaca, alpaca_response = await send_data_to_alpaca(origin_input, preference)
    result_glm, glm_response = await send_data_to_glm(origin_input, preference)
    if current_user and current_user.is_authenticated:
        session[current_user.email] = True
    return result_alpaca, alpaca_response, result_glm, glm_response


'''async def run_tasks(input_data, user_preference):
    alpaca_task = send_data_to_alpaca(input_data, user_preference)
    glm_task = send_data_to_glm(input_data, user_preference)

    # Gather all tasks
    results = await asyncio.gather(alpaca_task, glm_task)

    # Extract results
    result_alpaca, response_alpaca = results[0]
    result_glm, response_glm = results[1]

    # Further process results if needed

    return result_alpaca, response_alpaca, result_glm, response_glm
'''


def check_data_validity(data: Dict):
    errors = {}

    # Check schedule_status
    if int(data.get("schedule_status")) not in [0, 1, 2]:
        errors["schedule_status"] = "Invalid schedule status."

    # Check time_type
    if int(data.get("time_type")) not in [0, 1]:
        errors["time_type"] = "Invalid time_type."

    # Check schedule_type
    if int(data.get("schedule_type")) not in range(9):
        errors["schedule_type"] = "Invalid schedule_type."

    # Check input_id
    if data.get("input_id") is None:
        errors["input_id"] = "input_id must have a value."

    # Check notify_id based on if_remind_message
    if not data.get("if_remind_message") and data.get("notify_id") is not None:
        errors["notify_id"] = "If if_remind_message is False, notify_id must be empty."
    elif data.get("if_remind_message") and not isinstance(data.get("notify_id"), int):
        errors["notify_id"] = "Invalid notify settings. notify_id must be an integer."

    if not check_date_num_validity(schedule_type=int(data.get("schedule_type")), date_num=data.get('date_num')):
        errors["date_list"] = "date_num is not valid."
    return errors


def check_date_num_validity(schedule_type: int, date_num: list):
    def is_valid_month_day(month, day):
        if 1 <= month <= 12:
            if month in [1, 3, 5, 7, 8, 10, 12]:
                return 1 <= day <= 31
            elif month in [4, 6, 9, 11]:
                return 1 <= day <= 30
            else:  # month == 2 (February)
                return 1 <= day <= 29  # Assume leap year for simplicity
        return False

    if schedule_type == 0 and date_num:
        return False
    elif 5 >= schedule_type >= 1 != len(date_num):
        return False
    elif schedule_type == 6 and (len(date_num) > 7 or any(num not in range(7) for num in date_num)):
        return False
    elif schedule_type == 7 and (len(date_num) > 31 or any(num not in range(31) for num in date_num)):
        return False
    elif schedule_type == 8 and any(not is_valid_month_day(num // 100 + 1, num % 100 + 1) for num in date_num):
        return False

    return True
