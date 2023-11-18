from datetime import datetime

from smtplib import SMTPException

from sqlalchemy.exc import SQLAlchemyError
from validate_email import validate_email
from watchlist import app, db, memcache_client
from watchlist.models import User, Schedule, ScheduleDate, InputData, LanguageModel
from flask_login import login_user, login_required, logout_user, current_user
from flask import request, url_for, redirect, jsonify

from watchlist.views import basic_register, basic_send_verification_code, \
    check_verification_code, basic_login, send_data_to_alpaca, extract_data_from_alpaca, create_schedule


def validate_login_manually(email, password):
    errors = {}
    if not validate_email(email):
        errors['email'] = '请输入有效的邮箱地址，比如：email@domain.com'

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

    login_message = dict()

    basic_login(user_email=user_email, password=password, login_message=login_message)
    return login_message, 200


@app.route("/app_register", methods=["POST"])
def app_register():
    data = request.get_json()
    user_email = data.get('email')
    password = data.get('password')
    verification_code = data.get('verification_code')
    cached_verification_code = memcache_client.get(user_email)
    verification_code_error = {}
    registration_message = {}

    check_verification_code(verification_code_error, cached_verification_code, verification_code)
    if verification_code_error:
        return jsonify(verification_code_error), 400

    basic_register(user_email, password, registration_message)
    return registration_message, 200


@app.route("/app_send_verification_code", methods=["POST"])
def app_send_verification_code():
    data = request.get_json()
    email = data.get('email')
    message = {}
    if validate_email(email):
        basic_send_verification_code(message=message, email=email)
    return message


@app.route("/app_login_with_CAPTCHA", methods=["POST"])
def app_login_with_code():
    data = request.get_json()
    user_email = data.get('email')
    verification_code = data.get('verification_code')
    cached_verification_code = memcache_client.get(user_email)
    verification_code_error = {}

    user = User.query.filter_by(email=user_email).first()
    if user is None:
        return jsonify({"success": False, "message": "The user does not exist."})

    check_verification_code(verification_code_error, cached_verification_code, verification_code)
    if verification_code_error:
        return jsonify(verification_code_error), 400

    login_user(user_email)
    return jsonify({"success": True, "message": "Login success"}), 200


@app.route("/app_get_all_schedule", methods=["POST"])
def app_get_all_schedule():
    data = request.get_json()
    user_email = data.get('email')
    user = User.query.filter_by(email=user_email).first()

    if user is None:
        return jsonify({"success": False, "error": "The user does not exist."}), 400
    if not user.is_authenticated:
        return jsonify({"success": False, "error": "The current user is not logged in"}), 400

    schedules_list = user.schedule
    schedules_data = []
    for schedule in schedules_list:
        schedule_data = {
            'schedule_id': schedule.schedule_id,
            'schedule_status': schedule.schedule_status.value,
            'schedule_brief': schedule.schedule_brief,
            'schedule_detail': schedule.schedule_detail,
            'time_type': schedule.time_type.value,
            'start_time': schedule.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': schedule.end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'if_remind_message': schedule.if_remind_message,
            'schedule_type': schedule.schedule_type.value
        }
        schedules_data.append(schedule_data)
    return jsonify(schedules_data)


@app.route("/app_submit_to_LLM", methods=["POST"])
def app_submit_to_llm():
    data = request.get_json()
    input_type = data.get('input_type')
    base64_input = data.get('base64_input')
    origin_input = data.get('input_data')
    preference = data.get('user_preference')
    now_time = datetime.now()

    success, alpaca_response = send_data_to_alpaca(origin_input, preference)  # 向alpaca发送数据, success指示是否成功得到解析结果
    if success:
        alpaca_attributes = extract_data_from_alpaca(alpaca_response)  # 从response中提取日程属性
        if not alpaca_attributes:
            return jsonify(
                {"success": False, 'message': "The model output does not comply with the standard format."}), 200

        alpaca_input = InputData(input_type=input_type, data=base64_input, now_time=now_time,
                                 original_text=origin_input,
                                 use_model=LanguageModel.Chinese_Alpaca)
        db.session.add(alpaca_input)
        db.session.commit()  # 确认发送成功后再构建input_data

        all_origin_id = {'alpaca_origin': alpaca_input.input_id}
        alpaca_schedule = create_schedule(alpaca_attributes)
        all_schedule = {'alpaca_result': alpaca_schedule}
        return jsonify({"success": True, 'message': "Success submit to Language Model", "schedule": all_schedule,
                        "origin_id": all_origin_id}), 200
    else:
        return jsonify(
            {"success": True, 'message': "Failed To submit to Language Model", 'wrong message': alpaca_response}), 200


@app.route("/app_delete_one_schedule", methods=["POST"])
def app_delete_one_schedule():
    data = request.get_json()
    schedule_id = data.get('schedule_id')

    delete_schedule = Schedule.query.filter_by(schedule_id=schedule_id).first()
    if not delete_schedule:
        return jsonify({"success": False, "message": "No such a schedule."}), 400
    delete_id = delete_schedule.schedule_id
    db.session.delete(delete_schedule)
    db.session.commit()
    return jsonify({"success": True, "message": "Successful delete a schedule.", "schedule_id": delete_id}), 200


@app.route("/app_add_one_schedule", methods=["POST"])
def app_add_one_schedule():
    data = request.get_json()

    status = data.get('schedule_status')
    brief = data.get('schedule_brief')
    detail = data.get('schedule_detail')
    time_type = data.get('time_type')
    start = data.get('start_time')
    end = data.get('end_time')
    schedule_type = data.get('schedule_type')
    original_data_id = data.get('input_id')
    email = data.get('email')
    notify_id = data.get('notify_id')
    if_remind_message = data.get("if_remind_message")
    date_list = data.get('date_num')

    start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
    end_time = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    user = User.query.filter_by(email=email).first()
    user_id = user.user_id

    new_schedule = Schedule(schedule_status=status, schedule_brief=brief, schedule_detail=detail, time_type=time_type,
                            start_time=start_time, end_time=end_time, schedule_type=schedule_type, user_id=user_id,
                            notify_id=notify_id, input_id=original_data_id, if_remind=if_remind_message)
    db.session.add(new_schedule)
    db.session.commit()

    for date in date_list:
        new_datenum = ScheduleDate(date_num=date, schedule_id=new_schedule.schedule_id)
        db.session.add(new_datenum)
        db.session.commit()

    return jsonify(
        {"success": True, "message": "Successful add a schedule.", "schedule_id": new_schedule.schedule_id}), 200
