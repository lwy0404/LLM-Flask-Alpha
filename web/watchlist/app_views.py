import asyncio
import copy
from datetime import datetime, timedelta

from smtplib import SMTPException
from typing import Optional

import pytz
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, DataError
from sqlalchemy.orm.exc import FlushError
from validate_email import validate_email
from watchlist import app, db, memcache_client
from watchlist.models import User, Schedule, ScheduleDate, InputData, LanguageModel, Notify, Reminder, ScheduleState, \
    TimeType, Share, ScheduleType, PretrainedData
from flask_login import login_user, login_required, logout_user, current_user
from flask import request, jsonify

from watchlist.views import basic_register, basic_send_verification_code, \
    check_verification_code, basic_login, send_data_to_alpaca, extract_data_from_alpaca, create_schedule, \
    generate_remind_times, basic_add_a_schedule, basic_modify_a_schedule, basic_add_a_notify, basic_modify_a_notify, \
    basic_change_password, check_format, send_data_to_glm, extract_data_from_glm, run_tasks_wrapper


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

    result = basic_login(user_email, password, login_message)
    if result:
        user = User.query.filter_by(email=user_email).first()
        login_user(user)
    return login_message, 200  # 可能成功也可能不成功, 主要看success


@app.route("/app_register", methods=["POST"])
def app_register():
    data = request.get_json()
    user_email = data.get('email')
    password = data.get('password')
    verification_code = data.get('verification_code')
    user_name = data.get('user_name')
    cached_verification_code = memcache_client.get(user_email)
    verification_code_error = {}
    registration_message = {}

    check_verification_code(verification_code_error, cached_verification_code, verification_code)
    if verification_code_error:
        return jsonify(verification_code_error), 400

    new_user = basic_register(user_email=user_email, password=password, registration_message=registration_message,
                              user_name=user_name)
    return jsonify(registration_message), 200


@app.route("/app_send_verification_code", methods=["POST"])
def app_send_verification_code():
    data = request.get_json()
    email = data.get('email')
    message = {}
    if validate_email(email):
        result = basic_send_verification_code(message=message, email=email)
    else:
        return jsonify({"success": False, "message": "请输入有效的邮箱地址，比如：email@domain.com"}), 400
    if result:
        return jsonify(message), 200
    return jsonify(message), 400


@app.route("/app_login_with_CAPTCHA", methods=["POST"])
def app_login_with_code():
    data = request.get_json()
    user_email = data.get('email')
    verification_code = data.get('verification_code')
    cached_verification_code = memcache_client.get(user_email)
    verification_code_error = {}

    user = User.query.filter_by(email=user_email).first()
    if user is None:
        return jsonify({"success": False, "message": "The user does not exist."}), 400

    check_verification_code(verification_code_error, cached_verification_code, verification_code)
    if verification_code_error:
        return jsonify(verification_code_error), 400

    login_user(user_email)
    return jsonify({"success": True, "message": "Login success"}), 200


@app.route("/app_change_password", methods=["POST"])
def app_change_password():
    data = request.get_json()
    message = dict()

    result = basic_change_password(data=data, message=message)
    if not result:
        return jsonify(message), 400
    return jsonify(message), 200


# sync操作: 什么也不用做, 毕竟一个新建的notify哪里会有与之关联的schedule呢?
@app.route("/app_add_one_notify", methods=["POST"])
def app_add_one_notify():
    data = request.get_json()
    user_id = data.get('user_id')
    message = dict()

    new_notify = basic_add_a_notify(data=data, message=message, user_id=user_id,notify_sync=True)
    if not new_notify:
        return jsonify(message), 400

    return jsonify({"success": True, "message": "Successful add a notify", "notify_id": new_notify.notify_id}), 200


# sync操作: 将该user所有notify标记为True, 并从Reminder中删除 [schedule_id在related_schedule中且schedule_sync为true的记录]
#                                                       (即使用该notify的所有schedule中已被app同步的那些)
@app.route("/app_get_all_notify", methods=["POST"])
def app_get_all_notify():
    data = request.get_json()
    user_id = data.get('user_id')
    user = User.query.filter_by(user_id=user_id).first()
    if user is None:
        return jsonify({"success": False, "error": "The user does not exist."}), 400
    if not user.is_authenticated:
        return jsonify({"success": False, "error": "The current user is not logged in"}), 400

    notify_list = user.notice_setting

    db.session.commit()
    all_notify = []
    for notify in notify_list:
        print(notify)
        notify_data = {key: getattr(notify, key) for key in
                       ['notify_id', 'if_repeat', 'default_notify', 'repeat_interval', 'before_time', 'notify_name']}
        all_notify.append(notify_data)
        related_schedules = notify.schedule
        # sync部分: 从 Reminder 表中删除所有 schedule_id 在 related_schedules 中, 且schedule_sync=True的记录
        Notify.query.filter(Notify.notify_id.in_([notify.notify_id for notify in notify_list])).update(
            {"notify_sync": True},
            synchronize_session='fetch')
        Reminder.query.filter(
            Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules]),
            Schedule.schedule_sync is True  # 添加判断条件
        ).delete(synchronize_session='fetch')
    return jsonify({"success": True, "all_notify": all_notify})


# sync操作: 将该notify标记为True, 并从先Reminder中删除 [schedule_id在related_schedule的记录]
# 然后, 只有schedule.ENABLED(启用日程本身), schedule.schedule_sync=False(APP未同步), schedule.if_remind_message=True(需要提醒)
# 的情况下将该日程重新加入邮件提醒队列
@app.route("/app_modify_a_notify", methods=["POST"])
def app_modify_a_notify():
    data = request.get_json()
    message = dict()
    old_notify = basic_modify_a_notify(data=data, message=message, notify_sync=True)
    if not old_notify:
        return jsonify(message), 400

    related_schedules = old_notify.schedule
    # sync部分: 从 Reminder 表中删除所有 schedule_id 在 related_schedules 中的记录, 并根据schedule_sync判断是否应该加入邮件提醒
    old_notify.notify_sync = True
    Reminder.query.filter(
        Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).delete(
        synchronize_session='fetch')
    [generate_remind_times(schedule) for schedule in related_schedules if not schedule.schedule_sync]
    return jsonify(
        {"success": True, "message": "Successful modify a notify", "notify_id": old_notify.notify_id}), 200


# sync操作: 立即删除所有使用这个notify的schedule在Reminder中的记录(如果有), 并将if_remind_message设置为False(没有提醒设置就不能提醒)
@app.route("/app_delete_a_notify", methods=["POST"])
def app_delete_a_notify():
    data = request.get_json()
    notify_id = data.get('notify_id')
    delete_notify = Notify.query.filter_by(notify_id=notify_id).first()

    if not delete_notify:
        return jsonify(
            {"success": False, "message": "No schedule referenced by this notify_id", "notify_id": notify_id})

    related_schedules = delete_notify.schedule

    # sync部分
    Reminder.query.filter(Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).delete(
        synchronize_session='fetch')
    Schedule.query.filter(Schedule.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).update(
        {"if_remind_message": False, "schedule_sync": False}, synchronize_session='fetch')
    db.session.delete(delete_notify)
    db.session.commit()
    return jsonify({"success": True, "message": "Successfully deleted the notify referenced by notify_id.",
                    "notify_id": notify_id})


@app.route("/app_submit_to_LLM", methods=["POST"])
def app_submit_to_llm1():
    data = request.get_json()
    input_type, base64_input, origin_input, preference = (
        data.get(key) for key in ('input_type', 'base64_input', 'origin_input', 'user_preference')
    )
    preference = preference or '无'

    if any(value is None for value in [input_type, base64_input, origin_input, preference]):
        return jsonify({'error': 'Missing or invalid input'}), 400

    now_time = datetime.now()
    result_alpaca, alpaca_response, result_glm, glm_response = asyncio.run(run_tasks_wrapper(origin_input, preference))
    print("glm_result:",glm_response)
    wrong_format, all_origin_id, all_schedule = 0, {'alpaca_origin': None, 'glm_origin': None}, {'alpaca_result': None,
                                                                                                 'glm_result': None}

    def process_result(model, attributes):
        nonlocal wrong_format, all_origin_id, all_schedule

        if not attributes:
            wrong_format += 1
            all_origin_id[f'{model}_origin'] = None
            all_schedule[f'{model}_result'] = None
        else:
            use_model_enum = LanguageModel.Chinese_Alpaca if model == 'alpaca' else LanguageModel.ChatGLM
            input_data = InputData(input_type=input_type, data=base64_input, now_time=now_time,
                                   original_text=origin_input, use_model=use_model_enum, pretrainable=False)
            db.session.add(input_data)
            db.session.commit()

            all_origin_id[f'{model}_origin'] = input_data.input_id
            all_schedule[f'{model}_result'] = create_schedule(attributes)

    if result_alpaca:
        process_result('alpaca', extract_data_from_alpaca(alpaca_response))
    if result_glm:
        process_result('glm', extract_data_from_glm(glm_response))

    response_data = (
        {"success": False,
         'message': "The model output does not comply with the standard format."} if wrong_format == 2 or (
                wrong_format == 1 and (not result_alpaca or not result_glm))
        else {"success": True, 'message': "Success submit to Language Model", "schedule": all_schedule,
              "origin_id": all_origin_id}
    )

    if not result_alpaca and not result_glm:
        return jsonify(
            {"success": False, 'message': "Failed To submit to Language Model",
             ' message': "Language model service is not started."}), 200

    return jsonify(response_data), 400 if wrong_format == 2 else 200


def app_submit_to_llm():
    data = request.get_json()
    input_type, base64_input, origin_input, preference = (
        data.get(key) for key in ('input_type', 'base64_input', 'origin_input', 'user_preference')
    )
    preference = preference or '无'
    if any(value is None for value in [input_type, base64_input, origin_input, preference]):
        return jsonify({'error': 'Missing or invalid input'}), 400
    now_time = datetime.now()

    success, alpaca_response = send_data_to_alpaca(origin_input, preference)  # 向alpaca发送数据, success指示是否成功得到解析结果
    print(alpaca_response)
    if success:
        alpaca_attributes = extract_data_from_alpaca(alpaca_response)  # 从response中提取日程属性
        print(alpaca_attributes)

        if not alpaca_attributes:
            return jsonify(
                {"success": False, 'message': "The model output does not comply with the standard format."}), 400

        alpaca_input = InputData(input_type=input_type, data=base64_input, now_time=now_time,
                                 original_text=origin_input,
                                 use_model=LanguageModel.Chinese_Alpaca, pretrainable=False)
        db.session.add(alpaca_input)
        db.session.commit()  # 确认发送成功后再构建input_data

        all_origin_id = {'alpaca_origin': alpaca_input.input_id}
        alpaca_schedule = create_schedule(alpaca_attributes)
        all_schedule = {'alpaca_result': alpaca_schedule}
        return jsonify({"success": True, 'message': "Success submit to Language Model", "schedule": all_schedule,
                        "origin_id": all_origin_id}), 200

    else:
        return jsonify(
            {"success": False, 'message': "Failed To submit to Language Model", 'wrong message': alpaca_response}), 200


@app.route("/app_delete_a_input", methods=["POST"])
def app_delete_a_input():
    data = request.get_json()
    delete_array = data.get("input_array")
    for delete_id in delete_array:
        delete_input = InputData.query.filter_by(input_id=delete_id).first()

        if not delete_input:
            return jsonify({"success": False, "message": "No such a input data."}), 400

        related_schedule: Optional[Schedule] = delete_input.schedule
        if related_schedule:
            return jsonify({"success": False, "message": "The original input is not in a deprecated state."}), 400

        db.session.delete(delete_input)
        db.session.commit()
    return jsonify({"success": True, 'message': "Successfully deleted deprecated input data. "}), 200


# sync操作: 将该user的所有schedule_sync标记为True; 同时查看每个schedule对应的notify_sync, 为True则从立即从reminder中删除记录
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

    all_schedule = []
    for schedule in schedules_list:
        day_format = '%Y-%m-%d' if schedule.time_type == TimeType.Day else '%Y-%m-%d %H:%M:%S'
        expiration_date_aware = pytz.timezone('Asia/Shanghai').localize(schedule.end_time)
        if datetime.now(
                pytz.timezone(
                    'Asia/Shanghai')) > expiration_date_aware and schedule.schedule_type == ScheduleType.SINGLE:
            schedule.schedule_status = ScheduleState.EXPIRED
            db.session.commit()
        date_nums = [date.date_num for date in schedule.date]
        notify = schedule.notice
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
            'notify_id': notify.notify_id if notify else None,
            'notify_name': notify.notify_name if notify else None,
            'input_id': schedule.original_data_id,
            'date': date_nums

        }
        # sync部分: 当且仅当notify和schedule的sync都为True时, 删除 reminder 表中所有 old_schedule 的记录
        notify = schedule.notice
        if notify and schedule.if_remind_message and notify.notify_sync:
            Reminder.query.filter_by(schedule_id=schedule.schedule_id).delete(synchronize_session='fetch')
            db.session.commit()
        all_schedule.append(schedule_data)
    Schedule.query.filter(Schedule.schedule_id.in_([schedule.schedule_id for schedule in schedules_list])).update(
        {"schedule_sync": True}, synchronize_session='fetch')
    return jsonify(all_schedule)


# sync操作: 只需要从邮件提醒列表中删除该schedule的所有提醒记录就好, 轻松愉快
@app.route("/app_delete_one_schedule", methods=["POST"])
def app_delete_one_schedule():
    data = request.get_json()
    delete_id = data.get('schedule_id')

    delete_schedule = Schedule.query.filter_by(schedule_id=delete_id).first()
    if not delete_schedule:
        return jsonify({"success": False, "message": "No such a schedule."}), 400
    # sync部分
    Reminder.query.filter_by(schedule_id=delete_id).delete(synchronize_session='fetch')
    db.session.delete(delete_schedule)
    db.session.commit()
    return jsonify({"success": True, "message": "Successful delete a schedule.", "schedule_id": delete_id}), 200


# sync操作: 看看new_schedule使用的notify是否为True, 不是的话, 再根据schedule.ENABLED(启用日程本身),
#  schedule.if_remind_message=True(需要提醒)来判断是否需要添加到邮件提醒列表
@app.route("/app_add_one_schedule", methods=["POST"])
def app_add_one_schedule():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    message = dict()

    new_schedule = basic_add_a_schedule(data=data, message=message, user_id=user.user_id,schedule_sync=False)
    if not new_schedule:
        return jsonify(message), 400
    # sync部分
    notify = new_schedule.notice
    if (new_schedule.schedule_status == ScheduleState.ENABLED and new_schedule.if_remind_message
            and not notify.notify_sync):
        generate_remind_times(new_schedule)
    return jsonify(
        {"success": True, "message": "Successful add a schedule.", "schedule_id": new_schedule.schedule_id}), 200


# sync操作: 和app_add_one_schedule差不多, 唯一的区别是在判断要不要加之前先把Reminder里的记录删了
# (如果有, 因为很难判断date, start_end有没有被改过)
@app.route("/app_modify_one_schedule", methods=["POST"])
def app_modify_one_schedule():
    data = request.get_json()
    message = dict()
    schedule_id = data.get('schedule_id')

    old_schedule = basic_modify_a_schedule(data=data, message=message)
    if not old_schedule:
        return jsonify(message), 400

    # sync部分
    Reminder.query.filter_by(schedule_id=schedule_id).delete()
    notify = old_schedule.notice
    if (old_schedule.schedule_status == ScheduleState.ENABLED and old_schedule.if_remind_message
            and not notify.notify_sync):
        generate_remind_times(old_schedule)
    db.session.commit()
    return jsonify(
        {"success": True, "message": "Successful modify a schedule", "schedule_id": old_schedule.schedule_id}), 200


@app.route("/app_create_sharing_code", methods=["POST"])
def app_create_sharing_code():
    data = request.get_json()
    schedule_id = data.get("schedule_id")
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
        return jsonify({"success": True,
                        "message": "The sharing code has not expired yet.", "share_code": old_share.share_code}), 200
    new_share = Share(schedule_id=schedule_id,
                      expiration_date=datetime.now(pytz.timezone('Asia/Shanghai')) + timedelta(days=7),
                      share_cascade=share_cascade)
    db.session.add(new_share)
    db.session.commit()
    return jsonify({"success": True,
                    "message": "share schedule successful", "share_code": new_share.share_code}), 200


@app.route("/app_get_sharing_schedule", methods=["POST"])
def app_get_sharing_schedule():
    data = request.get_json()
    share_code = data.get("share_code")
    shared_schedule = Share.query.filter_by(share_code=share_code).first()
    if not shared_schedule:
        return jsonify(
            {"success": False, "message": " The shared schedule corresponding to this code does not exist."}), 200
    expiration_date_aware = pytz.timezone('Asia/Shanghai').localize(shared_schedule.expiration_date)
    if datetime.now(pytz.timezone('Asia/Shanghai')) > expiration_date_aware:
        return jsonify({"success": False, "message": "The share code has expired"}), 200
    original_schedule = shared_schedule.schedule
    day_format = '%Y-%m-%d' if original_schedule.time_type == TimeType.Day else '%Y-%m-%d %H:%M:%S'
    schedule_data = {
        'input_id': original_schedule.original_data_id,
        'share_cascade': shared_schedule.share_cascade,
        'schedule_status': original_schedule.schedule_status.value,
        'schedule_brief': original_schedule.schedule_brief,
        'schedule_detail': original_schedule.schedule_detail,
        'time_type': original_schedule.time_type.value,
        'start_time': original_schedule.start_time.strftime(day_format),
        'end_time': original_schedule.end_time.strftime(day_format),
        'if_remind_message': original_schedule.if_remind_message,
        'schedule_type': original_schedule.schedule_type.value,
        'date': [date.date_num for date in original_schedule.date]
    }
    return jsonify({"success": True, "message": "Successfully retrieved information for the shared schedule!",
                    'schedule_data': schedule_data}), 200


@app.route("/app_add_sharing_schedule", methods=["POST"])
def app_add_sharing_schedule():
    data = request.get_json()
    user_id = data.get('user_id')
    share_cascade = data.get('share_cascade')  # 能否复制原始数据
    if_cascade = data.get('if_cascade')  # 是否复制原始数据
    message = dict()

    if not share_cascade and if_cascade:
        return jsonify(
            {"success": False, "message": "The shared schedule does not allow joint copying.", "schedule_id": None})
    if share_cascade and if_cascade:
        old_input = InputData.query.filter_by(input_id=data.get('input_id'))
        share_input: Optional[InputData] = copy.copy(old_input)
        share_input.input_id = None
        share_input.pretrainable = False
        db.session.add(share_input)
        db.session.commit()
        data['input_id'] = share_input.input_id

    new_schedule = basic_add_a_schedule(data=data, message=message, user_id=user_id)
    if not new_schedule:
        return jsonify(message), 400
    # sync部分
    notify = new_schedule.notice
    if (new_schedule.schedule_status == ScheduleState.ENABLED and new_schedule.if_remind_message
            and not notify.notify_sync):
        generate_remind_times(new_schedule)
    return jsonify(
        {"success": True, "message": "Successful add a schedule.", "schedule_id": new_schedule.schedule_id}), 200


@app.route("/app_add_pretrained_data", methods=["POST"])
def app_add_pretrained_data():
    data = request.get_json()
    input_id = data.get('input_id')
    schedule_id = data.get('schedule_id')

    marked_input: Optional[InputData] = InputData.query.filter_by(input_id=input_id).first()
    if not marked_input.pretrainable:
        return jsonify(
            {"success": False, "message": "This input_data has already been labeled as training data."}), 200
    new_pretrained = PretrainedData(input_type=marked_input.input_type, data=marked_input.data,
                                    original_text=marked_input.original_text, now_time=marked_input.input_type,
                                    use_model=marked_input, schedule_id=schedule_id)
    db.session.add(new_pretrained)
    db.session.commit()
    return jsonify(
        {"success": True, "message": "Successfully added a piece of training data.get"}), 200
