from datetime import datetime

from smtplib import SMTPException

from sqlalchemy.exc import SQLAlchemyError, IntegrityError, DataError
from sqlalchemy.orm.exc import FlushError
from validate_email import validate_email
from watchlist import app, db, memcache_client
from watchlist.models import User, Schedule, ScheduleDate, InputData, LanguageModel, Notify, Reminder, ScheduleState
from flask_login import login_user, login_required, logout_user, current_user
from flask import request, jsonify

from watchlist.views import basic_register, basic_send_verification_code, \
    check_verification_code, basic_login, send_data_to_alpaca, extract_data_from_alpaca, create_schedule, \
    generate_remind_times


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

# sync操作: 什么也不用做, 毕竟一个新建的notify哪里会有与之关联的schedule呢?
@app.route("/app_add_one_notify", methods=["POST"])
def app_add_one_notify():
    data = request.get_json()
    data_keys = ['if_repeat', 'default_notify', 'repeat_interval', 'before_time', 'user_id']

    # 使用列表推导式获取所有的值
    values = [data.get(key) for key in data_keys]

    # 确保所有变量都有值，否则进行适当的错误处理
    if any(v is None for v in values):
        return jsonify({"success": False, "error": "Missing required data"}), 400
    (if_repeat, default_notify, repeat_interval, before_time, user_id) = values
    try:
        new_notify = Notify(if_repeat=if_repeat, default=default_notify, interval=repeat_interval, before=before_time,
                            user_id=user_id, notify_sync=True)
        db.session.add(new_notify)
        db.session.commit()
        return jsonify({"success": True, "message": "Successful add a notify", "notify_id": new_notify.notify_id}), 200
    except DataError as e:
        # 输入值无效或不符合预期
        db.session.rollback()
        return jsonify({"success": False, "error": "ValueError: {}".format(str(e))}), 400

    except IntegrityError as e:
        # 违反了数据库表的唯一性约束、外键约束
        db.session.rollback()
        return jsonify({"error": "IntegrityError: {}".format(str(e))}), 400

    except FlushError as e:
        # 违背业务规则约束
        db.session.rollback()
        return jsonify({"success": False, "error": "FlushError: {}".format(str(e))}), 400


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

    notify_list = user.notice_setting.all()
    [notify.update(notify_sync=True) for notify in notify_list]
    db.session.commit()
    all_notify = []
    for notify in notify_list:
        notify_data = {key: getattr(notify, key) for key in
                       ['notify_id', 'if_repeat', 'default_notify', 'repeat_interval', 'before_time']}
        all_notify.append(notify_data)
        related_schedules = notify.schedule
        # 从 Reminder 表中删除所有 schedule_id 在 related_schedules 中, 且schedule_sync=True的记录
        Reminder.query.filter(
            Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules]),
            Schedule.schedule_sync is True  # 添加判断条件
        ).delete(synchronize_session='fetch')
    return jsonify(all_notify)


# sync操作: 将该notify标记为True, 并从先Reminder中删除 [schedule_id在related_schedule的记录]
# 然后, 只有schedule.ENABLED(启用日程本身), schedule.schedule_sync=False(APP未同步), schedule.if_remind_message=True(需要提醒)
# 的情况下将该日程加入邮件提醒队列
@app.route("/app_modify_a_notify", methods=["POST"])
def app_modify_a_notify():
    data = request.get_json()
    notify_id = data.get('notify_id')
    old_notify = Notify.query.filter_by(notify_id=notify_id).first()
    related_schedules = old_notify.schedule.all()

    data_keys = ['if_repeat', 'default_notify', 'repeat_interval', 'before_time', 'user_id']
    values = [data.get(key) for key in data_keys]
    # 确保所有变量都有值
    if any(v is None for v in values):
        return jsonify({"success": False, "error": "Missing required data"}), 400

    try:
        for key, value in zip(data_keys, values):
            setattr(old_notify, key, value)
        db.session.commit()
    except ValueError as e:
        # 输入值无效或不符合预期
        db.session.rollback()
        return jsonify({"success": False, "error": "ValueError: {}".format(str(e))}), 400

    old_notify.notify_sync = True
    # 从 Reminder 表中删除所有 schedule_id 在 related_schedules 中的记录, 并根据schedule_sync判断是否应该加入邮件提醒
    Reminder.query.filter(
        Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).delete(
        synchronize_session='fetch')
    [generate_remind_times(schedule) for schedule in related_schedules if not schedule.schedule_sync]
    return jsonify(
        {"success": True, "message": "Successful modify a schedule", "notify_id": old_notify.notify_id}), 200


# sync操作: 立即删除所有使用这个notify的schedule在Reminder中的记录(如果有), 并将if_remind_message设置为False(没有提醒设置就不能提醒)
@app.route("/app_delete_a_notify", methods=["POST"])
def app_delete_a_notify():
    data = request.get_json()
    notify_id = data.get('notify_id')
    delete_notify = Notify.query.filter_by(notify_id=notify_id).first()

    if not delete_notify:
        return jsonify(
            {"success": False, "message": "No schedule referenced by this notify_id", "notify_id": notify_id})

    related_schedules = delete_notify.schedule.all()
    if any(schedule.schedule_sync is False for schedule in related_schedules):
        return jsonify({"success": False, "error": "Some schedules are not synced."}), 400

    # sync部分
    Reminder.query.filter(Reminder.schedule_id.in_([schedule.schedule_id for schedule in related_schedules])).delete(
        synchronize_session='fetch')
    [schedule.update(if_remind_message=False) for schedule in related_schedules]
    db.session.delete(delete_notify)
    db.session.commit()
    return jsonify({"success": True, "message": "Successfully deleted the notify referenced by notify_id.",
                    "notify_id": notify_id})


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

    schedules_list = user.schedule.all()
    [schedule.update(schedule_sync=True) for schedule in schedules_list]

    all_schedule = []
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
            'schedule_type': schedule.schedule_type.value,
            'notify_id': schedule.notify_id,
            'input_id': schedule.original_data_id

        }
        # 当且仅当notify和schedule的sync都为True时, 删除 reminder 表中所有 old_schedule 的记录
        notify = schedule.notice
        if schedule.if_remind_message and notify.notify_sync:
            Reminder.query.filter_by(schedule_id=schedule.schedule_id).delete(synchronize_session='fetch')
            db.session.commit()
        all_schedule.append(schedule_data)
    return jsonify(all_schedule)


# sync操作: 只需要从邮件提醒列表中删除该schedule的所有提醒记录就好, 轻松愉快
@app.route("/app_delete_one_schedule", methods=["POST"])
def app_delete_one_schedule():
    data = request.get_json()
    delete_id = data.get('schedule_id')

    delete_schedule = Schedule.query.filter_by(schedule_id=delete_id).first()
    if not delete_schedule:
        return jsonify({"success": False, "message": "No such a schedule."}), 400
    #                   sync部分
    Reminder.query.filter_by(schedule_id=delete_id).delete(synchronize_session='fetch')
    db.session.delete(delete_schedule)
    db.session.commit()
    return jsonify({"success": True, "message": "Successful delete a schedule.", "schedule_id": delete_id}), 200


# sync操作: 看看new_schedule使用的notify是否为True, 不是的话, 再根据schedule.ENABLED(启用日程本身),
#  schedule.if_remind_message=True(需要提醒)来判断是否需要添加到邮件提醒列表
@app.route("/app_add_one_schedule", methods=["POST"])
def app_add_one_schedule():
    data = request.get_json()

    data_keys = ['schedule_status', 'schedule_brief', 'schedule_detail', 'time_type', 'start_time', 'end_time',
                 'schedule_type', 'input_id', 'email', 'notify_id', 'if_remind_message', 'date_num']

    # 使用列表推导式获取所有的值
    values = [data.get(key) for key in data_keys]

    # 确保所有变量都有值，否则进行适当的错误处理
    if any(v is None for v in values[:-1]):
        return jsonify({"success": False, "error": "Missing required data"}), 400

    (status, brief, detail, time_type, start, end, schedule_type, original_data_id, email, notify_id,
     if_remind_message, date_list) = values
    start = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    user = User.query.filter_by(email=email).first()
    user_id = user.user_id
    try:
        new_schedule = Schedule(schedule_status=status, schedule_brief=brief, schedule_detail=detail,
                                time_type=time_type,
                                start_time=start, end_time=end, schedule_type=schedule_type, user_id=user_id,
                                notify_id=notify_id, input_id=original_data_id, if_remind=if_remind_message,
                                schedule_sync=True)
        db.session.add(new_schedule)
        db.session.commit()

    except ValueError as e:
        # 输入值无效或不符合预期
        db.session.rollback()
        return jsonify({"success": False, "error": "ValueError: {}".format(str(e))}), 400

    except IntegrityError as e:
        # 违反了数据库表的唯一性约束、外键约束
        db.session.rollback()
        return jsonify({"success": False, "error": "IntegrityError: {}".format(str(e))}), 400

    for date in date_list:
        new_date = ScheduleDate(date_num=date, schedule_id=new_schedule.schedule_id)
        db.session.add(new_date)
        db.session.commit()
    #sync部分
    notify = new_schedule.notice.first
    if new_schedule.schedule_status == ScheduleState.ENABLED and new_schedule.if_remind_message and not notify.notify_sync:
        generate_remind_times(new_schedule)
    return jsonify(
        {"success": True, "message": "Successful add a schedule.", "schedule_id": new_schedule.schedule_id}), 200

# sync操作: 和app_add_one_schedule差不多, 唯一的区别是在判断要不要加之前先把Reminder里的记录删了
# (如果有, 因为很难判断date, start_end有没有被改过)
@app.route("/app_modify_one_schedule", methods=["POST"])
def app_modify_one_schedule():
    data = request.get_json()

    schedule_id = data.get('schedule_id')
    old_schedule = Schedule.query.filter_by(schedule_id=schedule_id).first()
    date_list = data.get('date_num')

    data_keys = ['schedule_status', 'schedule_brief', 'schedule_detail', 'time_type', 'start_time', 'end_time',
                 'schedule_type', 'input_id', 'notify_id', 'if_remind_message']
    values = [data.get(key) for key in data_keys]

    # 确保所有变量都有值，否则进行适当的错误处理
    if any(v is None for v in values):
        return jsonify({"success": False, "error": "Missing required data"}), 400

    start_index = data_keys.index('start_time')
    end_index = data_keys.index('end_time')
    values[start_index] = datetime.strptime(values[start_index], "%Y-%m-%d %H:%M:%S")
    values[end_index] = datetime.strptime(values[end_index], "%Y-%m-%d %H:%M:%S")

    for key, value in zip(data_keys, values):
        setattr(old_schedule, key, value)
    ScheduleDate.query.filter_by(schedule_id=old_schedule.schedule_id).delete()
    try:
        db.session.commit()
    except IntegrityError as e:
        # 违反了数据库表的唯一性约束、外键约束
        db.session.rollback()
        return jsonify({"error": "IntegrityError: {}".format(str(e))}), 400

    for date in date_list:
        new_date = ScheduleDate(date_num=date, schedule_id=schedule_id)
        db.session.add(new_date)
    Reminder.query.filter_by(schedule_id=old_schedule.schedule_id).delete()

    #                              sync部分
    notify = old_schedule.notice
    if (old_schedule.schedule_status == ScheduleState.ENABLED and old_schedule.if_remind_message
            and not notify.notify_sync):
        generate_remind_times(old_schedule)
    db.session.commit()
    return jsonify(
        {"success": True, "message": "Successful modify a schedule", "schedule_id": old_schedule.schedule_id}), 200
