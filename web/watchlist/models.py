import secrets
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import String, ForeignKey, event, and_
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, validates
from werkzeug.security import generate_password_hash, check_password_hash
import binascii
import zlib
from enum import Enum
from watchlist import db


class ScheduleState(Enum):
    ENABLED = 0
    DISABLED = 1
    EXPIRED = 2


class InputType(Enum):
    TEXT = 0
    PICTURE = 1
    AUDIO = 2


class ScheduleType(Enum):
    SINGLE = 0
    CYCLE = 1
    EVERY_DAY = 2
    EVERY_WEEK = 3
    EVERY_MONTH = 4
    EVERY_YEAR = 5
    AT_SPECIFIC_WEEKDAY = 6
    AT_SPECIFIC_MONTHDAY = 7
    AT_SPECIFIC_DATE_WITHOUT_SPECIFIC_YEAR = 8
    AT_SPECIFIC_TIME = 9


'''/sT=0 null sT=1 datetime cycle timelength sT=2345 int (eg. sT=2 cT=2 means every 2 week) sT= int (eg. sT=6 cT=3 
means every Thursday/sT=7 cT=7 means every 8th day of month(7+1=8)) sT=8 int (eg. cT=105 means every February 6)'''


class LanguageModel(Enum):
    Chinese_Alpaca = 0
    ChatGLM = 1


class TimeType(Enum):
    Day = 0
    Minute = 1


class Reminder(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    reminder_time = db.Column(db.DateTime, nullable=False)
    schedule_id = db.Column(db.BigInteger, db.ForeignKey('schedule.schedule_id'),
                            nullable=False)

    def __init__(self, reminder_time, schedule_id):
        self.reminder_time = reminder_time
        self.schedule_id = schedule_id


class User(db.Model, UserMixin):
    user_id = mapped_column(db.Integer, autoincrement=True, primary_key=True)
    email = mapped_column(db.String(30), unique=True)
    password_hash = mapped_column(db.String(128))  # 密码散列值
    user_name = mapped_column(db.String(40))
    user_preference = mapped_column(db.String(200))

    schedule = db.relationship('Schedule', backref='user', lazy=True, cascade="save-update, "
                                                                              "delete-orphan, delete")
    notice_setting = db.relationship('Notify', backref='user', lazy=True, cascade="save-update, "
                                                                                  "delete-orphan, delete")

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值

    def get_id(self):
        return str(self.user_id)

    def __init__(self, email, name):
        self.email = email
        self.user_name = name


class Notify(db.Model):
    notify_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    notify_name = mapped_column(db.String(40), nullable=False)
    if_repeat = mapped_column(db.Boolean, nullable=False)
    default_notify = mapped_column(db.Boolean, server_default="0")
    repeat_interval = mapped_column(db.Integer, nullable=True)  # 用秒表示的提醒间隔, 比如间隔5分钟提醒就是300
    before_time = mapped_column(db.Integer, nullable=False)  # 用秒表示的提前量, 比如提前15分钟提醒就是900
    notify_sync = mapped_column(db.Boolean, nullable=False)  # app是否获得了notify的最新状态

    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    schedule = db.relationship('Schedule', backref='notice', lazy=True, cascade="save-update")

    def __init__(self, if_repeat, default, interval, before, user_id, notify_sync, notify_name):
        self.if_repeat = if_repeat
        self.default_notify = default
        self.before_time = before
        self.repeat_interval = interval
        self.user_id = user_id
        self.notify_sync = notify_sync
        self.notify_name = notify_name

    @validates('default_notify')
    def validate_default_notify(self, key, value):
        if value:
            # 检查是否已经存在其他 Notify 对象的 default_notify 为 True
            existing_default_notify = Notify.query.filter_by(user_id=self.user_id, default_notify=True).first()
            if existing_default_notify and existing_default_notify != self:
                raise ValueError("Only one Notify can have default_notify set to True per user.")
        return value


# 在插入或更新操作之前，使用事件监听器进行验证
@event.listens_for(Notify, 'before_insert')
@event.listens_for(Notify, 'before_update')
def validate_default_notify_on_insert_or_update(mapper, connection, target):
    if target.default_notify:
        existing_default_notify = Notify.query.filter(and_(
            Notify.user_id == target.user_id,
            Notify.default_notify == True  # noqa
        )).first()

        if existing_default_notify and existing_default_notify.notify_id != target.notify_id:
            # 如果已经存在默认提醒，并且不是当前对象，则抛出异常
            raise ValueError('User already has a default notify set to True')


class InputData(db.Model):
    input_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    input_type = mapped_column(db.Enum(InputType), nullable=False)  # 存储原始数据的类型
    data = mapped_column(db.Text, nullable=False)  # 存储的原始数据, 经过base64编码
    original_text = mapped_column(db.Text, nullable=False)  # 从原始数据中识别出来的文本
    apply_time = mapped_column(db.DateTime, nullable=False)  # 提交时间
    use_model = mapped_column(db.Enum(LanguageModel), nullable=False)  # 由哪个语言模型进行分析
    pretrainable = mapped_column(db.Boolean, nullable=False)  # 这份input是否能被添加到训练集

    schedule = db.relationship('Schedule', backref='schedule', lazy=True, cascade="save-update")

    def __init__(self, input_type, data, original_text, now_time, use_model, pretrainable):
        self.input_type = input_type
        self.data = data
        self.original_text = original_text
        self.apply_time = now_time
        self.use_model = use_model
        self.pretrainable = pretrainable


class PretrainedData(db.Model):
    pretrained_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    input_type = mapped_column(db.Enum(InputType), nullable=False)  # 存储原始数据的类型
    data = mapped_column(db.Text, nullable=False)  # 存储的原始数据, 经过base64编码
    original_text = mapped_column(db.Text, nullable=False)  # 从原始数据中识别出来的文本
    apply_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)  # 提交时间
    use_model = mapped_column(db.Enum(LanguageModel), nullable=False)  # 由哪个语言模型进行分析

    schedule_id = db.Column(db.BigInteger, db.ForeignKey('schedule.schedule_id'), nullable=True)

    def __init__(self, input_type, data, original_text, now_time, use_model, schedule_id):
        self.input_type = input_type
        self.data = data
        self.original_text = original_text
        self.apply_time = now_time
        self.use_model = use_model
        self.schedule_id = schedule_id


# sync总原则: 1. 如果一个schedule和它使用的notify都被APP同步(schedule_sync and notify_sync), 那么这个日程一定不会被加入邮件提醒队列(Reminder)
#            2. 即使不满足上述条件, 也只有当启用日程本身(ScheduleState.ENABLED)且需要提醒(schedule.if_remind_message=True)的情况下会被加入队列

class Schedule(db.Model):
    schedule_id: Mapped[int] = mapped_column(db.BigInteger, primary_key=True, autoincrement=True)
    schedule_status = mapped_column(db.Enum(ScheduleState), nullable=False)  # 启用, 禁用或过期
    schedule_brief = mapped_column(db.String(100))  # 日程的简要概括
    schedule_detail = mapped_column(db.Text, nullable=False)  # 日程的具体细节
    time_type = mapped_column(db.Enum(TimeType), nullable=False)  # 日程的时间精度
    start_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)  # 日程开始时间
    end_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)  # 日程结束时间
    if_remind_message: Mapped[bool] = mapped_column(db.Boolean, nullable=False)  # 是否启用提醒
    schedule_sync = mapped_column(db.Boolean, nullable=False)
    schedule_type = mapped_column(db.Enum(ScheduleType), nullable=False)  # 指示日程的周期: 每年/月/日/星期/单次, 或特殊时间

    share_schedule = db.relationship('Share', backref='schedule', lazy=True,
                                     cascade="save-update, delete-orphan, delete")
    mail_time = db.relationship('Reminder', backref='schedule', lazy=True,
                                cascade="save-update, delete-orphan, delete")
    date = db.relationship('ScheduleDate', backref='schedule', lazy=True,
                           cascade="save-update, delete-orphan, delete")
    training_data = db.relationship('PretrainedData', backref='schedule', lazy=True, uselist=False)

    notify_id = db.Column(db.Integer, db.ForeignKey('notify.notify_id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    original_data_id = db.Column(db.Integer, db.ForeignKey('input_data.input_id'), nullable=False)

    def __init__(self, schedule_status, schedule_brief, schedule_detail, time_type, start_time, end_time,
                 schedule_type, if_remind, user_id, notify_id, original_data_id, schedule_sync):
        self.schedule_status = ScheduleState(schedule_status)
        self.time_type = TimeType(time_type)
        self.schedule_type = ScheduleType(schedule_type)
        self.schedule_brief = schedule_brief
        self.schedule_detail = schedule_detail
        self.start_time = start_time
        self.end_time = end_time
        self.user_id = user_id
        self.if_remind_message = if_remind
        self.notify_id = notify_id
        self.original_data_id = original_data_id
        self.schedule_sync = schedule_sync


@event.listens_for(Schedule, 'before_insert')
@event.listens_for(Schedule, 'before_update')
def before_schedule_insert_update_listener(mapper, connection, schedule):
    # 在插入和更新之前检查 if_remind_message 和 notify_id 的约束
    if schedule.if_remind_message and not schedule.notify_id:
        raise ValueError("if_remind_message为True时，notify_id不能为空")

    if schedule.notify_id is None and schedule.if_remind_message:
        raise ValueError("notify_id为空时，if_remind_message只能为False")


class Share(db.Model):
    share_code = mapped_column(db.String(8), nullable=False, unique=True)  # 使用较短的字符串字段
    share_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    share_cascade = mapped_column(db.Boolean, nullable=False)  # 指示由该分享添加的日程是否复制对应的input_data
    expiration_date = mapped_column(db.DateTime, nullable=False)
    schedule_id = db.Column(db.BigInteger, db.ForeignKey('schedule.schedule_id'),
                            nullable=False)

    def __init__(self, schedule_id, expiration_date, share_cascade):
        self.share_code = self.calculate_share_code()
        self.schedule_id = schedule_id
        self.expiration_date = expiration_date
        self.share_cascade = share_cascade

    def calculate_share_code(self):
        # 将 share_id 转换为字节
        share_schedule_id_bytes = str(self.share_id).encode()
        random_bytes = secrets.token_bytes(4)  # 4 字节的随机数
        share_schedule_id_bytes += random_bytes
        # 使用 CRC32 哈希算法计算哈希值
        crc32_hash = zlib.crc32(share_schedule_id_bytes) & 0xFFFFFFFF
        # 将哈希值格式化为 8 位的十六进制字符串
        return format(crc32_hash, '08x')


class ScheduleDate(db.Model):
    date_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    date_num = mapped_column(db.Integer)
    schedule_id = db.Column(db.BigInteger, db.ForeignKey('schedule.schedule_id'), nullable=False)

    def __init__(self, date_num, schedule_id):
        self.date_num = date_num
        self.schedule_id = schedule_id
