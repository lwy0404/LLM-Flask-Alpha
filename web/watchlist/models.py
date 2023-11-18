from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import String, ForeignKey, event, and_
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


class LanguageModel(Enum):
    Chinese_Alpaca = 0
    ChatGLM = 1


class TimeType(Enum):
    Day = 0
    Minute = 1


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

    def __init__(self, email):
        self.email = email


class Notify(db.Model):
    notify_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    if_repeat = mapped_column(db.Boolean, nullable=False)
    default_notify = mapped_column(db.Boolean)
    repeat_interval = mapped_column(db.Integer)
    before_time = mapped_column(db.Integer)  # 用秒表示的提前量, 比如提前15分钟提醒就是900

    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    schedule = db.relationship('Schedule', backref='notice', lazy=True)

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
    input_id = mapped_column(db.Integer, primary_key=True, autoincrement=True, server_default="0")
    input_type = mapped_column(db.Enum(InputType), nullable=False)  # 存储原始数据的类型
    data = mapped_column(db.Text, nullable=False)  # 存储的原始数据, 经过base64编码
    original_text = mapped_column(db.Text, nullable=False)  # 从原始数据中识别出来的文本
    apply_time = mapped_column(db.DateTime, nullable=False)  # 提交时间
    use_model = mapped_column(db.Enum(LanguageModel), nullable=False)  # 由哪个语言模型进行分析
    pretrainable = mapped_column(db.Boolean, nullable=False)  # 这份input是否能被添加到训练集

    schedule = db.relationship('Schedule', backref='schedule', lazy=True, cascade="save-update")
    pretrained_data = db.relationship('PretrainedData', backref='input_data', lazy=True, uselist=False)

    def __init__(self, input_type, data, original_text, now_time, use_model):
        self.input_type = input_type
        self.data = data
        self.original_text = original_text
        self.apply_time = now_time
        self.use_model = use_model


class PretrainedData(db.Model):
    pretrained_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    input_type = mapped_column(db.Enum(InputType), nullable=False)  # 存储原始数据的类型
    data = mapped_column(db.Text, nullable=False)  # 存储的原始数据, 经过base64编码
    apply_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)  # 提交时间
    use_model = mapped_column(db.Enum(LanguageModel), nullable=False)  # 由哪个语言模型进行分析

    input_id = db.Column(db.Integer, db.ForeignKey('input_data.input_id'), nullable=False)


class Schedule(db.Model):
    schedule_id: Mapped[int] = mapped_column(db.BigInteger, primary_key=True, autoincrement=True)
    schedule_status = mapped_column(db.Enum(ScheduleState), nullable=False)  # 启用, 禁用或过期
    schedule_brief = mapped_column(db.String(100))  # 日程的简要概括
    schedule_detail = mapped_column(db.Text, nullable=False)  # 日程的具体细节
    time_type = mapped_column(db.Enum(TimeType), nullable=False)  # 日程的时间精度
    start_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)  # 日程开始时间
    end_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)  # 日程结束时间
    if_remind_message: Mapped[bool] = mapped_column(db.Boolean, nullable=False)  # 是否启用提醒
    schedule_type = mapped_column(db.Enum(ScheduleType), nullable=False)  # 指示日程的周期: 每年/月/日/星期/单次, 或特殊时间

    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    share_schedule = db.relationship('Share', backref='schedule', lazy=True,
                                     cascade="save-update, delete-orphan, delete")
    date = db.relationship('ScheduleDate', backref='schedule', lazy=True,
                           cascade="save-update, delete-orphan, delete")
    notify_id = db.Column(db.Integer, db.ForeignKey('notify.notify_id'), nullable=False)
    original_data_id = db.Column(db.Integer, db.ForeignKey('input_data.input_id'), nullable=False)

    def __init__(self, schedule_status, schedule_brief, schedule_detail, time_type, start_time, end_time,
                 schedule_type, if_remind, user_id, notify_id, input_id):
        self.schedule_status = schedule_status
        self.time_type = time_type
        self.schedule_type = schedule_type
        self.schedule_brief = schedule_brief
        self.schedule_detail = schedule_detail
        self.start_time = start_time
        self.end_time = end_time
        self.user_id = user_id
        self.if_remind_message = if_remind
        self.notify_id = notify_id
        self.original_data_id = input_id


class Share(db.Model):
    share_code = mapped_column(db.String(6), nullable=False, unique=True)  # 使用较短的字符串字段
    share_id = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    share_cascade = mapped_column(db.Boolean, nullable=False)  # 指示由该分享添加的日程是否复制对应的input_data
    expiration_date = mapped_column(db.DateTime, nullable=False)
    schedule_id = db.Column(db.BigInteger, db.ForeignKey('schedule.schedule_id'),
                            nullable=False)

    def __init__(self, schedule_id, expiration_date):
        self.share_code = self.calculate_share_code()
        self.schedule_id = schedule_id
        self.expiration_date = expiration_date

    def calculate_share_code(self):
        # 将 share_id 转换为字节
        share_schedule_id_bytes = str(self.share_id).encode()
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
