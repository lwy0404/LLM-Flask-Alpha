import os


import pymysql
import memcache
from flask import Flask
from flask_bootstrap import Bootstrap5
from flask_login import current_user, LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session

from sqlalchemy.orm import DeclarativeBase
from apscheduler.schedulers.background import BackgroundScheduler
from celery import Celery





class Base(DeclarativeBase):
    pass


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'ScheduleMaster')

db = SQLAlchemy(model_class=Base)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://liwanyun:graphhnu2023@115.157.197.84:8040/LLM'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对模型修改的监控
db.init_app(app)

login_manager = LoginManager(app)  # 实例化扩展类
login_manager.login_view = 'login'
bootstrap = Bootstrap5(app)
Alpaca_API_URL = 'http://localhost:19327/v1/chat/completions'
GLM_API_URL = 'http://localhost:8000/v1/chat/completions'

app.config["MAIL_SERVER"] = "smtp.qq.com"  # 邮件服务器的名称/IP地址
app.config["MAIL_PORT"] = 465  # 所用服务器的端口号
app.config["MAIL_USERNAME"] = "2293652843@qq.com"  # 发件人的用户名
app.config["MAIL_PASSWORD"] = "ezwcgermkmmxechf"  # 发件人的POP3/IMAP/SMTP服务的SSL连接客户端授权码
app.config["MAIL_USE_TLS"] = False  # 禁用传输安全层加密
app.config["MAIL_USE_SSL"] = True  # 启用安全套接字层加密
mail = Mail(app)  # 创建邮件类对象

app.config["MEMCACHE_SERVERS"] = ["115.157.197.84:11211"]  # Memcache 服务器的主机和端口
app.config["MEMCACHE_TIMEOUT"] = 120  # 缓存项的默认过期时间（以秒为单位）
memcache_client = memcache.Client(app.config['MEMCACHE_SERVERS'])

app.config['SESSION_TYPE'] = 'memcached'  # 选择会话存储后端（也可以使用其他后端，如数据库）
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# app.config['WTF_CSRF_ENABLED'] = False
'''scheduler = BackgroundScheduler()
scheduler.add_job(func=check_reminders, trigger="interval", minutes=1)
scheduler.start()'''


'''def check_reminders():
    current_time = datetime.now()
    reminders = Reminder.query.filter(Reminder.reminder_time <= current_time).all()

    for reminder in reminders:
        send_result = send_reminder.apply_async(args=[reminder.schedule_id])
        if send_result.successful():
            # Delete the reminder from the database
            db.session.delete(reminder)
            db.session.commit()'''


'''@celery.task
def send_reminder(schedule_id):
    # Implement your reminder sending logic here
    print(f"Sending reminder for Schedule ID: {schedule_id}")'''


@login_manager.user_loader
def load_user(user_email):  # 创建用户加载回调函数，接受用户 ID 作为参数
    from watchlist.models import User

    user = User.query.filter_by(email=user_email).first()  # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象


@app.context_processor
def inject_user():
    # 返回一个包含当前用户信息的字典，如果用户未登录，则返回空字典
    return {"current_user": current_user}


from watchlist import views, app_views
