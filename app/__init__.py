from flask import Flask
from app.config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from logging.handlers import RotatingFileHandler
import multiprocessing
from flask_httpauth import HTTPTokenAuth
import os
import logging
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest


app = Flask(__name__)	# 创建一个flask对象
auth = HTTPTokenAuth(scheme='Token')
app.config.from_object(Config)	# 给flask对象通过类来配置一些属性
db = SQLAlchemy(app)	# 创建一个数据库对象
client = AcsClient('LTAI4FqWjNWjnSWXe6qLUXc5', 'DWIh9COWIIIQ95U7Tulm5dshKL70Yo', 'cn-hangzhou')
migrate = Migrate(app, db)	# 创建一个Migrate对象，用于迁移数据库
login = LoginManager(app)	# 创建一个登陆管理对象
login.init_app(app)
# 设置登录视图的名称，如果一个未登录用户请求一个只有登录用户才能访问的视图，
# 则闪现一条错误消息，并重定向到这里设置的登录视图。
# 如果未设置登录视图，则直接返回401错误。	
# login.login_view = 'login'
# 用于记录日志
if not app.debug:
	# 创建日志文件夹
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/info.log', maxBytes=40960,
                                       backupCount=40)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Microblog startup')
from app.timing import *
from app import routes,models
if __name__ == '__main__':
    t =  timing.start
    process1 = multiprocessing.Process(target=t)
    process1.start()