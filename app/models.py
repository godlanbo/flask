from datetime import datetime
from app import db,app,auth
from flask_login import UserMixin
from app import login
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_manager
from flask import jsonify
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from flask import g,request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_,or_,not_
maps = ['普通用户','铜牌用户','银牌用户','金牌用户','Root','superRoot']
GMT_FORMAT = '%a %b %d %Y %H:%M:%S GMT'
class User(UserMixin, db.Model):
    """定义用户信息的数据库"""
    # 用户名
    # 密码
    # 电话(用于登陆)        
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(64),index = True,unique=True) # 用户的账号
    company = db.Column(db.String(64), index=True) # 公司名称
    contact = db.Column(db.String(64),index =True) # 联系人
    telnum = db.Column(db.String(11), index=True, nullable = False) # 电话号码
    ip_addr = db.Column(db.PickleType,index = True,nullable = True) # ip地址
    right = db.Column(db.Integer,nullable = False)   # 用户的等级
    right_chinese = db.Column(db.String(64))   # 用户的等级
    password = db.Column(db.String(64))  # 用户密码
    password_hash = db.Column(db.String(128)) # 加过密的密码
    search_count = db.Column(db.Integer) # 用于对查询次数计数
    out_count = db.Column(db.Integer) # 用于对导出次数计数
    data_count = db.Column(db.Integer) # 用于对数据查询量计数

    def reset_count(self):
        if self.right == 1: 
            self.date_count = 10
            self.search_count = 10
            self.out_count = 0
        elif self.right == 2:
            self.date_count = 20 
            self.search_count = 10
            self.out_count = 0
        elif self.right == 3:
            self.date_count = 50
            self.search_count = 10
            self.out_count = 0
        elif self.right == 4:
            self.date_count = 100
            self.search_count = 20
            self.out_count = 20
        else:
            self.date_count = 10000000
            self.search_count = 100000
            self.out_count = 100000

    def set_right(self,right):
        self.right_chinese = maps[right-1]
        self.right = right
        

    def set_password(self, password):
        # 通过哈希加密密码
        self.password_hash = generate_password_hash(password)
        self.password = password

    # 通过哈希检测密码
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 重置密码
    def reset_password(self):
        self.password = "123456789"
        self.password_hash = generate_password_hash("123456789")

    # 添加ip
    def add_ip(self,ip_addr):
        if self.right>4:
            return
        elif self.ip_addr == None:
            self.ip_addr = [ip_addr]

        elif len(self.ip_addr) < self.right and ip_addr not in self.ip_addr:
            self.ip_addr.append(ip_addr)

    # 重置ip
    def reset_ip(self):
        self.ip_addr = None

    # 检测ip
    def check_ip(self,ip_addr):
        if self.right > 4 or ip_addr in self.ip_addr:
            return True
        return False
        
    # 修改信息
    def change_info(self,username,password):
        if(password!=None):
            self.set_password(password)
        if(username!=None):
            self.username = username

    def to_dict(self):
        return {"account":self.account,"company":self.account,"companyBoss":self.contact,\
                 "telnum":self.telnum,"password":self.password,"right":self.right_chinese,\
                 "ip":self.ip_addr}

    # 得到全部用户信息
    @staticmethod
    def get_all_user(page_num,page_size = 20):
        page = User.query.filter(User.id > 1).order_by(User.id).paginate(page_num,per_page=page_size,error_out=False)
        all_user = page.items
        return [user.to_dict() for user in all_user], User.query.count()

    # 分页
    @staticmethod
    def paging(data,page_num,page_size = 20):
        return data[(page_num-1)*page_size:(page_num)*page_size if page_num*page_size>len(data) else len(data)],len(data)

    # 搜索
    @staticmethod
    def search(keyword):
        con = store_info.id > 1
        if keyword:
            con = and_(con,or_(User.account.like("%{}%".format(keyword)),
                                User.company.like("%{}%".format(keyword)),
                                User.contact.like("%{}%".format(keyword)),
                                User.ip_addr.like("%{}%".format(keyword))))
        all_info = store_info.query.filter(con).all()
        return [info.to_dict() for info in all_info]


    def generate_auth_token(self, expiration = 5184000):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    @auth.verify_token
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        g.user = user
        return user

class store_info(UserMixin, db.Model):
    """
        定义商户信息的数据库
    """
    # 商户名称
    # 地址
    # 链接
    # 联系人
    # 电话
    # 信息来源
    # 渠道
    # 备注
    # 更新时间
    id = db.Column(db.Integer, primary_key = True)  
    store_name = db.Column(db.String(100), index=True, unique=True) # 商户名称
    store_address = db.Column(db.String(100), index = True)   # 商家地址
    phone_number = db.Column(db.String(100), index = True)    # 商家电话号码
    score = db.Column(db.Float(10))  # 评分
    comment_num = db.Column(db.String(20),index = True)  # 信息来源
    city = db.Column(db.String(),index = True)
    web_link = db.Column(db.String(128)) # 商家链接
    web = db.Column(db.String(128)) # 表示从那个网站爬取的 
    remark = db.Column(db.String(128))  # 备注
    time = db.Column(db.DateTime, index=True) #爬取时间
    adminName = db.Column(db.String(128),index = True)
    def to_dict(self):
        return {"store_name":self.store_name , "store_address":self.store_address,\
                "phone_number":self.phone_number , "score":self.score , "comment_num":\
                self.comment_num , "web_link":self.web_link , "web":\
                self.web , "remark":self.remark , "time": str(self.time) }

    # 得到所有商家信息
    @staticmethod
    def get_all_store_info(page_num,page_size = 2):
        page = store_info.query.order_by(store_info.time).paginate(page_num,per_page = page_size,error_out = False)
        all_info = page.items
        return [info.to_dict() for info in all_info], store_info.query.count()

    # 分页
    @staticmethod
    def paging(data,page_num,page_size = 2):
        return data[(page_num-1)*page_size:(page_num)*page_size if page_num*page_size>len(data) else len(data)],len(data)
    
    # 搜索
    def search(keyword,path,info_from,date_begin,date_end):
        con = store_info.id>=1
        if keyword:
            con = or_(store_info.store_address.like("%{}%".format(keyword)),
                      store_info.store_name.like("%{}%".format(keyword)),
                      store_info.phone_number.like("%{}%".format(keyword)))
        if path:
            con = and_(con,store_info.path == path)
        if info_from:
            con = and_(con,store_info.info_from == info_from)
        if date_begin:
            con = and_(con,store_info.time > date_begin)
        if date_end:
            con = and_(con,store_info.time < date_end)
        all_info  =  store_info.query.filter(con).all()
        return [info.to_dict() for info in all_info]
 
class recircle_user(UserMixin, db.Model):
    """定义用户信息的数据库"""
    # 用户名
    # 密码
    # 电话(用于登陆)
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(64), index=True, unique=True) # 用户的账号
    company = db.Column(db.String(64), index=True) # 公司名称
    contact = db.Column(db.String(64), index=True) # 联系人
    telnum = db.Column(db.String(11), index=True, nullable=False) # 电话号码
    ip_addr = db.Column(db.PickleType, index=True, nullable=True) # ip地址
    right = db.Column(db.Integer, nullable=False)   # 用户的等级
    right_chinese = db.Column(db.String(64))
    password = db.Column(db.String(64))  # 用户密码
    password_hash = db.Column(db.String(128))   # 加过密的密码
    delete_time = db.Column(db.DateTime) # 删除时间
    rest_day = db.Column(db.Integer)


    # 通过名称索引恢复该用户
    @staticmethod
    def recircle(account):
        d_user = recircle_user.query.filter_by(account = account).first()
        if not d_user:
            return None
        r_user = User(account = d_user.account,
                      company = d_user.company,
                      contact = d_user.contact,
                      telnum = d_user.telnum,
                      ip_addr = d_user.ip_addr,
                      right = d_user.right,
                      right_chinese = d_user.right_chinese,
                      password = d_user.password,
                      password_hash = d_user.password_hash)
        r_user.reset_count()
        return d_user,r_user

    def to_dict(self):
            return {"account":self.account,"company":self.account,"companyBoss":self.contact,\
                     "telnum":self.telnum,"password":self.password,"right":self.right_chinese,\
                     "ip":self.ip_addr}

    # 得到全部用户信息
    @staticmethod
    def get_all_user(page_num,page_size = 20):
        page = recircle_user.query.order_by(recircle_user.id).paginate(page_num,per_page=page_size,error_out=False)
        all_r_user = page.items
        return [r_user.to_dict() for r_user in all_r_user], recircle_user.query.count()

    # 分页
    @staticmethod
    def paging(data,page_num,page_size = 20):
        return data[(page_num-1)*page_size:(page_num)*page_size if page_num*page_size>len(data) else len(data)],len(data)

    # 搜索
    @staticmethod
    def search(keyword,timeframe):
        con = store_info.id > 1
        if keyword:
            con = and_(con,or_(recircle_user.account.like("%{}%".format(keyword)),
                                recircle_user.company.like("%{}%".format(keyword)),
                                recircle_user.contact.like("%{}%".format(keyword)),
                                recircle_user.ip_addr.like("%{}%".format(keyword))))
        if timeframe:
            con = adn_(con,recircle_user.rest_day < timeframe)
        all_info = store_info.query.filter(con).all()
        return [info.to_dict() for info in all_info]

def verify_password(account, password):
    user = User.query.filter_by(account = account).first()
    if not user or not user.check_password(password):
        return False
    g.user = user
    return True

@auth.error_handler
def unauthorized():
    code = get_code(request.headers['Authorization'])
    return jsonify({"Error_message":"token无效"}),200,\
                {'Authorization':request.headers['Authorization'],'code':code}

# 判断当前token状态
def get_code(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return 10010 # valid token, but expired
        except BadSignature:
            return 10011 # invalid token
        return 0

# 根据公司名称生成一个账号
def get_account(company,userNum):
    """
    userNum 该公司申请账号总数
    user_num 账号的后3位
    """

    all_user = User.query.all()
    try:
        company_num = User.query.filter_by(company = company).first()['account'][0:3]
    except:
        company_num = ("00"+str(len(set([user.account[0:3]  for user in User.query.all() if user.id!=1]))))[-3:]
    company_user_num = len(User.query.filter_by(company = company).all())
    return [company_num + ("00" + str(company_user_num + offset))[-3:] for offset in range(userNum)]

