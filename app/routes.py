from app import app,db,auth,client
from app.models import *
from flask import redirect,url_for,request,g,session
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user,login_required,logout_user
from werkzeug.urls import url_parse
from app.response import *
from flask import jsonify,Response,make_response
from datetime import datetime
from sqlalchemy import and_,or_,not_

# 设置登陆路由
# 仅接受post请求
# 检查密码账号是否正确
@app.route('/api/check_account',methods=['POST'])
def check_account(): 
    data = request.get_json(silent = True)
    if data == None:
        return response_login_requests(False,"账号密码不能为空")
    ip = request.remote_addr
    account = data['account']
    password = data['password']
    ok = verify_password(account, password)
    if not ok:
        return response_login_requests(False,"密码错误")
    user = g.user
    user.add_ip(ip)
    if not user.check_ip(ip):
        return response_login_requests(False,"该IP不是你的常用IP")
    db.session.commit()
    login_user(user)
    token = user.generate_auth_token()
    return jsonify(g.user.to_dict()),200,{'Authorization':\
            request.headers['Authorization'],'code':0}

@app.route('/api/personal_info',methods = ['GET'])
@auth.login_required
def personal_info():
    data = request.get_json(silent = True)
    return jsonify(g.user.to_dict()),200,{'Authorization':request.headers['Authorization'],'code':0}

# 添加用户
@app.route('/api/add_user',methods = ['POST'])
@auth.login_required
def add_user():
    data = request.get_json(silent=True)
    try:
        userNum = data['userNum']
        right = int(data["right"])
        telnum = data["telnum"]
        company = data['company']
        contact = data['companyBoss']
    except:
        return jsonify({"success":False,"error_message":"请完善信息"}),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
    if g.user.right < 5 or (right == 5 and g.user.right != 6) or right >= 6:
        return jsonify({"success":False,"error_message":"权限不够"}),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
    all_account = get_account(company,int(userNum))
    try: 
        for account in all_account:
            user = User(account = account,company = company,telnum = telnum,right = right,contact = contact)
            user.reset_password()
            user.reset_count()
            user.set_right(right)
            db.session.add(user)
    except:
         return response_register_requests(False,"信息错误"),200,{'Authorization':\
                     request.headers['Authorization'],'code':0}
    db.session.commit()
    return response_register_requests(True,"注册成功"),200,{'Authorization':\
        request.headers['Authorization'],'code':0}

# 修改密码
@app.route('/api/change_info',methods = ["POST"])
@auth.login_required
def change_info():
    data = request.get_json(silent=True)
    try:
        old_password = data['old_password']
        new_password = data["new_password"]
    except:
        return response_register_requests(False,"信息错误"),200,{'Authorization':\
                     request.headers['Authorization'],'code':0}
    if user != None:
        ok = verify_password(account, password)
        if not ok:
            return jsonify({"success":False,"error_message":"密码错误"}),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
        g.user.set_password(password)
        db.session.commit()
        return jsonify({"success":True,"error_message":""}),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
    return jsonify({"success":False,"error_message":"账号为空"}),200,{'Authorization':\
        request.headers['Authorization'],'code':0}


# 查询用户信息
@app.route('/api/get_user_info',methods = ['POST'])
@auth.login_required
def get_user_info():
    data = request.get_json(silent=True)
    page_num = data['pageNumber']
    searchState = data['searchState']
    if searchState and "search_user_info" in session.keys():
        info,totalInfoNum = User.paging(session['search_user_info'],page_num)
        return jsonify({"info":info,"totalInfoNum":totalInfoNum}),200,{'Authorization':request.headers['Authorization'],'code':0}
    user_info, totalInfoNum = User.get_all_user(page_num)
    return jsonify({"user_info":user_info,"totalInfoNum":totalInfoNum}), \
            200, {'Authorization':request.headers['Authorization'],'code':0}


# 搜索用户
@app.route('/api/search_user',methods = ['POST'])
@auth.login_required
def search_user():
    data = request.get_json(silent=True)
    if(data == None):
        return jsonify({"success":False,"error_message":"空数据"}),\
                200, {'Authorization':request.headers['Authorization'],'code':0}
    keyword = data['keyword']
    session['search_user_info'] = User.search(keyword)
    info,totalInfoNum = User.paging(session['search_user_info'],1)
    return jsonify({"info":info,"totalInfoNum":totalInfoNum}), \
            200, {'Authorization':request.headers['Authorization'],'code':0}

@app.route('/api/del_user',methods = ['POST'])
@auth.login_required
def del_user():
    """
        删除用户
    """
    data = request.get_json(silent= True)
    if(data == None):
        return jsonify({"success":False,"error_message":"空数据"}),200, \
                {'Authorization':request.headers['Authorization'],'code':0}
    account = str(data['account'])
    d_user = User.query.filter_by(account = account).first()
    if not d_user:
        return response_register_requests(False,"该用户不存在"),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
    try:
        user = g.user
    except BaseException as e:
        return response_register_requests(False,"当前账号未登录"),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}

    if g.user.right < 5 or (d_user.right==5 and g.user.right != 6):
        return jsonify({"success":False,"error_message":"权限不够"}),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
    re_user = recircle_user(account = d_user.account,
                            company = d_user.company,
                            contact = d_user.contact,
                            telnum = d_user.telnum,
                            ip_addr = d_user.ip_addr,
                            right = d_user.right,
                            right_chinese = d_user.right_chinese,
                            password = d_user.password,
                            password_hash = d_user.password_hash,
                            delete_time = datetime.now(),
                            rest_day = 30)
    db.session.add(re_user)
    db.session.delete(d_user)
    db.session.commit()
    return "",204,{'Authorization':request.headers['Authorization'],'code':0}


# 得到全部信息
@app.route('/api/get_store_info',methods=["POST"])
@auth.login_required
def get_store_info():
    data = request.get_json(silent = True)
    print(data)
    page_num = int(data['pageNumber'])
    searchState = data['searchState']
    if searchState and "search_store_info" in session.keys():
        info,totalInfoNum = store_info.paging(session['search_store_info'],page_num)
        return jsonify({"info":info,"totalInfoNum":totalInfoNum}),200,\
                {'Authorization':request.headers['Authorization'],'code':0}
    info,count = store_info.get_all_store_info(page_num)
    return jsonify({"info":info , "totalInfoNum":count}),200,\
            {'Authorization':request.headers['Authorization'],'code':0}


# 搜索相关信息
@app.route('/api/search_store_info',methods = ['POST'])
@auth.login_required
def search_store_info():
    data = request.get_json(silent = True)
    if(data == None):
        return jsonify({"success":False,"error_message":"空数据"}),200, \
        {'Authorization':request.headers['Authorization'],'code':0}
    keyword = data['keyword']
    info_from = data['infofrom'] if data['infofrom'] !='all' else None
    path = data['path'] if data['path'] !='all' else None
    try:
        date1 = data['date1'][0:10] + " 23:59:00"
        date2 = data['date2'][0:10] + " 23:59:00"
        date_begin = datetime.strptime(date1,'%Y-%m-%d %H:%M:%S')
        date_end = datetime.strptime(date2,'%Y-%m-%d %H:%M:%S')
    except:
        date_begin = None
        date_end = None
    if g.user.right<5 and g.user.data_count <= 0:
        return  jsonify({"success":False,"error":"countEnd"}),200, \
                {'Authorization':request.headers['Authorization'],'code':0}
    session['search_store_info'] = store_info.search(keyword,path,info_from,date_begin,date_end)
    info,totalInfoNum = store_info.paging(session['search_store_info'],1)
    return jsonify({"info":session['search_store_info'],"totalInfoNum":totalInfoNum}), 200,\
             {'Authorization':request.headers['Authorization'],'code':0}
    
# 手动添加信息
@app.route('/api/add_store_info',methods = ['POST'])
@auth.login_required
def add_store_info():
    data = request.get_json(silent = True)
    if(data == None):
        return jsonify({"success":False,"error_message":"空数据"}),200,\
                {'Authorization':request.headers['Authorization'],'code':0}
    store_name = data['store_name'] # 商户名称
    store_address = data['store_address']   # 商家地址
    phone_number = data['phone_number']    # 商家电话号码
    score = data['score']  # 评分
    comment_num = data['comment_num']  # 信息来源
    adminName = data['adminName'] # 公司负责人
    infofrom = data['infofrom']  # 信息来源
    web_link = data['web_link'] # 商家链接
    web = data['web'] # 表示从那个网站爬取的 
    remark = data['remark'] # 备注
    time = datetime.strptime(data['time'],'%Y-%m-%d %H:%M:%S') # 爬取时间

    new_store = store_info(
        store_name = store_name,
        store_address = store_address,
        phone_number = phone_number,
        score = score,
        comment_num = comment_num,
        web_link = web_link,
        web = web,
        remark = remark,
        time = time,
        adminName = adminName
    )

    db.session.add(new_store)
    db.session.commit()
    return "",204,{'Authorization':request.headers['Authorization'],'code':0}

# 删除商户信息
@app.route('/api/del_store',methods = ['POST'])
@auth.login_required
def del_store():
    data = request.get_json(silent = True)
    if(data == None):
        return jsonify({"success":False,"error_message":"空数据"}),200,\
                {'Authorization':request.headers['Authorization'],'code':0}
    store_name = data['store_name']
    d_store = store_info.query.filter_by(store_name = store_name).first()
    if not d_store:
        return response_register_requests(False,"该用户不存在"),200,{'Authorization':\
                    request.headers['Authorization'],'code':0}
    db.session.delete(d_store)
    db.session.commit()
    return "",204,{'Authorization':request.headers['Authorization'],'code':0}

# 恢复用户
@app.route('/api/re_user',methods = ['POST'])
@auth.login_required
def re_user():
    data = request.get_json(silent = True)
    if not isinstance(data,list):
        data = list([data])
    all_account = [i["account"] for i in data]
    for account in all_account:
        d_user,r_user = recircle_user.recircle(account)
        db.session.delete(d_user)
        db.session.add(r_user)
    db.session.commit()
    return "",204,{'Authorization':request.headers['Authorization'],'code':0}

# 删除回收站的用户
@app.route('/api/del_re_user',methods = ['POST'])
@auth.login_required
def del_re_user():
    data = request.get_json(silent = True)
    if not isinstance(data,list):
        data = list([data])
    all_account = [i['account'] for i in data]
    for account in all_account:
        d_re_user = recircle_user.query.filter_by(account = account).first()
        db.session.delete(d_re_user)
    db.session.commit()
    return "",204,{'Authorization':request.headers['Authorization'],'code':0}

# 查看删除用户信息
@app.route('/api/get_re_user',methods = ['POST'])
@auth.login_required
def get_re_user_info():
    data = request.get_json(silent=True)
    page_num = data['pageNumber']
    searchState = data['searchState']
    if searchState and "search_re_user_info" in session.keys():
        info,totalInfoNum = recircle_user.paging(session['search_re_user_info'],page_num)
        return jsonify({"info":info,"totalInfoNum":totalInfoNum}),200,{'Authorization':request.headers['Authorization'],'code':0}
    re_user_info, totalInfoNum = recircle_user.get_all_user(page_num)
    return jsonify({"re_user_info":re_user_info,"totalInfoNum":totalInfoNum}), 200, {'Authorization':request.headers['Authorization'],'code':0}


# 搜索删除用户
@app.route('/api/search_re_user',methods = ['POST'])
@auth.login_required
def search_re_user():
    data = request.get_json(silent=True)
    if(data == None):
        return jsonify({"success":False,"error_message":"空数据"})
    keyword = data['keyword']
    timeframe = data['timeframe']
    session['search_re_user_info'] = store_info.search(keyword,timeframe)
    info,totalInfoNum = store_info.paging(session['search_re_user_info'],1)
    return jsonify({"info":session['search_re_user_info'],"totalInfoNum":totalInfoNum}), 200, {'Authorization':request.headers['Authorization'],'code':0}


# 发送短信
@app.route('/api/send_message',methods = ['POST'])
@auth.login_required
def send_smg():
    request = CommonRequest()
    request.set_accept_format('json')
    request.set_domain('dysmsapi.aliyuncs.com')
    request.set_method('POST')
    request.set_protocol_type('https') # https | http
    request.set_version('2017-05-25')
    request.set_action_name('SendBatchSms')
    data = request.get_json(silent = True)
    tel = [tel.phone_number for tel in data]
    request.add_query_param('RegionId', "cn-hangzhou")
    request.add_query_param('PhoneNumberJson', json.dumps(phone_number))
    request.add_query_param('SignNameJson', json.dumps(["龙鱼游戏","龙鱼游戏"]))
    request.add_query_param('TemplateCode', "SMS_175050744")
    request.add_query_param('TemplateParamJson', json.dumps([{"code":"8080"}]*len(tel)))
    response = client.do_action(request)
    return response,200,{'Authorization':request.headers['Authorization'],'code':0}

# 查询短信信息
@app.route('/api/get_msg_histroy',methods = ['POST'])
@auth.login_required
def get_msg_histroy():
    pass
