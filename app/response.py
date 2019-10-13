from flask import jsonify

# 回复客户端的登陆请求
def response_login_requests(success,error_message):
	return jsonify({"success":success,"error_message":error_message})

# 回复客户端的注册请求
def response_register_requests(success,error_message):
	return jsonify({"success":success,"error_message":error_message})

# 回复客户端的全部信息请求
def to_dict(info):
	return {"name":info.name,"addr":info.addr,
		"url":info.url,"contact":info.contact,
		"telnum":info.telnum,"info_from":info.info_from,
		"remark":info.remark,"channel":info.channel,
		"updata_time":info.update_time}

def response_all_info_requests():
	all_info = Merchant_information.query.all()
	return jsonify([to_dict(i) for i in all_info])

def respose_search_requests(name,channel):
	all_info = Merchant_information.query.filter_by(name = name)
	return jsonify([to_dict(i) for i in all_info])

# def respose_query_user_info_request(telnum,username):
# 	if telnum == None and username == None:
# 		return User.query.filter_by(telnum = telnum)
#     all_user_info = User.query.filter_by(telnum = telnum)
#     return jsonify([to_dict(i) for i in all_info])