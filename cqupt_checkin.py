#! /bin/env python3
import base64
import datetime
import json
import os
import random
import sys
import time

import pytz
from Crypto.Cipher import AES
import ddddocr
import requests
from lxml import etree

'''  ##########！！！配置信息！！！(务必修改)########## '''
USERNAME = ""  # 本地打卡更改or后面就行
PASSWORD = ""  # 本地打卡更改or后面就行
# 学校拼音简写命名变量，真的会谢
checkin_data = {
    "JZDXXDZ": "详细地址",  # 目前居住地详细地址 本地打卡更改ot后面就行
    "JZDYQFXDJ": "其他",  # 目前居住地风险等级  可选参数:其他|低风险|中风险|高风险
    "SFYZGFXDQLJS": "无",  # 7天内是否有中高风险地区旅居史  可选参数:无|有
    "SFJCZGFXDQLJSRY": "无",  # 7天内是否接触中高风险地区旅居史人员  可选参数:无|有
    "SZDJSSFYYQFS": "否",  # 7天内所在地级市是否有本土疫情发生 可选参数:否|是
    "JZDSFFXQHLSGKQY": "否",  # 目前居住地是否为风险区或临时管控区域 可选参数:否|是
    "TWSFZC": "是",  # 今日体温是否正常 可选参数:是|否
    "SFYGRZZ": "无",  # 是否有疫情感染症状 可选参数:无|有
    "TZRYSFYC": "否",  # 同住人员是否有以上情况异常 可选参数:否|是|无同住人员
    "YKMYS": "绿色",  # 渝康码颜色   绿色|黄色|红色|其他
    "QTSM": "",  # 其他说明, 可选参数:空|说明字符串
    "LONGITUDE": "",  # 打卡经度
    "LATITUDE": "",  # 打卡维度
}
'''  ####################！！！通知信息配置！！！(按需修改，具体参照Readme)########## '''
# 通知方式
notification_types = []  # 可选参数:wx_pusher|push_plus|telegram_bot, 可多选。 e,g. notification_types = ["wx_pusher", "telegram_bot"]
# wx_pusher推送
wx_pusher_token = ""    # wx_pusher推送token，必填
wx_pusher_uids = []      # 需要推送目标的UID，是一个数组,元素类型为string。注意uids和topicIds可以同时填写，也可以只填写一个 e.g. ["UID_XXXXX", "UID_XXXXX"]
wx_pusher_topic_ids = []  # 发送目标的topicId，是一个数组,元素类型为int，也就是群发，使用uids单发的时候，可以不传。 e.g. [123]

# push_plus推送
push_plus_token = ""  # push_plus推送token，必填
push_plus_topic = ""  # push_plus群组编码，选填，不填仅发送给自己；channel为webhook时无效
push_plus_channel = ""  # 推送渠道，选填，不填默认为微信；可选参数见push plus文档

# telegram_bot推送
telegram_bot_token = ""  # telegram_bot推送token，必填
telegram_bot_chat_id = ""  # telegram_bot推送给的用户id,必填

'''  ##############################以下脚本运行代码，不动勿动##############################  '''
'''读取环境变量'''

if "USERNAME" in os.environ:
    USERNAME = os.environ["USERNAME"]
if "PASSWORD" in os.environ:
    PASSWORD = os.environ["PASSWORD"]
if "JZDXXDZ" in os.environ:
    checkin_data["JZDXXDZ"] = os.environ["JZDXXDZ"]
if "LONGITUDE" in os.environ:
    checkin_data["LONGITUDE"] = os.environ["LONGITUDE"]
if "LATITUDE" in os.environ:
    checkin_data["LATITUDE"] = os.environ["LATITUDE"]
if "NOTIFICATIONTYPES" in os.environ:
    notification_types = os.environ["NOTIFICATIONTYPES"].split(",")
if "PUSHPLUSTOKEN" in os.environ:
    push_plus_token = os.environ["PUSHPLUSTOKEN"]
if "PUSHPLUSTOPIC" in os.environ:
    push_plus_topic = os.environ["PUSHPLUSTOPIC"]
if "PUSHPLUSTCHANNEL" in os.environ:
    push_plus_channel = os.environ["PUSHPLUSTCHANNEL"]
if "TELEGRAMBOTTOKEN" in os.environ:
    telegram_bot_token = os.environ["TELEGRAMBOTTOKEN"]
if "TELEGRAMBOTCHATID" in os.environ:
    telegram_bot_chat_id = os.environ["TELEGRAMBOTCHATID"]
if "WXPUSHERTOKEN" in os.environ:
    wx_pusher_token = os.environ["WXPUSHERTOKEN"]
if "WXPUSHERUIDS" in os.environ:
    wx_pusher_uids = os.environ["WXPUSHERUIDS"].split(",")
if "WXPUSHERTOPICIDS" in os.environ:
    wx_pusher_topic_ids = os.environ["WXPUSHERTOPICIDS"].split(",")

'''--------------------------------------------------'''

if checkin_data['LONGITUDE'] == "" or checkin_data['LATITUDE'] == "":
    print("请输入经纬度,或者保证代码中已填写经纬度")
    sys.exit(1)

if checkin_data['JZDXXDZ'] == "详细地址" or checkin_data['JZDXXDZ'] == "":
    print("请输入详细地址,或者保证代码中已填写详细地址")
    sys.exit(1)

if USERNAME == "":
    print("请输入用户名,或者保证代码中已填写用户名")
    sys.exit(1)

if PASSWORD == "":
    print("请输入密码,或者保证代码中已填写密码")
    sys.exit(1)

# 经纬度随机扰动
checkin_data['LONGITUDE'] = str(round(float(checkin_data["LONGITUDE"]) + 0.0001 * random.randint(-4, 4), 4))
checkin_data['LATITUDE'] = str(round(float(checkin_data["LATITUDE"]) + 0.0001 * random.randint(-4, 4), 4))

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/87.0.4280.141 Safari/537.36 "
}


# 处理二维码
def handle_captcha(session: requests.Session):
    # 识别二维码
    def recognize_captcha(image_path):
        return ddddocr.DdddOcr(old=True, show_ad=False).classification(image_path)

    # 获取二维码图片
    def get_captcha():
        print("开始获取验证码")
        captcha_url = "https://ids.cqupt.edu.cn/authserver/getCaptcha.htl?1661054554115".format(int(time.time() * 1000))
        try:
            res = session.get(captcha_url, headers=headers)
        except Exception as e:
            print("获取验证码失败，错误信息：{}".format(e))
            raise Exception("获取验证码失败，错误信息：{}".format(e))
        print("获取验证码成功")
        return res.content

    print("开始处理验证码")
    captcha = get_captcha()
    captcha_code = recognize_captcha(captcha)
    print("验证码识别结果：{}".format(captcha_code))
    return captcha_code


# 加密提交的password，使用算法为 base64(aes(key:登录网页获取到的key, mode:CBC, iv:随机16位字符串, pkcs7padding(data:随机64位字符串+password)))
def password_encrypt(key: str, encrypt_str) -> str:
    # 随机字符串
    def randomString(length: int) -> str:
        aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
        retStr = ''
        for i in range(length):
            retStr += aes_chars[random.randint(0, len(aes_chars) - 1)]
        return retStr

    # 执行aes加密
    def getAesString(data: str, aes_key: str, iv: str, ):
        aes_key = aes_key.strip()
        aes = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        return base64.b64encode(aes.encrypt(pkcs7padding(data))).decode('utf-8')

    # 进行pkcs7padding模式的位数补全
    def pkcs7padding(text):
        """明文使用PKCS7填充 """
        bs = 16
        length = len(text)
        bytes_length = len(text.encode('utf-8'))
        padding_size = length if (bytes_length == length) else bytes_length
        padding = bs - padding_size % bs
        padding_text = chr(padding) * padding
        return (text + padding_text).encode('utf-8')

    return getAesString(randomString(64) + encrypt_str, key, randomString(16))


# 判断是否需要验证码。但是经实际证明，该接口不可靠，有时实际需要验证码该接口却返回不需要。
# 真正是否需要还是只能依靠提交post登录以后，是否出现了http_code:401 返回html出现提示：验证码错误
def need_captcha(session: requests.Session):
    print("开始判断此次登录是否需要验证码")
    url = "https://ids.cqupt.edu.cn/authserver/checkNeedCaptcha.htl?username={}&_={}".format(USERNAME,
                                                                                             int(time.time() * 1000))
    try:
        res = session.get(url, headers=headers)
    except Exception as e:
        print("判断验证码失败，错误信息：{}".format(e))
        raise Exception("判断验证码失败，错误信息：{}".format(e))
    if res.json()['isNeed']:
        print("此次登录需要验证码")
        return True
    else:
        print("此次登录不需要验证码")
        return False


# 返回 0 表示登录成功，并返回下一个接口访问地址, 1 表示登录账户或密码有误，
# 2 表示提示验证码出错，但是判断验证码是否需要的接口返回是不需要，只能下次提交时强行开启验证码识别
# 3 表示提交验证码出错，ocr验证码识别失败
# 4 表示该账户已经被冻结
def login_ids(session: requests.Session, _is_need_captcha: bool = False):
    print("开始打开登录页面")
    authserver_login_url = "https://ids.cqupt.edu.cn/authserver/login?service=http%3A%2F%2Fehall.cqupt.edu.cn%2Fpublicapp%2Fsys%2Fcyxsjkdkmobile%2F*default%2Findex.html"
    try:
        res = session.get(authserver_login_url, headers=headers)
    except Exception as e:
        print("登录失败，错误信息：{}".format(e))
        raise Exception("登录失败，错误信息：{}".format(e))

    print("登录页面打开成功，开始解析登录页面")
    tree = etree.HTML(res.text)
    form_data = dict()
    form_data['username'] = USERNAME

    form_data['password'] = str(password_encrypt(tree.xpath('// *[ @ id = "pwdEncryptSalt"]/@value')[0]
                                                 , PASSWORD))
    # 登录表单固定常量
    form_data['_eventId'] = "submit"
    form_data['cllt'] = "userNameLogin"
    form_data['dllt'] = "generalLogin"
    form_data['lt'] = ""  # 为空

    form_data['execution'] = tree.xpath('//*[@id="execution"]/@value')[0]

    form_data['captcha'] = ""  # 验证码，如果不需要验证码，留空即可

    # 判断是否需要验证码，如果出现上次返回提示验证码错误，则强行开启验证码识别，否则根据是否需要验证码的接口返回判断是否需要验证码
    if not _is_need_captcha:
        _is_need_captcha = need_captcha(session)

    if _is_need_captcha:
        form_data['captcha'] = handle_captcha(session)

    print("开始提交登录表单")
    try:
        res = session.post(authserver_login_url, form_data, headers, timeout=10, allow_redirects=False)
    except Exception as e:
        print("提交登录表单失败，登录失败，错误信息：{}".format(e))
        raise Exception("提交登录表单失败，登录失败，错误信息：{}".format(e))
    if res.status_code == 302:
        return 0, res.headers.get("location")
    if res.status_code == 401:
        tree = etree.HTML(res.text)
        tips = tree.xpath('//span[@id="showErrorTip"]/span/text()')
        tip = ""
        if tips:
            tip = tips[0]
        if tip == "您提供的用户名或者密码有误":
            return 1, ""
        if tip == "验证码错误":
            if form_data['captcha'] == "":
                return 2, ""
            return 3, ""
        if "该帐号已经被冻结" in tip:
            return 4, tip
    print("http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
    return -1, ""


# 获取cookie字段中的MOD_AUTH_CAS, 由于python request的session会自己管理cookie，所以这里访问一下，不需要自己管理cookie
def get_MOD_AUTH_CAS(url: str, session: requests.Session):
    try:
        res = session.get(url, headers=headers, allow_redirects=False)
    except Exception as e:
        print("获取MOD_AUTH_CAS失败，错误信息：{}".format(e))
        return -1
    if res.status_code == 302:
        return 0
    else:
        print("获取MOD_AUTH_CAS失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1


# 获取用户userID，实际获取ID无用，只是保证cookie字段中WEU字段的刷新。由于python request的session会自己管理cookie，所以这里只需访问一下，不需要自己管理cookie
def get_user_ID(session: requests.Session):
    url = "http://ehall.cqupt.edu.cn/publicapp/sys/cyxsjkdk/getUserId.do"
    try:
        res = session.get(url, headers=headers)
    except Exception as e:
        print("获取用户ID失败，错误信息：{}".format(e))
        return -1
    if res.status_code == 200:
        return 0
    else:
        print("获取用户ID失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1


# 获取打卡app的信息，实际返回app信息是固定的，所以不用此接口返回，更多的是保证cookie字段中WEU字段的刷新。
# 由于python request的session会自己管理cookie，所以这里只需访问一下，不需要自己管理cookie
def get_APP_info(session: requests.Session):
    url = "http://ehall.cqupt.edu.cn/publicapp/sys/funauthapp/api/getAppConfig/cyxsjkdkmobile-6578524306216816.do"
    try:
        res = session.get(url, headers=headers)
    except Exception as e:
        print("获取appInfo失败，错误信息：{}".format(e))
        return -1
    if res.status_code == 200:
        return 0
    else:
        print("获取appInfo失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1


# 获取最终打卡所需WEU
# 由于python request的session会自己管理cookie，所以这里只需访问一下，不需要自己管理cookie
def get_final_WEU(session: requests.Session):
    url = "http://ehall.cqupt.edu.cn/publicapp/sys/funauthapp/api/changeAppRole/cyxsjkdk/20220428150137410.do"
    try:
        res = session.get(url, headers=headers)
    except Exception as e:
        print("获取final_WEU失败，错误信息：{}".format(e))
        return -1
    if res.status_code == 200:
        return 0
    else:
        print("获取final_WEU失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1


# 判断今日是否已经打卡，若未打卡返回打卡相关信息，包括打卡所需：WID字段、学号字段、姓名字段
def get_today_info(session: requests.Session):
    url = "http://ehall.cqupt.edu.cn/publicapp/sys/cyxsjkdk/modules/yddjk/T_XSJKDK_XSTBXX_QUERY.do"
    form_data = {
        "TYRZM": USERNAME,
        "RQ": datetime.datetime.now().strftime("%Y-%m-%d"),
        "pageNumber": "1",
    }
    try:
        res = session.post(url, form_data, headers=headers)
    except Exception as e:
        print("获取今日打卡信息失败，错误信息：{}".format(e))
        return -1, ""
    if res.status_code != 200:
        print("获取今日打卡信息失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1, ""
    res_json = res.json()
    try:
        today_data = res_json["datas"]["T_XSJKDK_XSTBXX_QUERY"]["rows"][0]
    except Exception as e:
        print("解析今日打卡信息的返回json失败，错误信息：{}".format(e))
        return 2, ""
    if today_data["SFDK"] == "否":
        return 0, today_data
    elif today_data["SFDK"] == "是":
        return 1, today_data
    print("获取今日打卡信息失败，未知错误，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
    return -1, ""


# 从腾讯地图api解析经纬度信息，获取地址信息
def get_information_from_tencent_map(session: requests.Session, latitude, longitude):
    # 特殊情况，学校打卡页面的地区选择中，重庆市内的县不算重庆市，而算县
    def handle_address_chongqing_specification(address):
        if address['city'] == '重庆' and "县" in address['district']:
            return address['province'] + ',县,' + address['district']
        else:
            return address['province'] + ',' + address['city'] + ',' + address['district']

    print("开始从腾讯地图解析经纬度信息")
    url = "https://apis.map.qq.com/ws/geocoder/v1?location={}%2C{}&key=7IMBZ-XWMWW-D4FR5-R3NAG-G7A7S-FMBFN&output=json". \
        format(latitude, longitude, )

    try:
        res = session.get(url, headers=headers)
    except Exception as e:
        print("获取地址信息失败，错误信息：{}".format(e))
        return -1, ()
    if res.status_code != 200:
        print("获取地址信息失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1, ()
    res_json = res.json()
    try:
        location_small = res_json["result"]["address"]  # 详细地址
        location_big = res_json["result"]["ad_info"]["name"]  # 中国 重庆市 重庆市 南岸区
        address1 = res_json["result"]['address_component']  # 重庆市 重庆市 南岸区
    except Exception as e:
        print("解析地址信息的返回json失败，错误信息：{}".format(e))
        return 2, ()
    return 0, (location_small, location_big, handle_address_chongqing_specification(address1))


# 根据提交打卡数据判断是否有异常
def is_abnormal():
    if checkin_data['JZDYQFXDJ'] != '低风险' and checkin_data['JZDYQFXDJ'] != '其他':
        return '是'
    if checkin_data['SFYZGFXDQLJS'] != '无':
        return '是'
    if checkin_data['SFJCZGFXDQLJSRY'] != '无':
        return '是'
    if checkin_data['SZDJSSFYYQFS'] != '否':
        return '是'
    if checkin_data['JZDSFFXQHLSGKQY'] != '否':
        return '是'
    if checkin_data['TWSFZC'] != '是':
        return '是'
    if checkin_data['SFYGRZZ'] != '否':
        return '是'
    if checkin_data['TZRYSFYC'] != '否':
        return '是'
    if checkin_data['YKMYS'] != '绿色':
        return '是'
    return '否'


# 开始打卡
def do_checkin(session: requests.Session, address, _today_data):
    print("开始整理打卡数据")
    url = "http://ehall.cqupt.edu.cn/publicapp/sys/cyxsjkdk/modules/yddjk/T_XSJKDK_XSTBXX_SAVE.do"
    checkin_data.update({
        "XH": _today_data['XH'],
        "XM": _today_data['XM'],
        "MQJZD": address[2],
        "DKSJ":  datetime.datetime.now(tz=pytz.timezone('Asia/Shanghai')).strftime("%Y-%m-%d %H:%M:%S"),
        "RQ":  datetime.datetime.now(tz=pytz.timezone('Asia/Shanghai')).strftime("%Y-%m-%d"),
        "SFYC": is_abnormal(),
        "LOCATIONBIG": address[1],
        "LOCATIONSMALL": address[0],
        "SFTS": "是",
        "SFTQX": "是",  # 是否同区县，即你所填地址的所在区县与微信地图api获取到你所在区县是否相同
        "SFDK": "是",  # 是否打卡，那必然是
        "WID": _today_data['WID']}
    )
    print("开始提交打卡数据")
    try:
        res = session.post(url, checkin_data, headers=headers)
    except Exception as e:
        print("打卡失败,发生错误：{}".format(e))
        return -1
    if res.status_code != 200:
        print("打卡失败，http错误code:{}, 错误信息：{}".format(res.status_code, res.text))
        return -1
    return 0


# 打卡主逻辑
def main():
    # 当前已尝试登录次数
    current_try_times = 0
    # 允许尝试次数
    try_times = 5
    # 登录成功后的跳转链接
    location = ""
    # requests的session对象
    _session = ""
    # 是否需要强制开启验证码识别，默认不需要。针对判断是否需要验证码接口有时返回错误的判断
    is_need_captcha = False

    while current_try_times < try_times:
        print("第{}次尝试登录".format(current_try_times + 1))
        _session = requests.session()
        result, location = login_ids(session=_session, _is_need_captcha=is_need_captcha)
        if result == 0:
            print("登录成功")
            break
        elif result == 1:
            print("输入的账户或密码错误错误了哦,请检查")
            raise Exception("输入的账户或密码错误错误了哦,请检查")
        elif result == 2:
            print("学校服务器不讲武德，上个接口返回分明说这次不需要验证码,结果实际访问却要验证码。只能再尝试一次，下一次请求识别验证码了::>_<::")
            try_times += 1  # 增加尝试次数
            is_need_captcha = True
        elif result == 3:
            print("验证码错误,看来自动ocr识别验证码错误了,容我再试试(●'◡'●)")
            is_need_captcha = True
        elif result == 4:
            print("账号被冻结啦，学校服务器提示：{}".format(location))
        else:
            print("第{}尝试,未知错误".format(current_try_times + 1))

        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("验证码尝试次数到达最大尝试次数，脚本退出")

    # print(location)

    current_try_times = 0  # 重置尝试次数
    try_times = 3  # 允许尝试次数

    while current_try_times < try_times:
        print("第{}次尝试获取MOD_AUTH_CAS".format(current_try_times + 1))
        temp_session = _session  # 防止错误的session环境，影响下一次尝试
        result = get_MOD_AUTH_CAS(location, session=temp_session)
        if result == 0:
            print("获取MOD_AUTH_CAS成功")
            _session = temp_session
            break
        else:
            print("获取MOD_AUTH_CAS失败")
        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("获取MOD_AUTH_CAS尝试次数到达最大尝试次数，脚本退出")

    current_try_times = 0  # 重置尝试次数
    try_times = 3  # 允许尝试次数\

    while current_try_times < try_times:
        print("第{}次尝试获取appInfo".format(current_try_times + 1))
        temp_session = _session  # 防止错误的session环境，影响下一次尝试
        result = get_APP_info(session=temp_session)
        if result == 0:
            print("获取appInfo成功")
            _session = temp_session
            break
        else:
            print("获取appInfo失败")
        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("获取appInfo尝试次数到达最大尝试次数，脚本退出")

    current_try_times = 0  # 重置尝试次数
    try_times = 3  # 允许尝试次数

    while current_try_times < try_times:
        print("第{}次尝试获取final_WEU".format(current_try_times + 1))
        temp_session = _session  # 防止错误的session环境，影响下一次尝试
        result = get_final_WEU(session=temp_session)
        if result == 0:
            print("获取final_WEU成功")
            _session = temp_session
            break
        else:
            print("获取final_WEU失败")
        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("获取final_WEU尝试次数到达最大尝试次数，脚本退出")

    current_try_times = 0  # 重置尝试次数
    try_times = 3  # 允许尝试次数
    today_data = ""

    while current_try_times < try_times:
        print("第{}次尝试获取今日打卡信息".format(current_try_times + 1))
        temp_session = _session  # 防止错误的session环境，影响下一次尝试
        result, today_data = get_today_info(session=temp_session)
        if result == 0:
            print("获取今日打卡信息成功")
            _session = temp_session
            break
        elif result == 1:
            print("今日已打卡,不再打卡,脚本退出")
            raise Exception("今日已打卡,不再打卡,脚本退出")
        elif result == 2:
            print("成功请求学校服务器,但是学校服务器返回确实空空如也。")
            print("此情况大多数是由于您打卡时间过早，以至于学校服务器还未生成今日打卡信息，建议更换打卡的时间至白天。")
            print("脚本退出")
            raise Exception("成功请求学校服务器,但是学校服务器返回确实空空如也。此情况大多数是由于您打卡时间过早，以至于学校服务器还未生成今日打卡信息，建议更换打卡的时间至白天。")
        else:
            print("获取今日打卡信息失败")
        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("获取今日打卡信息尝试次数到达最大尝试次数，脚本退出")

    # print(today_data)

    current_try_times = 0  # 重置尝试次数
    try_times = 3  # 允许尝试次数
    address = ()

    while current_try_times < try_times:
        print("第{}次尝试解析经纬度信息".format(current_try_times + 1))
        temp_session = _session  # 防止错误的session环境，影响下一次尝试
        result, address = get_information_from_tencent_map(session=temp_session, latitude=checkin_data['LATITUDE'],
                                                           longitude=checkin_data['LONGITUDE'])
        if result == 0:
            print("解析经纬度信息成功")
            _session = temp_session
            break
        else:
            print("解析经纬度信息失败")
        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("解析经纬度信息尝试次数到达最大尝试次数，脚本退出")

    current_try_times = 0  # 重置尝试次数
    try_times = 3  # 允许尝试次数

    while current_try_times < try_times:
        print("第{}次尝试提交打卡数据".format(current_try_times + 1))
        temp_session = _session  # 防止错误的session环境，影响下一次尝试
        result = do_checkin(session=temp_session, address=address, _today_data=today_data)
        if result == 0:
            print("time:{},打卡成功,脚本退出".format(datetime.datetime.now(tz=pytz.timezone('Asia/Shanghai')).strftime("%Y-%m-%d %H:%M:%S")))
            break
        else:
            print("打卡失败")
        current_try_times += 1

    if current_try_times >= try_times:
        print("到达最大尝试次数，脚本退出")
        raise Exception("提交打卡数据尝试次数到达最大尝试次数，脚本退出")


'''-----------------------------通知推送函数----------------------------------'''


# WxPusher推送,文档: https://wxpusher.zjiecode.com/docs/#/?id=%e5%8f%91%e9%80%81%e6%b6%88%e6%81%af-1
def wx_pusher(title, content):
    if wx_pusher_token == "":
        print("未配置wx_pusher_token,跳过推送")
        return
    post_url = "https://wxpusher.zjiecode.com/api/send/message"
    data = {
        "appToken": wx_pusher_token,
        "content": content,
        "summary": title,
    }

    if wx_pusher_topic_ids.length > 0:
        data["topicIds"] = wx_pusher_topic_ids

    if wx_pusher_uids.length > 0:
        data["uids"] = wx_pusher_uids

    try:
        response1 = requests.post(post_url, json.dumps(data), headers={"content-type": "application/json"})
    except Exception as e:
        print('wx_pusher推送信息失败:{}'.format(str(e)))
        return
    if response1.status_code != 200:
        print('wx_pusher推送信息失败:{}'.format(response1.text))
        return
    print('wx_pusher推送信息成功')
    return


# telegram bot, 文档: https://core.telegram.org/bots/api#sendmessage
def telegram_bot(title, content):
    if telegram_bot_token == "":
        print("telegram_bot_token为空，跳过telegram_bot推送")
        return
    url = "https://api.telegram.org/bot{}/sendMessage".format(telegram_bot_token)

    data = {
        "chat_id": telegram_bot_chat_id,
        "text": "*{}*\n{}".format(title, content),
        "parse_mode": "Markdown"
    }

    try:
        response1 = requests.post(url, json.dumps(data), headers={"content-type": "application/json"})
    except Exception as e:
        print('telegram_bot推送信息失败:{}'.format(str(e)))
        return
    if response1.status_code != 200:
        print('telegram_bot推送信息失败:{}'.format(response1.text))
        return
    if not response1.json()['ok']:
        print('telegram_bot推送信息失败:{}'.format(response1.text))
        return
    print('telegram_bot推送信息成功')
    return

# push plus推送,文档: https://www.pushplus.plus/doc/guide/api.html#%E4%B8%80%E3%80%81%E5%8F%91%E9%80%81%E6%B6%88%E6%81%AF%E6%8E%A5%E5%8F%A3
def push_plus(title, content):
    if push_plus_token == "":
        print("未配置push_plus_token,跳过推送")
        return
    post_url = "http://www.pushplus.plus/send"
    data = {
        "token": push_plus_token,
        "content": content,
        "title": title,
        "topic": push_plus_topic,
        "channel": push_plus_channel,
    }

    try:
        response1 = requests.post(post_url, json.dumps(data), headers={"content-type": "application/json"})
    except Exception as e:
        print('push_plus推送信息失败:{}'.format(str(e)))
        return
    if response1.status_code != 200:
        print('push_plus推送信息失败:{}'.format(response1.text))
        return
    if response1.json()['code'] != 200:
        print('push_plus推送信息失败:{}'.format(response1.text))
        return
    print('push_plus推送信息成功')
    return


# 发送信息主函数
def send_notification(title, content):
    for notification_type in notification_types:
        if notification_type == "wx_pusher":
            wx_pusher(title, content)
        elif notification_type == "telegram_bot":
            telegram_bot(title, content)
        elif notification_type == "push_plus":
            push_plus(title, content)


'''-----------------------------主执行逻辑----------------------------------'''

try:
    main()
except Exception as e:
    if str(e) == "今日已打卡,不再打卡,脚本退出":
        send_notification("今日已打卡", "今日已打卡,不再打卡,脚本退出")
        sys.exit(0)
    else:
        send_notification("打卡失败", str(e))
        sys.exit(1)

send_notification("打卡成功", "打卡成功")
sys.exit(0)
