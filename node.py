import requests
import re
import json
from flask import Flask

app = Flask(__name__)
session = requests.Session()

with open('apikey.txt', 'r') as f:
    global apikey
    apikey = f.readline()

print('apikey=%s' % apikey)


@app.route('/<ip>')
def get(ip):
    if not re.match(r'^(([0-9]{1,3}).){3}[0-9]{1,3}$', ip, re.I):
        return 'Bad IP', 400
    r = session.post('https://api.threatbook.cn/v3/scene/ip_reputation', {
        'apikey': apikey,
        'lang': 'zh',
        'resource': ip,
    }).json()
    if r['response_code'] == 0:  # 数据正常
        dr = r['data']
        for name in dr:  # name是查询的ip 这个循环只有一次
            info = dr[name]
            severity = info['severity']     # 危害程度  严重/高/中/低/无危胁
            judgmentsarr = info['judgments']   # 类型数组
            ibasic = info['basic']
            blocation = ibasic['location']
            carrier = ibasic['carrier']       # 运营商
            country = blocation['country']    # 国家
            province = blocation['province']  # 省
            city = blocation['city']          # 城市
            locationname = '%s %s %s %s' % (country, province, city, carrier)
            locationname = re.sub(r' +', '/', locationname)
            judgments = '/'
            for j in judgmentsarr:
                judgments = '%s%s/' % (judgments, j)
            return json.dumps({
                'ip': ip,
                'severity': severity,
                'locationname': locationname,
                'judgments': judgments,
            }, ensure_ascii=False)
    return 'Failed', 503


if __name__ == '__main__':
    app.run()
