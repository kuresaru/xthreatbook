from re import search
import requests
import sys
import re
import json
from tokens import tokens

itoken = 0

url = 'https://api.threatbook.cn/v3/scene/ip_reputation'


def check(session, ip):
    global itoken
    if len(tokens) == 0:
        return None, None, None  # 没有可用的key
    itoken = (itoken + 1) % len(tokens)
    key = tokens[itoken]
    data = {
        'apikey': key,
        'lang': 'zh',
        'resource': ip,
    }
    r = session.post(url, data).json()
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
            return severity, locationname, judgments
    else:  # key失效 可能是次数用完了
        sys.stderr.write('\033[0;32;31m')
        sys.stderr.write(r['verbose_msg'])  # 打印错误信息
        sys.stderr.write(key)
        sys.stderr.write('\033[m\n')
        tokens.remove(key)               # 删除失效key
        return check(session, ip)        # 递归再查询


def run(filename):
    session = requests.Session()
    with open(filename, 'r') as f:
        print('IP,危害,地址,标签')
        while True:
            line = f.readline()
            if not line:
                break
            line = re.sub(r'[^0-9.]', '', line, flags=re.M)
            if line == '':
                continue
            severity, locationname, judgments = check(session, line)
            if not severity:
                sys.stderr.write('\033[0;32;31m查询失败: 没有可用的剩余次数\033[m\n')
                break
            else:
                print('%s,%s,%s,%s' % (
                    line, severity, locationname, judgments))
        session.close()
        sys.stderr.write('\033[0;32;32m查询完成\033[m\n')


if __name__ == '__main__':
    if len(sys.argv) == 2:
        run(sys.argv[1])
    else:
        print('没有输入文件!')
        print('Usage: %s <ip_file>' % sys.argv[0])
        sys.exit(1)
