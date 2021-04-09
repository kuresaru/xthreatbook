import requests
import sys
import re
import random
import time

nodelist = []
index = 0

with open('nodelist.txt', 'r') as f:
    line = f.readline()
    while line:
        n = line.splitlines()[0]
        nodelist.append(n)
        sys.stderr.write('\033[1;34m加载节点%s\033[m\n' % n)
        line = f.readline()


def check(session, ip):
    global index
    if len(nodelist) == 0:
        return None  # 没有可用的node
    index = (index + 1) % len(nodelist)
    node = nodelist[index]
    url = node + '/' + ip
    r = session.get(url)
    if r.status_code == 200:  # 数据正常
        r = r.json()
        r['node'] = node
        return r  # node ip severity locationname judgments
    else:  # 可能是次数用完了  FIXME: 输入无效导致失败也会当成不可用
        sys.stderr.write('\033[0;32;31m节点%s不可用:%s\033[m\n',
                         (node, r.status_code))  # 打印错误信息
        nodelist.remove(node)       # 删除失效node
        return check(session, ip)   # 递归再查询


def run(filename):
    session = requests.Session()
    with open(filename, 'r') as f:
        print('节点,IP,危害,地址,标签')
        while True:
            line = f.readline()
            if not line:
                break
            line = re.sub(r'[^0-9.]', '', line, flags=re.M)
            if line == '':
                continue
            r = check(session, line)
            if not r:
                sys.stderr.write('\033[0;32;31m查询失败: 没有可用的节点\033[m\n')
                break
            else:
                print('%s,%s,%s,%s,%s' % (
                    r['node'],
                    r['ip'],
                    r['severity'],
                    r['locationname'],
                    r['judgments']))
            time.sleep(random.randint(300, 800) / 1000.0)  # 限速循环
        session.close()
        sys.stderr.write('\033[0;32;32m查询完成\033[m\n')


if __name__ == '__main__':
    if len(sys.argv) == 2:
        run(sys.argv[1])
    else:
        print('没有输入文件!')
        print('Usage: %s <ip_file>' % sys.argv[0])
        sys.exit(1)
