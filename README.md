# xthreatbook
api批量查询微步在线威胁情报

# usage

## node

0. 安装依赖 pip3 install requests flask
1. 在apikey.txt里写入对应帐号的apikey
2. 运行 python3 node.py

## client

0. 安装依赖 pip3 install requests
1. 配置环境 在nodelist.txt写所有node的访问url 一行一个 例http://192.168.1.2:5000
2. 把要查询的ip写到文件(例test.txt),一行一个地址
3. 运行 python3 xthreatbook.py test.txt
