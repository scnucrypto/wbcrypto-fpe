# 一些脚本

### 环境
安装python3.7及以上版本

## 创建数据表
使用目录下的create_student.sql创建数据表
```asm
$ mysql -uroot -p
## mysql中执行
> CREATE DATABASE test;
> USE test;
> SOURCE /path/to/create_student.sql;
```

## 生成随机数据
```asm
$ pip install -r requirements.insert.txt
$ python insert_mysql.py
```
修改password为数据库密码

修改num_inserts为指定生成数量

## 简单的透明代理
```asm
$ pip install -r requirements.proxy.txt
$ python trans_proxy.py
```
修改password为数据库密码
### 测试
```asm
## 测试连通，获取到“hello”证明连通
$ curl http://localhost:5432/hello
## 测试获取数据库数据
$ curl --data "sql=SELECT * FROM student limit 1" http://localhost:5432/admin/students
$ curl --data "sql=SELECT * FROM student limit 1" http://localhost:5432/user/students
```

### 运行在服务器
```asm
$ pip install gunicorn
$ gunicorn trans_proxy:app -b 0.0.0.0:5432
```
在/etc/systemd/system目录下创建trans_proxy.service并编写：
```asm
[Unit]
Description=Trans proxy
After=network.target

[Service]
User=xie
Group=xie
WorkingDirectory=/home/wbcrypto-fpe/py/  ##改成指定目录
ExecStart=/usr/local/bin/gunicorn trans_proxy:app -b 0.0.0.0:5432
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```
```asm
## 后台执行
$ sudo systemctl start trans_proxy
$ sudo systemctl enable trans_proxy

## 检查状态
$ sudo systemctl status trans_proxy
```
记得配置nginx反向代理！