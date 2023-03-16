## udf透明代理使用文档

根据当前目录下的README.md部署服务

### 已存在数据表

**数据表名：student**

| 列名    | 列含义   | 列属性 | 是否脱敏 |
| ------- | -------- | ------ | -------- |
| id      | 序列号   | int    | 否       |
| name    | 名字     | string | 是       |
| age     | 年龄     | int    | 否       |
| sex     | 性别     | string | 否       |
| grade   | 年级     | string | 否       |
| phone   | 手机号   | string | 是       |
| address | 地址     | string | 是       |
| idcard  | 身份证号 | string | 是       |



### 接口文档

#### 测试是否能使用

Get请求：http://127.0.0.1:5432/hello

```curl
curl --location --request GET 'http://139.159.238.207:80/hello'
```

返回“hello证明成功”。

#### 管理员接口（访问真实数据）

Post请求：http://127.0.0.1:5432/admin/students

```curl
curl --location --request POST 'http://139.159.238.207:80/admin/students' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'sql=SELECT * FROM student limit 10;'
```

- 参数：sql
- 参数内容：输入sql语句（做了过滤，仅支持搜索语句）

#### 用户接口（访问脱敏后数据）

Post请求：http://127.0.0.1:5432/user/students

```curl
curl --location --request POST 'http://139.159.238.207:80/user/students' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'sql=SELECT * FROM student limit 10;'
```

- 参数：sql
- 参数内容：输入sql语句（做了过滤，仅支持搜索语句）