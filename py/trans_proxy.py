from flask import Flask, request, jsonify
import mysql.connector
import re

app = Flask(__name__)

# 设置数据库连接参数
config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '123',
    'database': 'test'
}

stud_fields = ['id', 'name', 'age', 'sex', 'grade', 'phone', 'address', 'idcard']

# 连接数据库
cnx = mysql.connector.connect(**config)
# 创建游标对象
cursor = cnx.cursor()

def get_mysql_version():
    cursor.execute('SELECT VERSION()')
    mysql_version = cursor.fetchone()[0]
    print(f'connected to MySQL version: {mysql_version}')
    if mysql_version.startswith('5.'):
        return 5
    elif mysql_version.startswith('8.'):
        return 8

# 处理 SQL 语句，添加 UDF 函数
def process_sql(sql):
    # 使用正则表达式匹配 SELECT *，并替换成需要的字段列表
    sql = re.sub(r'SELECT\s+\*\s+', 'SELECT ' + ', '.join(stud_fields) + ' ', sql, flags=re.IGNORECASE)
    version = get_mysql_version()
    fields = {
        'phone': "fpe(phone, 'phone', '123xxxx1234') as phone",
        'address': "fpe(address, 'address') as address",
        'name': "fpe(name, 'name') as name",
        'idcard': "fpe(idcard, 'idcard', '1111xxxxxxxxxx1234') as idcard"
    }  # 定义特殊字段及其 UDF 函数
    if version == 8:
        fields = {
            'phone': "cast(fpe(phone, 'phone', '123xxxx1234') as char) as phone",
            'address': "cast(fpe(address, 'address') as char) as address",
            'name': "cast(fpe(name, 'name') as char) as name",
            'idcard': "cast(fpe(idcard, 'idcard', '1111xxxxxxxxxx1234') as char) as idcard"
        }  # 定义特殊字段及其 UDF 函数
    for field, udf in fields.items():
        if field in sql.lower():
            sql = sql.replace(field, udf)
    return sql

@app.route('/hello')
def hello():
    return "hello"

@app.route('/admin/students', methods=['POST'])
def get_admin_students():
    # 执行查询语句
    sql = request.form.get('sql')
    # 检查 SQL 语句是否是 select, insert, delete, update 类型语句
    # if not sql.lower().startswith('select') and not sql.lower().startswith('insert') and not sql.lower().startswith('delete') and not sql.lower().startswith('update'):
    #     return jsonify({'error': 'only statements are allowed: select, insert, delete, update'}), 400
    # 检查 SQL 语句是否是 SELECT 类型语句
    if not sql.lower().startswith('select'):
        return jsonify({'error': 'only SELECT statements are allowed.'}), 400
    print("[admin] 执行的sql语句为：",sql)
    cursor.execute(sql)
    # 将结果转换为 JSON 格式
    results = []
    for row in cursor.fetchall():
        result = {}
        for i, col in enumerate(cursor.column_names):
            if isinstance(row[i], bytearray):
                # 将bytearray转换为字符串
                result[col] = row[i].decode('utf-8')
            else:
                result[col] = row[i]
        results.append(result)
    return jsonify(results)

@app.route('/user/students', methods=['POST'])
def get_user_students():
    sql = request.form.get('sql')
    if not sql.lower().startswith('select'):
        return jsonify({'error': 'only SELECT statements are allowed.'}), 400
    sql = process_sql(sql)
    print("[user] 执行的sql语句为：",sql)
    cursor.execute(sql)
    results = []
    for row in cursor.fetchall():
        result = {}
        for i, col in enumerate(cursor.column_names):
            result[col] = row[i]
        results.append(result)
    return jsonify(results)

if __name__ == '__main__':
    app.run(port=5432)
    # 关闭游标和连接
    cursor.close()
    cnx.close()
