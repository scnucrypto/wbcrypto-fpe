import random
import mysql.connector
import datetime
from faker import Faker

# 创建 MySQL 数据库连接
mydb = mysql.connector.connect(
    host="127.0.0.1",
    user="root",
    password="123",
    database="test"
)

# 创建 MySQL 数据库游标
mycursor = mydb.cursor()

# 准备 SQL 插入语句
sql = "INSERT INTO student (name, age, sex, grade, phone, address, idcard) VALUES (%s, %s,%s, %s, %s, %s, %s)"

fake = Faker('zh_CN')

# 中国移动号段
china_mobile_prefix = ['134', '135', '136', '137', '138', '139', '150', '151', '152', '157', '158', '159', '182', '183',
                       '184', '187', '188', '147', '178']
# 中国联通号段
china_unicom_prefix = ['130', '131', '132', '155', '156', '185', '186', '145', '176']
# 中国电信号段
china_telecom_prefix = ['133', '153', '180', '181', '189', '177']

# 随机生成手机号
def generate_mobile_number():
    # 从三个运营商的号段中随机选择一个
    prefix = random.choice(china_mobile_prefix + china_unicom_prefix + china_telecom_prefix)
    # 在号段后面随机生成 8 位数字
    suffix = ''.join(str(random.randint(0, 9)) for _ in range(8))
    # 返回完整的手机号
    return prefix + suffix

# 随机生成一个区域码（6 位数）
def random_area_code():
    # 区域码第一位是 1-9
    first = random.randint(1, 9)
    # 区域码第二位到第六位是 0-9
    other = ''.join(str(random.randint(0, 9)) for _ in range(5))
    return int(str(first) + other)

# 随机生成一个生日（8 位数）
def random_birthday():
    start_date = datetime.datetime.strptime('1970-01-01', '%Y-%m-%d')
    end_date = datetime.datetime.strptime('2008-12-31', '%Y-%m-%d')
    days = (end_date - start_date).days
    birthday = start_date + datetime.timedelta(days=random.randint(0, days))
    return int(birthday.strftime('%Y%m%d'))

# 随机生成一个顺序码（3 位数）
def random_order_code():
    return random.randint(0, 999)

# 计算校验码
def calculate_check_code(number):
    weight_list = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_code_list = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    check_code = sum([int(number[i]) * weight_list[i] for i in range(len(number))]) % 11
    return check_code_list[check_code]

# 生成一个随机的中国身份证号
def generate_id_card():
    area_code = random_area_code()
    birthday = random_birthday()
    order_code = random_order_code()
    number = str(area_code) + str(birthday) + str(order_code).zfill(3)
    check_code = calculate_check_code(number)
    return number + check_code

# 定义插入数据的数量
num_inserts = 1000
# 生成随机数据并插入到表中
for i in range(num_inserts):
    # 生成随机数据
    # id = i + 1
    name = fake.name()
    sex = random.choice(['男', '女'])
    age = random.randint(18, 26)
    grade = random.choice(['大一', '大二', '大三', '大四', '研一', '研二', '研三'])
    phone = generate_mobile_number()
    idcard = generate_id_card()
    # 删除后面的邮编和门牌号
    address = fake.address()[:-9]

    # 插入数据到表中
    val = (name, age, sex, grade, phone, address, idcard)
    mycursor.execute(sql, val)
# 提交更改到数据库
mydb.commit()
# 输出插入数据的数量
print(mycursor.rowcount, "插入了", num_inserts, "条数据到表中")
