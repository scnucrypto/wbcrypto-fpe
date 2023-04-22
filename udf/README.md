# MySQL-FPE

## 构建 && 安装

### 预备操作

#### 环境准备

```asm
## 安装mysql和mysql开发库
$ sudo apt-get update && sudo apt upgrade
$ sudo apt install mysql-server-5.7
$ sudo apt-get install build-essential libmysqlclient-dev
```

#### 编译wbcrypto-fpe密码库
```asm
## 在目录wbcrypt-fpe/下编译库
$ mkdir build && cd build
$ cmake ..
$ make -j
$ sudo make install
$ sudo cp -f ./out/libwbcrypto.so /usr/lib/
```

### 构建
```asm
## 在当前目录udf/下编译库
$ mkdir build && cd build
$ cmake ..
$ make -j
$ sudo make install
```
MySQL8版本将其中cmake命令改为：
```asm
$ cmake -DMYSQL8=1 ..
```
如果报错找不到libmysqlclient路径，尝试将CMakelists.txt中/usr/lib改为/usr/lib64
```
输入mysql -uroot -p进行数据库操作界面：
```asm
## 创建udf函数
> CREATE FUNCTION fpe RETURNS string SONAME 'udf.so';

## 移除udf函数
> DROP FUNCTION fpe;

## 查询安装列表
> select * from mysql.func;
```

### 使用
```asm
## mysql 5.x版本
> SELECT fpe('13912345678','phone', '134****5678');
> SELECT fpe('441412345678901234','idcard', '4414**********1234');
> SELECT fpe('广东省广州市天河区华南师范大学','address', '**省**市**区*****');

## mysql 8.x版本
> SELECT cast(fpe('13912345678','phone', '134****56788') as char);

## 使用fpe查询数据表（假设存在test数据表，数据列为phone）
> SELECT fpe(phone,'phone', '134****5678') from test limit 100;
```

### 测试

#### 测试速度
```asm
## 查询10000条数据的耗时
> SELECT *, UNIX_TIMESTAMP() - @start_time AS elapsed_time FROM test LIMIT 10000;

## 查询fpe函数速度
> SELECT BENCHMARK(1000000, fpe('13912345678','phone', '134****5678'));
```

```asm
## 例子
> SELECT phone, UNIX_TIMESTAMP() - @start_time AS elapsed_time FROM test LIMIT 100000;
> SELECT fpe(phone,'phone','134****5678'), UNIX_TIMESTAMP() - @start_time AS elapsed_time FROM test LIMIT 100000;

> SELECT BENCHMARK(100000, fpe('13912345678','phone', '134****5678'));
```

