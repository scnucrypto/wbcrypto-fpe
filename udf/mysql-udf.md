# MySQL 的 UDF 函数使用

## ubuntu 安装 MySQL

```asm
## 安装mysql
$ sudo apt-get update
$ sudo apt-get install mysql-server
$ sudo mysql_secure_installation

## 启动mysql
$ sudo service mysql start

## 查看mysql启动情况
$ ps -ef | grep mysql

## 直接回车 默认root 没有密码
$ sudo mysql -u root -p

## 修改root密码
> use mysql;
> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'xxxx';
> flush privileges;
```

```asm
## 卸载mysql
$ sudo apt-get remove mysql*
$ sudo apt-get purge mysql*
$ sudo apt-get autoremove
$ sudo apt-get autoclean

$ sudo rm -rf /var/lib/mysql
$ sudo rm -rf /etc/mysql
$ sudo apt-get remove --purge mysql*
$ sudo apt-get purge mysql*
$ sudo apt-get autoremove
$ sudo apt-get autoclean
```

## 使用 UDF 功能

参考博客：[udf的使用](https://www.cnblogs.com/ghc666/p/8609067.html)

### 安装 MySQL 的接口库

```asm
$ sudo apt-get update
$ sudo apt-get install build-essential libmysqlclient-dev
```

### 编写源码

```c
// reverse: 调转string函数
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

extern "C"
{
    EXPORT bool myreverse_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    EXPORT void myreverse_deinit(UDF_INIT *initid);
    EXPORT char *myreverse(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
}

EXPORT bool myreverse_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    if (args->arg_count != 1) {
        strcpy(message, "UDF reverse() requires one argument");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "UDF reverse() requires a string as argument");
        return 1;
    }

    initid->max_length = args->lengths[0];
    initid->maybe_null = args->maybe_null;
    initid->ptr = (char*)malloc(initid->max_length+1);
    if (initid->ptr == NULL) {
        strcpy(message, "Could not allocate memory for reverse()");
        return 1;
    }

    return 0;
}

EXPORT void myreverse_deinit(UDF_INIT *initid)
{
    free(initid->ptr);
}

EXPORT char *myreverse(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    if (args->args[0] == NULL) {
        *is_null = 1;
        return NULL;
    }

    char* input = args->args[0];
    unsigned long input_length = args->lengths[0];

    memcpy(initid->ptr, input, input_length);
    initid->ptr[input_length] = '\0';

    for (int i = 0; i < input_length / 2; i++) {
        char temp = initid->ptr[i];
        initid->ptr[i] = initid->ptr[input_length - i - 1];
        initid->ptr[input_length - i - 1] = temp;
    }

    *length = input_length;
    memcpy(result, initid->ptr, input_length);

    // char ret[1024];
    // sprintf(ret, "%s", result);

    return result;
}

```

函数文件：mysql.cpp

myreverse

### 编译库
```asm
## 编译库
$  g++ -shared -fPIC -I /usr/include/mysql mysql.cpp -o udf.so

## 将库移动到指定位置
$ sudo mv udf.so /usr/lib/mysql/plugin/
```

### 执行数据库命令
进行数据库执行命令
```asm
## 创建udf函数
> CREATE FUNCTION myreverse RETURNS string SONAME 'udf.so';
## 注意：返回函数名、返回参数和库名需要写对

## 移除udf函数
> DROP FUNCTION myreverse;

## 使用udf函数
> SELECT myreverse('Hello');
> SELECT cast(myreverse('Hello') as char);

## 查询安装列表
> select * from mysql.func;
```
