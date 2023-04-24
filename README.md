# FPE密码库

**标准：https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf**

本密码算法库提供FPE（FF1和FF3-1）的加解密接口。中国手机号、身份证号和中文字符（姓名和地址）的加解密接口。

## 概述

#### 目前支持算法

- sm3
- aes
- sm4
- wbsm4 - 白盒SM4

#### 目前支持加密模式

- CBC模式
- GCM模式
- gcmfile模式 - 基于GCM模式加解密文件模式
- FPE模式 - FF1和FF3加密格式

#### 其他能力
- 支持手机号、身份证号、姓名、地址的FPE加密



## 构建 && 安装

### 快速开始

请确保编译环境中含gcc和cmake环境，同时安装好openssl库。

运行下面命令编译库：
```asm
$ mkdir build && cd build
$ cmake ..
$ make -j
```
编译好后，{项目路径}/build/out目录下为头文件和编译库，{项目路径}/build/test目录下为可执行文件。

（可选）使用下面命令将头文件和编译库安装至系统全局环境中：

```asm
$ sudo make install
```

假设创建测试文件test.c调用环境变量中的wbcrypto编译库，请指定动态库搜索路径，例如ubuntu环境下：

```asm
$ gcc test.c -o test -lwbcrypto -Wl,-rpath="/usr/local/lib"
```



## 额外能力

### MySQL的UDF函数

在当面目录下的/udf下

### 伪透明代理服务

在当面目录下的/py下
