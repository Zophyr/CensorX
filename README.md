# CensorX · [![Build Status](https://travis-ci.com/Zophyr/CensorX.svg?branch=master)](https://travis-ci.com/Zophyr/CensorX)

⚖️ X.509 数字证书解析

## 快速使用

**安装**

```shell
$ pip install censorx
```

**使用**

```python
>>> from censorx import censorx
>>>
>>> inputFile = open("./test.cer", "rb")
>>>
>>> decoder = censorx.decoder()
>>> decoder.scan(inputFile)
>>> decoder.print()
Version: V3
Serial Number: 2
Algorithm: sha1RSA
Issuer
countryName: US
organizationName: Apple Inc.
················
······more······
················
```

## 什么是 X.509 ?

X.509 是密码学里公钥证书的格式标准。

X.509 是ITU-T标准化部门基于他们之前的ASN.1定义的一套证书标准。

也就是说，了解 X.509 就是了解 ASN.1 。

## X.509 证书结构

```shell
证书
├── 版本号
├── 序列号
├── 签名算法
├── 证书有效期
│   ├── 此日期前无效
│   └── 此日期后无效
├── 主题
├── 主题公钥信息
│   ├── 公钥算法
│   └── 主题公钥
├── 颁发者唯一身份信息（可选项）
├── 主题唯一身份信息（可选项）
├── 扩展信息（可选项）
│   ├── ······
│   └── ······
├── 证书签名算法
└── 数字签名
```

## X.509 证书解析

一般来说，我们将 `cer` 文件读取进来，转化成 16 进制，会是这个样子：

```shell
Before: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

3082 04bb 3082 03a3 a003 0201 0202 0102
300d 0609 2a86 4886 f70d 0101 0505 0030
6231 0b30 0906 0355 0406 1302 5553 3113
3011 0603 5504 0a13 0a41 7070 6c65 2049
6e63 2e31 2630 2406 0355 040b 131d 4170
706c 6520 4365 7274 6966 6963 6174 696f
6e20 4175 7468 6f72 6974 7931 1630 1406
0355 0403 130d 4170 706c 6520 526f 6f74
2043 4130 1e17 0d30 3630 3432 3532 3134
3033 365a 170d 3335 3032 3039 3231 3430
3336 5a30 6231 0b30 0906 0355 0406 1302
············
····more····
············
```

下面我们使用 RFC 2459 Internet X.509 Public Key Infrastructure标准文档中摘取的一个证书作为例子。

| 地址 | 内容 | 含义 |
| :---: | :--- | :--- |
| 0000 | 30 82 02 b7 | SEQUENCE类型(30) 数据块长度字节为2(82), 长度为695 (02 b6) |
| 0004 | 30 82 02 77 | SEQUENCE类型, 长度631 |
| 0008 | a0 03 | Version::特殊内容-证书版本(a0),长度3 |
| 0010 | 02 01 02 | INTEGER 2 version::整数类型(02),长度1,版本3(2) |
| 0013 | 02 01 11 | INTEGER 17 serialNumber::整数类型(02),长度1,证书序列号 17 |
| 0016 | 30 09 | SEQUENCE  signature::SEQUENCE类型(30),长度9 |
| 0018 | 06 07 | signature::OBJECT IDENTIFIER类型,长度7 |
| 👆 | 2a 86 48 ce 38 04 03 | dsa with sha算法, OID 1.2.840.10040.4.3 |
| 0027 | 30 2a | SEQUENCE 以下的数据块表示issuer信息,长度为42 |

