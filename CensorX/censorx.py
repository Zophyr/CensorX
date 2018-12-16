#!/usr/bin/env python
# encoding: utf-8

"""
    CensorX
    ~~~~~~~~~~~~~
    check 509
"""

import collections

# bytes 类型
from builtins import bytes

from enum import IntEnum

import sys
import binascii

from barber import barber


# 定义 asn1 数据类型
class Numbers(IntEnum):
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    Enumerated = 0x0a
    UTF8String = 0x0c
    Sequence = 0x10
    Set = 0x11
    PrintableString = 0x13
    IA5String = 0x16
    UTCTime = 0x17
    UnicodeString = 0x1e

# 定义 enum


class Types(IntEnum):
    Constructed = 0x20
    Primitive = 0x00

# 定义简单类型


class Classes(IntEnum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xc0


# 定义 tag id 匹配
tag_id_to_string_map = {
    Numbers.Boolean: "BOOLEAN",
    Numbers.Integer: "INTEGER",
    Numbers.BitString: "BIT STRING",
    Numbers.OctetString: "OCTET STRING",
    Numbers.Null: "NULL",
    Numbers.ObjectIdentifier: "OBJECT",
    Numbers.PrintableString: "PRINTABLESTRING",
    Numbers.IA5String: "IA5STRING",
    Numbers.UTCTime: "UTCTIME",
    Numbers.Enumerated: "ENUMERATED",
    Numbers.Sequence: "SEQUENCE",
    Numbers.Set: "SET"
}

# 定义四种基本类型匹配
class_id_to_string_map = {
    Classes.Universal: "U",
    Classes.Application: "A",
    Classes.Context: "C",
    Classes.Private: "P"
}

object_id_to_string_map = {
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",

    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.42": "givenName",

    "1.2.840.113549.1.9.1": "emailAddress",

    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.15": "X509v3 Key Usage",
    "2.5.29.16": "X509v3 Private Key Usage Period",
    "2.5.29.17": "X509v3 Subject Alternative Name",
    "2.5.29.18": "X509v3 Issuer Alternative Name",
    "2.5.29.19": "X509v3 Basic Constraints",
    "2.5.29.30": "X509v3 Name Constraints",
    "2.5.29.31": "X509v3 CRL Distribution Points",
    "2.5.29.32": "X509v3 Certificate Policies Extension",
    "2.5.29.33": "X509v3 Policy Mappings",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.36": "X509v3 Policy Constraints",
    "2.5.29.37": "X509v3 Extended Key Usage",
}

# 算法
algorithm_id_to_string_map = {
    '1.2.840.10040.4.1': 'DSA',
    "1.2.840.10040.4.3": "sha1DSA",
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.2": "md2RSA",
    "1.2.840.113549.1.1.3": "md4RSA",
    "1.2.840.113549.1.1.4": "md5RSA",
    "1.2.840.113549.1.1.5": "sha1RSA",
    '1.3.14.3.2.29': 'sha1RSA',
    '1.2.840.113549.1.1.13': 'sha512RSA',
    '1.2.840.113549.1.1.11': 'sha256RSA'
}

# 版本号
version_id_to_string_map = {
    0: 'V1',
    1: 'V2',
    2: 'V3'
}

# 时间
time_id_to_string_map = {
    0: 'not before: ',
    1: 'not after: '
}


# 使用 collections 定义 Tag 对象
# 描述 数据类型、长度、数据
# Tag = collections.namedtuple('Tag', 'nr typ cls')
Tag = collections.namedtuple('Tag', ["nr", "typ", "cls"])


class decoder(object):

    # 初始化
    def __init__(self):
        # 缓冲区
        self.m_stack = None

        # 记录当前 Tag 类型
        self.m_tag = None

        # 是否传入数据
        self.m_scan = False

        # 储存结果
        self.result = ""

        # 记录输出
        self.count = 4

        # 记录时间输出

        self.time_count = 2

    # 开始解析
    # 传入相关参数
    def scan(self, data):
        if not isinstance(data, bytes):
            try:
                data = data.read()
            except OverflowError:
                print("WRONG INPUT!")

        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None
        self.m_scan = True

    # 读取 Tag
    def peek(self):
        if self._end_of_input():
            return None

        if self.m_tag is None:
            self.m_tag = self._read_tag()

        return self.m_tag

    # 识别 Tag 含义
    def analyze(self):
        if self._end_of_input():
            return None

        tag = self.peek()
        length = self._read_length()
        value = self._read_value(tag.nr, length)
        self.m_tag = None
        return tag, value

    # 解析完成
    def eof(self):
        return self._end_of_input()

    # load
    def load(self):
        tag = self.peek()

        if tag.typ != Types.Constructed:
            return

        length = self._read_length()
        bytes_data = self._read_bytes(length)
        self.m_stack.append([0, bytes_data])
        self.m_tag = None

    # unload
    def unload(self):  # type: () -> None
        if len(self.m_stack) == 1:
            return

        del self.m_stack[-1]
        self.m_tag = None

    def _read_tag(self):
        byte = self._read_byte()

        cls = byte & 0xc0
        typ = byte & 0x20
        nr = byte & 0x1f

        if nr == 0x1f:
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break

        return Tag(nr=nr, typ=typ, cls=cls)

    def _read_length(self):

        byte = self._read_byte()

        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                return

            bytes_data = self._read_bytes(count)
            length = 0
            for byte in bytes_data:
                length = (length << 8) | int(byte)
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte

        return length

    # 转换数据类型，变成人看得懂的
    def _read_value(self, nr, length):
        bytes_data = self._read_bytes(length)

        if nr == Numbers.Boolean:
            value = self._decode_boolean(bytes_data)
        elif nr in (Numbers.Integer, Numbers.Enumerated):
            value = self._decode_integer(bytes_data)
        elif nr == Numbers.OctetString:
            value = self._decode_octet_string(bytes_data)
        elif nr == Numbers.Null:
            value = self._decode_null(bytes_data)
        elif nr == Numbers.ObjectIdentifier:
            value = self._decode_object_identifier(bytes_data)
        elif nr in (Numbers.PrintableString, Numbers.IA5String, Numbers.UTCTime):
            value = self._decode_printable_string(bytes_data)
        else:
            value = bytes_data
        return value

    # 读取一个 bytes
    def _read_byte(self):
        index, input_data = self.m_stack[-1]

        byte = input_data[index]

        self.m_stack[-1][0] += 1
        return byte

    # 读取一串 bytes
    def _read_bytes(self, count):
        index, input_data = self.m_stack[-1]

        bytes_data = input_data[index:index + count]

        if len(bytes_data) != count:
            return

        self.m_stack[-1][0] += count
        return bytes_data

    # 判断时候结束 eof
    def _end_of_input(self):
        index, input_data = self.m_stack[-1]
        return index == len(input_data)

    # 转换格式 boolean
    @staticmethod
    def _decode_boolean(bytes_data):
        if len(bytes_data) != 1:
            return

        if bytes_data[0] == 0:
            return False
        return True

    # 转换格式 integer
    @staticmethod
    def _decode_integer(bytes_data):
        values = [int(b) for b in bytes_data]

        negative = values[0] & 0x80

        if negative:
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    # 转换格式 string
    @staticmethod
    def _decode_octet_string(bytes_data):
        return bytes_data

    # 转换格式 null
    @staticmethod
    def _decode_null(bytes_data):
        if len(bytes_data) != 0:
            return

        return None

    # 转换格式 object
    @staticmethod
    def _decode_object_identifier(bytes_data):
        result = []
        value = 0

        for i in range(len(bytes_data)):
            byte = int(bytes_data[i])
            if value == 0 and byte == 0x80:
                return

            value = (value << 7) | (byte & 0x7f)

            if not byte & 0x80:
                result.append(value)
                value = 0

        if len(result) == 0 or result[0] > 1599:
            return

        result = [result[0] // 40, result[0] % 40] + result[1:]
        result = list(map(str, result))
        return str('.'.join(result))

    # 转换格式 string
    @staticmethod
    def _decode_printable_string(bytes_data):
        return bytes_data.decode('utf-8')

    # 转换 tag id
    @staticmethod
    def tag_id_to_string(identifier):
        if identifier in tag_id_to_string_map:
            return tag_id_to_string_map[identifier]
        return '{:#02x}'.format(identifier)

    # 转换 class
    @staticmethod
    def class_id_to_string(identifier):
        if identifier in class_id_to_string_map:
            return class_id_to_string_map[identifier]
        raise ValueError('Illegal class: {:#02x}'.format(identifier))

    # 转换 object
    @staticmethod
    def object_identifier_to_string(identifier):
        if identifier in object_id_to_string_map:
            return object_id_to_string_map[identifier]
        return identifier

    # 转换 string
    @staticmethod
    def value_to_string(self, tag_number, value):
        if tag_number == Numbers.ObjectIdentifier:
            return self.object_identifier_to_string(value)
        elif isinstance(value, bytes):
            return binascii.hexlify(value).upper().decode()
        elif isinstance(value, str):
            return value
        else:
            return repr(value)

    def print(self, index=0):
        if self.m_scan == False:
            print("Please use Scan first!")
            return

        while not self.eof():
            tag = self.peek()
            if tag.typ == Types.Primitive:
                tag, value = self.analyze()
                if self.count == 4:
                    print("Version: {}".format(
                        version_id_to_string_map[value]))
                    self.count -= 1
                elif self.count == 3:
                    print("Serial Number: {}".format(value))
                    self.count -= 1
                elif self.tag_id_to_string(tag.nr) == "OBJECT" and value in algorithm_id_to_string_map:
                    print('Algorithm: {}'.format(
                        algorithm_id_to_string_map[value]))
                elif self.tag_id_to_string(tag.nr) == "OBJECT" and self.value_to_string(self, tag.nr, value) == 'countryName' and self.count == 2:
                    print('Issuer')
                    print('{}: '.format(self.value_to_string(self, tag.nr, value)), end='')
                    self.count -= 1
                elif self.tag_id_to_string(tag.nr) == "OBJECT" and self.value_to_string(self, tag.nr, value) == 'countryName' and self.count == 1:
                    print('Subject')
                    print('{}: '.format(self.value_to_string(
                        self, tag.nr, value)), end='')
                    self.count -= 1
                elif self.tag_id_to_string(tag.nr) == "UTCTIME" and self.time_count == 2:
                    time_str = self.value_to_string(self, tag.nr, value)
                    print('Validity not before (UTC): 20{}.{}.{} {}:{}:{} '.format(time_str[0:2], time_str[2:4],
                                                                                   time_str[4:6], time_str[6:8], time_str[8:10], time_str[10:12]))
                    self.time_count -= 1
                elif self.tag_id_to_string(tag.nr) == "UTCTIME" and self.time_count == 1:
                    time_str = self.value_to_string(self, tag.nr, value)
                    print('Validity not after (UTC): 20{}.{}.{} {}:{}:{} '.format(time_str[0:2], time_str[2:4],
                                                                                  time_str[4:6], time_str[6:8], time_str[8:10], time_str[10:12]))
                    self.time_count -= 1
                elif self.tag_id_to_string(tag.nr) == "OBJECT":
                    print('{}: '.format(self.value_to_string(
                        self, tag.nr, value)), end='')
                elif self.tag_id_to_string(tag.nr) == "PRINTABLESTRING":
                    print(self.value_to_string(self, tag.nr, value))
                elif self.tag_id_to_string(tag.nr) == "NULL":
                    continue
                else:
                    print(barber.cut(self.value_to_string(self, tag.nr, value)))
            elif tag.typ == Types.Constructed:
                self.load()
                self.print(index + 2)
                self.unload()
