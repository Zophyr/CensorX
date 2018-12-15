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


# 使用 collections 定义 Tag 对象
# 描述 数据类型、长度、数据
# Tag = collections.namedtuple('Tag', 'nr typ cls')
Tag = collections.namedtuple('Tag', ["nr", "typ", "cls"])


class CensorX(object):

    # 初始化
    def __init__(self):
        # 缓冲区
        self.m_stack = None

        # 记录当前 Tag 类型
        self.m_tag = None

    # 开始解析
    # 传入相关参数
    def scan(self, data):
        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None

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
    def enter(self):
        tag = self.peek()

        if tag.typ != Types.Constructed:
            return

        length = self._read_length()
        bytes_data = self._read_bytes(length)
        self.m_stack.append([0, bytes_data])
        self.m_tag = None

    # unload
    def leave(self):  # type: () -> None
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
