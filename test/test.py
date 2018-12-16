#!/usr/bin/env python
# encoding: utf-8

import sys
from barber import barber

sys.path.insert(0, './')
sys.path.insert(0, '../')

from censorx import censorx

inputFileOne = open("./test.cer", "rb")

inputFileTwo = open("./test.cer", "rb")

print("\nBefore: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")

print(barber.cut(inputFileOne.read().hex()))

print("\nAfter: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")

decoder = censorx.decoder()

decoder.scan(inputFileTwo)

decoder.print()
