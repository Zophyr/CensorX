#!/usr/bin/env python
# encoding: utf-8

import sys

sys.path.insert(0, './')
sys.path.insert(0, '../')

from CensorX import censorx

inputFile = open("./test.cer", "rb")

decoder = censorx.decoder()

decoder.scan(inputFile)

decoder.print()
