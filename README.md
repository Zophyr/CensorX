# CensorX

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