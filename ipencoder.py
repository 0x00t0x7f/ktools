#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
简单IP加密模块
"""
import os
import random
from base64 import b64encode, b64decode

__version__ = "0.0.1"
__build__ = 0x0001
__author__ = "UNKNOWN"

SALT = "unknown!"


def sample_ip_valid(ip):
    try:
        ip_split = ip.split(".")
        assert len(ip_split) == 4
        for n in ip_split:
            assert 0 <= int(n) < 255
        else:
            return 1
    except:
        return 0


def patch_split(data, split_nums=2):
    before_index = 0
    for index, item in enumerate(data):
        if index and index % split_nums == 0:
            yield data[before_index:index]
            before_index = index
    else:
        yield data[before_index:]


def sample_ip_handle(ip):
    if not isinstance(ip, bytes):
        ip = ip.encode("utf-8")
    b64 = b64encode(ip).decode()
    b64 = "".join(chr(ord(s) + 13) for s in b64)
    hex_string = "".join([s.encode().hex() for s in b64])
    return hex_string


def sample_ip_handle_reverse(hex):
    rascii = "".join([chr(int(s, 16)) for s in patch_split(hex)])
    b64 = "".join(chr(ord(s) - 13) for s in rascii)
    return b64decode(b64.encode("utf-8"))


def ip_encode(string, keys):
    if sample_ip_valid(string):
        random.seed(keys)
        encrypt = "".join([str(ord(s) ^ random.randint(0, 255)) + "," for s in string])
        return sample_ip_handle(encrypt.strip(","))
    return 0


def ip_decode(string, keys):
    random.seed(keys)
    string = sample_ip_handle_reverse(string)
    print(string)
    if isinstance(string, bytes):
        string = string.decode()
    string = string.split(",")
    decrypt = "".join([chr(int(s) ^ random.randint(0, 255)) for s in string])
    return decrypt


def write_file(path):
    """
    :param path: ip列表文件
    :return: 输出的json文件
    """
    if os.path.exists(path):
        try:
            fconf = open("ipconfig.txt", "wt")
            with open(path, "rt") as fp:
                fdata = fp.readlines()
            for ip in fdata:
                ip = ip.strip()
                ip_encrypt = ip_encode(ip, SALT)
                if ip_encrypt == 0:
                    continue
                fconf.write(ip_encrypt+"\n")
        except Exception as why:
            print(why)
        finally:
            fconf.close()
    else:
        print("file path error")


if __name__ == "__main__":
    for ip in ["172.27.1.57", "172.27.2.85", "255.254.212.110", "10.3.0.7", "192.168.70.1"]:
        ENCRYPT = ip_encode(ip, SALT)
        print("加密串：%s" % ENCRYPT)
        if ENCRYPT != 0:
            result = ip_decode(ENCRYPT, SALT)
            print("解密IP： %s" % result)
            assert ip == result
