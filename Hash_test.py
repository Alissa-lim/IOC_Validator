import requests
import html2text
import re
import socket
import sys
import validators
import subprocess
from bs4 import BeautifulSoup
from lxml import html


def detect_hash(hash_code):
    hash_decode = 'python hash-id.py ' + hash_code
    p = subprocess.Popen(hash_decode, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    output = out.decode("utf-8")
    if 'Possible Hashs' in output:
        return (hash_code + ":" + output.split(" ")[2][:-5])
    else:
        return False


test_hash = ["150990c01ce3198086c91576d323046d5cd72c3846bb006c96ba4bbb2fea819e0c0be618b54da576daca212f10340c57ab2f09b46666f1e2c15056ae77b22527", " ", "TEST", "b56a0874ccca2700e17bbb5c3aea067c"]

for hashes in test_hash:
    checkHash = detect_hash(hashes)
    if(str(checkHash) != "False"):
            print(checkHash + "\n")
