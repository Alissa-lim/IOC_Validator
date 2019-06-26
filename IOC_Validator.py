#File name
#Registry --> HKLM, HKCR, HKCU,HKCC,HK_Users
#File Path --> check by /
#Process Name --> .exe
#backdoor name?
# Check if URL is valid by response code 
#Parse text from URL (Do separately then compare efficiency)
#IP address: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

import requests
import html2text
import re
import socket 
import sys
import validators
import subprocess
from bs4 import BeautifulSoup
from lxml import html

def is_site_alive(url):
    request = requests.get(url)
    if request.status_code == 200:
        return True 
    else:
        return False 

def is_ip_address(ip):
    try:
        print(socket.inet_aton(ip))
        return True 
    except socket.error:
        return False


def is_domain(domain_name):
    if validators.domain(domain_name):
        return True
    else:
        return False


def is_url(url):
    if validators.url(url):
        return True 
    else:
        return False

def detect_hash(hash_code):
    hash_decode = 'python hash-id.py ' + hash_code
    p = subprocess.Popen(hash_decode, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate() 
    output = out.decode("utf-8")
    if 'Possible Hashs' in output:
        return output.split(" ")[2][:-5]
    else:
        return False 


def detectJS(data):
    re_js = '(^{)|(}$)|(function(.*)\(\)(.*\s*){)|(for(.*)\((.*\s*)\)(\s*){)|(=+(.*\s*)=+(.*\s*)=)|(!+(.*\s*)!+(.*\s*)!)|(\++(.*\s*)\++(.*\s*)\+)|(:+(.*\s*):+(.*\s*):+(.*\s*):+(.*\s*):+(.*\s*))|(\(+(.*\s*)\);)|(&&)'
    x = re.search(re_js, data)
    if x:
        return True
    else:
        return False



h = html2text.HTML2Text()
h.ignore_links = True
keyTuple = ("HKLM", "HKCU", "**HKLM", "**HKCU")
fileExtension = (".ps1", ".doc", ".js", ".vbs", ".Vbs", ".ps1_", ".doc_", ".js_", ".vbs_", ".Vbs_")
link = "https://reaqta.com/2017/11/muddywater-apt-targeting-middle-east/"
f = requests.get(link)
REG_File = open("reg_key.txt", "w+")
File_name = open("fileName.txt", "w+")
File_path = open("filePath.txt", "w+")
ip_address = open("ip_address.txt", "w+")
domain_name = open("domain_name.txt", "w+")
url_file = open("url.txt", "w+")
hash_file = open("hash.txt", "w+") 

fulltext = f.text
contentFromURL = h.handle(fulltext)
#print(contentFromURL)
for line in contentFromURL.splitlines():
    splittelLine = line.split(" ")
    for splitted in splittelLine:
        if (is_ip_address(splitted)):
            ip_address.write("%s\n" %splitted)
        elif(is_domain(splitted)):
            domain_name.write("%s\n" %splitted)
        elif(is_url(splitted)):
            url_file.write("%s\n" %splitted)
        elif(detect_hash(splitted)):
            hash_file.write("%s\n" %splitted)
        elif splitted.startswith(keyTuple):
            print("REGISTRY KEY: " + splitted)
            REG_File.write("%s\n" %(splitted))
        elif splitted.endswith(fileExtension):
            if "\\" in splitted:
                finalFile = splitted.split("\\")
                print ("FileName " + finalFile[-1])
                File_name.write("%s\n" %(finalFile[-1]))
                File_path.write("%s\n" %(splitted))
            else:
                File_name.write("%s\n" %(splitted))
            

REG_File.close()
File_name.close()
File_path.close()
ip_address.close()
domain_name.close()
url_file.close()
hash_file.close()

#root, ext = os.path.splitext(path) --> check for extension
# ip_candidates = re.findall(r'\bHKLM:\w+', contentFromURL)
#     # remove duplciated from list: (list(dict.fromkeys(ip_candidates))
# print(list(dict.fromkeys(ip_candidates)))