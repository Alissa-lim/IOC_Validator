#!/usr/bin/env python
# coding: utf-8

# In[1]:


import requests
import sys
import socket 
import validators
import subprocess
import urllib.request
from bs4 import BeautifulSoup
from lxml import html
import re


# In[3]:


#url = sys.argv[1]
url = 'https://reaqta.com/2017/11/muddywater-apt-targeting-middle-east/'


# In[91]:


def is_site_alive(url):
    request = requests.get(url)
    if request.status_code == 200:
        return True 
    else:
        return False 


# In[92]:


def is_ip_address(ip):
    try:
        print(socket.inet_aton(ip))
        return True 
    except socket.error:
        return False 


# In[93]:


def is_domain(domain_name):
    if validators.domain(domain_name):
        return True
    else:
        return False


# In[94]:


def is_url(url):
    if validators.url(url):
        return True 
    else:
        return False


# In[95]:


def detect_hash(hash_code):
    hash_decode = 'python hash-id.py ' + hash_code
    p = subprocess.Popen(hash_decode, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate() 
    output = out.decode("utf-8")
    if 'Possible Hashs' in output:
        return output.split(" ")[2][:-5]
    else:
        return False 


# In[5]:


page = requests.get(url)


# In[7]:


page.content


# In[8]:


soup = BeautifulSoup(page.content)


# In[98]:


filter_text = soup.get_text().split("\n") #Splitting websites content by \n (line by line analysis)


# In[121]:


#converting ' ', \t, \xa0 to '' and then eliminating all '' elements from the filter_text list
for ft in range(len(filter_text)):
    if filter_text[ft]==' ':  
        filter_text[ft]=''
    filter_text[ft] = filter_text[ft].replace('\t', '')
    filter_text[ft] = filter_text[ft].replace('\r', '')
    filter_text[ft] = filter_text[ft].replace('\xa0', '')


# In[167]:


def detectJS(data):
    re_js = '(^{)|(}$)|(function(.*)\(\)(.*\s*){)|(for(.*)\((.*\s*)\)(\s*){)|(=+(.*\s*)=+(.*\s*)=)|(!+(.*\s*)!+(.*\s*)!)|(\++(.*\s*)\++(.*\s*)\+)|(:+(.*\s*):+(.*\s*):+(.*\s*):+(.*\s*):+(.*\s*))|(\(+(.*\s*)\);)|(&&)'
    x = re.search(re_js, data)
    if x:
        return True
    else:
        return False


# In[168]:


for ft in range(len(filter_text)):
    if detectJS(filter_text[ft])==True:
        filter_text[ft]=''
filter_text = list(filter(None, filter_text)) 


# In[ ]:




