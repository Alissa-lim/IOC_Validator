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

h = html2text.HTML2Text()
h.ignore_links = True
keyTuple = ("HKLM", "HKCU", "**HKLM", "**HKCU")
fileExtension = (".ps1", ".doc", ".js", ".vbs", ".Vbs", ".ps1_", ".doc_", ".js_", ".vbs_", ".Vbs_")
link = "https://reaqta.com/2017/11/muddywater-apt-targeting-middle-east/"
f = requests.get(link)
REG_File = open("reg_key.txt", "w+")
File_name = open("fileName.txt", "w+")
File_path = open("filePath.txt", "w+")

fulltext = f.text
contentFromURL = h.handle(fulltext)
#print(contentFromURL)
for line in contentFromURL.splitlines():
    splittelLine = line.split(" ")
    for splitted in splittelLine:
        if splitted.startswith(keyTuple):
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

#root, ext = os.path.splitext(path) --> check for extension
# ip_candidates = re.findall(r'\bHKLM:\w+', contentFromURL)
#     # remove duplciated from list: (list(dict.fromkeys(ip_candidates))
# print(list(dict.fromkeys(ip_candidates)))