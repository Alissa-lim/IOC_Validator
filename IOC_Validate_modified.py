#!/usr/bin/env python
# coding: utf-8

# In[140]:


import requests
import re
import socket
import sys
import validators
import subprocess
from bs4 import BeautifulSoup
from lxml import html
from nltk.corpus import wordnet


# In[141]:


def is_site_alive(url):
    try:
        status = requests.get(url)
        if status.status_code == 200:
            return status
    except:
        return False


# In[142]:


def is_domain(domain_name):
    if validators.domain(domain_name):
        return True
    else:
        return False


# In[143]:


def getContents(status):
    soup = BeautifulSoup(status.content)
    # Splitting websites content by \n (line by line analysis)
    [s.extract() for s in soup('style')]  #Extracting CSS from contents
    [s.extract() for s in soup('script')] #Extracting Javascript from contents
    filter_text = soup.get_text().split("\n") #Splitting the web content on the basis of newline character in the form of an array
    return filter_text


# In[144]:


def writeToFile(listTocheck, fileToWrite):
    if (len(listTocheck) > 0):
        listTocheck = list(dict.fromkeys(listTocheck))
        for ip in listTocheck:
            fileToWrite.write("%s\n" %(ip))


# In[145]:


def cleanCode(text):
    for ft in range(len(text)):
        if text[ft]==' ':  
            text[ft]=''
        text[ft] = text[ft].replace('\t', '')
        text[ft] = text[ft].replace('\r', '')
        text[ft] = text[ft].replace('\xa0', '')
    filter_text = list(filter(None, text))
    return filter_text


# In[146]:


def getIPAdr(filter_text):
    ip_addr = re.findall(r"\b\d{1,3}\[*\.\]*\d{1,3}\[*\.\]*\d{1,3}\[*\.\]*\d{1,3}\b",' '.join(filter_text))
    return ip_addr


# In[147]:


def getHash(split, hash_list):
    length_hash = [32, 64, 128]             
    if (re.match('^[a-zA-Z0-9]*$', split)): 
        if(len(split) in length_hash): 
            hash_list.append(split)   
    return hash_list


# In[148]:


def checkFilePath(split, file_name, file_path):
    if "\\" in split:
        finalFile = split.split("\\")
        indexOfFilePath = re.search(r"[a-zA-Z]:", split).start()
        file_name.append(finalFile[-1])
        file_path.append(split[indexOfFilePath:])
    else:
        file_name.append(split)
    return file_name, file_path


# In[149]:


def getDomain(split, domain_list, url_list):
    if ("http" in split or "https" in split or "hxxp" in split or "hxxps" in split):
        url_list.append(split)  
    else:
        domain_list.append(split)  
    return domain_list, url_list


# In[175]:


def writeToFile(listTocheck, fileToWrite):
    if (len(listTocheck) > 0):
        listTocheck = list(dict.fromkeys(listTocheck))
        for ip in listTocheck:
            fileToWrite.write("%s\n" %(ip))


# In[176]:


def openFile():
    Reg_file = open("reg_key.txt", "w+")
    File_name = open("fileName.txt", "w+")
    File_path = open("filePath.txt", "w+")
    Ip_address = open("ip_address.txt", "w+")
    Domain_name = open("domain_name.txt", "w+")
    Url_file = open("url.txt", "w+")
    Hash_file = open("hash.txt", "w+")
    return Reg_file,File_name,File_path,Ip_address,Domain_name,Url_file,Hash_file


# In[177]:


def closeFile(Reg_file,File_name,File_path,Ip_address,Domain_name,Url_file,Hash_file):
    Reg_file.close()
    File_name.close()
    File_path.close()
    Ip_address.close()
    Domain_name.close()
    Url_file.close()
    Hash_file.close()


# In[182]:


def writeAllToFile(instances):
    Reg_file,File_name,File_path,Ip_address,Domain_name,Url_file,Hash_file = openFile()
    writeToFile(instances['IP_Address'], Ip_address)
    writeToFile(instances['Registry_Keys'], Reg_file)
    writeToFile(instances['File_Name'], File_name)
    writeToFile(instances['File_Path'], File_path)
    writeToFile(instances['Urls'], Url_file)
    writeToFile(instances['Domain_Name'], Domain_name)
    writeToFile(instances['Hashes'], Hash_file)
    closeFile(Reg_file,File_name,File_path,Ip_address,Domain_name,Url_file,Hash_file)


# In[188]:


def running(link):
    instances = {'Registry_Keys':[], 'File_Name': [], 'File_Path': [], 'Urls': [], 'Hashes': [], 'IP_Address': [], 'Domain_Name': []}
    keyTuple = ("HKLM:", "HKCU:", "**HKLM:", "**HKCU:")
    fileExtension = (".ps1", ".doc", ".js", ".vbs", ".Vbs",
                    ".ps1_", ".doc_", ".js_", ".vbs_", ".Vbs_", ".py", ".exe", ".dll")
    domain_reg = r"[\[]*\.[\]]*([A-Z0-9-_]+)[\[]*\.[\]]*(XN--VERMGENSBERATUNG-PWB|XN--VERMGENSBERATER-CTB|XN--CLCHC0EA0B2G2A9GCD|TRAVELERSINSURANCE|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--XKC2AL3HYE2A|XN--KCRX77D1X4A|XN--MGBC0A9AZCG|SANDVIKCOROMANT|XN--I1B6B1A6A2E|XN--NQV7FS00EMA|XN--MGBA3A4F16A|XN--LGBBAT1AD8J|XN--MGBX4CD0AB|XN--MGBA3A3EJT|XN--FIQ228C5HS|XN--MGBBH1A71E|XN--B4W605FERD|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBB9FBPOB|XN--JLQ61U9W7B|CANCERRESEARCH|WEATHERCHANNEL|XN--6QQ986B3XL|XN--YGBI2AMMX|INTERNATIONAL|XN--FZC2C9E2C|LIFEINSURANCE|SPREADBETTING|XN--YFRO4I67O|XN--ECKVDTC9D|XN--FPCRJ9C3D|XN--MGBT3DHD|XN--QCKA1PMC|XN--3E0B707E|XN--MK1BU44C|XN--80ASEHDB|VERSICHERUNG|XN--NGBC5AZD|XN--NGBE9E0A|CONSTRUCTION|XN--OGBPF8FL|PAMPEREDCHEF|SCHOLARSHIPS|XN--MGB9AWBF|XN--MGBAB2BD|XN--MGBPL2FH|XN--80ADXHKS|XN--42C2D9A|XN--G2XX48C|XN--KPRW13D|XN--ZFR164B|XN--CZR694B|XN--KPRY57D|REDUMBRELLA|XN--EFVY88H|CREDITUNION|XN--3DS443G|LAMBORGHINI|XN--GECRJ9C|BRIDGESTONE|XN--80AO21A|BARCLAYCARD|XN--H2BRJ9C|XN--T60B56A|XN--SES554G|XN--3BST00M|XN--1QQW23A|XN--HXT814E|XN--6FRZ82G|XN--11B4C3D|XN--S9BRJ9C|XN--RHQV96G|XN--D1ACJ3B|XN--IMR513N|XN--Q9JYB4C|XN--MGBTX2B|PRODUCTIONS|XN--FJQ720A|XN--FLW351E|INVESTMENTS|XN--J6W193G|XN--XHQ521B|XN--55QW42G|PLAYSTATION|WILLIAMHILL|PHOTOGRAPHY|CONTRACTORS|ACCOUNTANTS|MOTORCYCLES|XN--VUQ861B|XN--PGBS0DH|XN--ESTV75G|XN--PBT977C|ENTERPRISES|XN--NYQY26A|ENGINEERING|BLACKFRIDAY|XN--45BRJ9C|XN--KPU716F|VOLKSWAGEN|VISTAPRINT|ACCOUNTANT|TELEFONICA|XN--O3CW4H|TECHNOLOGY|TATAMOTORS|XN--FIQ64B|XN--FIQS8S|XN--FIQZ9S|XN--CZRU2D|XN--PSSY2U|XN--CZRS0T|XN--CG4BKI|IMMOBILIEN|XN--C2BR7G|INDUSTRIES|APARTMENTS|XN--IO0A7I|ASSOCIATES|FOUNDATION|XN--9ET52U|CONSULTING|XN--9DBQ2A|XN--90A3AC|XN--KPUT3I|XN--80ASWG|CREDITCARD|XN--Y9A3AQ|XN--55QX5D|CUISINELLA|XN--MXTQ1M|EUROVISION|XN--4GBRIM|PROPERTIES|XN--WGBL6A|XN--WGBH1C|VLAANDEREN|RESTAURANT|XN--45Q11C|MANAGEMENT|REPUBLICAN|BNPPARIBAS|XN--UNUP4Y|XN--3PXU8K|BOEHRINGER|UNIVERSITY|XN--30RR7Y|PROTECTION|HEALTHCARE|SCHAEFFLER|CHRISTMAS|LANDROVER|LANCASTER|XN--TCKWE|LIFESTYLE|EDUCATION|BLOOMBERG|MARKETING|XN--VHQUV|EQUIPMENT|MELBOURNE|XN--L1ACC|ACCENTURE|FAIRWINDS|BARCELONA|TRAVELERS|MICROSOFT|XN--90AIS|FINANCIAL|FIRESTONE|DIRECTORY|FRESENIUS|FURNITURE|XN--C1AVG|SOLUTIONS|XN--J1AMH|STATEFARM|XN--J1AEF|INSURANCE|AQUARELLE|INSTITUTE|COMMUNITY|YODOBASHI|ANALYTICS|AMSTERDAM|STOCKHOLM|XN--NQV7F|ALLFINANZ|GOLDPOINT|XN--D1ALF|HOMEDEPOT|XN--P1ACF|XN--FHBEI|MONTBLANC|VACATIONS|DISCOUNT|PLUMBING|DIAMONDS|LIGHTING|BUSINESS|FIRMDALE|ISTANBUL|SECURITY|SERVICES|DELOITTE|FEEDBACK|ATTORNEY|FOOTBALL|PHARMACY|PARTNERS|PROPERTY|MORTGAGE|BROADWAY|SOFTBANK|BRADESCO|IPIRANGA|SOFTWARE|ENGINEER|MARRIOTT|BUDAPEST|DOWNLOAD|SAARLAND|COMPUTER|XN--QXAM|DEMOCRAT|STCGROUP|MEMORIAL|VENTURES|PICTURES|INFINITI|COMMBANK|CATERING|MOVISTAR|VERISIGN|XN--NODE|EVERBANK|EXCHANGE|SUPPLIES|CAPETOWN|BOUTIQUE|BARGAINS|XN--P1AI|BUILDERS|YOKOHAMA|AIRFORCE|SYMANTEC|GRAINGER|GRAPHICS|BARCLAYS|CLOTHING|CLINIQUE|MUTUELLE|HOLDINGS|CLEANING|REDSTONE|CITYEATS|CIPRIANI|DELIVERY|HELSINKI|FLSMIDTH|BRUSSELS|TRAINING|REVIEWS|COMPANY|COMPARE|SHIKSHA|TRADING|THEATER|TIFFANY|ABOGADO|KITCHEN|CONTACT|CAPITAL|COOKING|EXPOSED|EXPRESS|WHOSWHO|CARAVAN|CORSICA|COUNTRY|COUPONS|COURSES|ANDROID|FASHION|JEWELRY|SYSTEMS|FERRERO|ZUERICH|CAREERS|CRICKET|FINANCE|WINDOWS|CRUISES|YOUTUBE|CARTIER|FISHING|FITNESS|PHILIPS|RENTALS|FLIGHTS|FLORIST|FLOWERS|SCIENCE|STATOIL|THEATRE|RECIPES|ISELECT|PANERAI|FORSALE|REALTOR|MARKETS|YAMAXUN|SURGERY|FROGANS|BAUHAUS|LINCOLN|KOMATSU|LIMITED|GALLERY|CHANNEL|ORGANIC|OKINAWA|SCHWARZ|STARHUB|LIAISON|TICKETS|GENTING|SPIEGEL|DENTIST|LECLERC|BROTHER|ALIBABA|NEUSTAR|DIGITAL|LATROBE|NETWORK|NETBANK|WANGGOU|SCHMIDT|SUPPORT|BENTLEY|LASALLE|LANXESS|HYUNDAI|DOMAINS|WATCHES|BUGATTI|HOTMAIL|WEATHER|TEMASEK|LACAIXA|ACADEMY|STORAGE|HOTELES|HOSTING|AUCTION|HOLIDAY|WEBSITE|CLUBMED|TOSHIBA|SANDVIK|SINGLES|WEDDING|GUITARS|SAMSUNG|SHRIRAM|COLLEGE|HAMBURG|HANGOUT|HITACHI|COLOGNE|REXROTH|ORIGINS|HEALTH|HIPHOP|TIENDA|HOCKEY|TENNIS|TATTOO|TAOBAO|TAIPEI|AGENCY|SYDNEY|SWATCH|GRATIS|GOOGLE|SUZUKI|ABBOTT|AIRTEL|ALIPAY|SUPPLY|GLOBAL|ALSACE|GIVING|STUDIO|YANDEX|INSURE|GARDEN|FUTBOL|ARAMCO|YACHTS|SOCIAL|SOCCER|JAGUAR|TOYOTA|JOBURG|FAMILY|JUEGOS|KAUFEN|AUTHOR|EXPERT|KINDER|EVENTS|ESTATE|XPERIA|SELECT|ENERGY|EMERCK|TRAVEL|BAYERN|SCHULE|SCHOOL|DURBAN|BERLIN|SANOFI|BHARTI|DOOSAN|DIRECT|LAWYER|DESIGN|SAKURA|SAFETY|RYUKYU|DENTAL|ROCHER|DEGREE|REVIEW|DEALER|REPORT|LIVING|REPAIR|DATSUN|REISEN|LONDON|REALTY|BOSTIK|RACING|QUEBEC|LUXURY|BROKER|CAMERA|MADRID|MAISON|MAKEUP|DATING|VIAJES|MARKET|CAREER|PICTET|PIAGET|PHYSIO|PHOTOS|VILLAS|CREDIT|MOBILY|MONASH|CASINO|CONDOS|MORMON|COMSEC|MOSCOW|COFFEE|CENTER|VIRGIN|OTSUKA|CHANEL|WEBCAM|ORANGE|MUSEUM|CLINIC|ORACLE|CLAIMS|ONLINE|WALTER|VISION|NAGOYA|OFFICE|VOYAGE|HERMES|CHROME|CIRCLE|NOWRUZ|VOTING|NORTON|CHURCH|NISSAN|ACTIVE|SALON|NINJA|NIKON|NEXUS|CISCO|LEASE|CHLOE|VISTA|WALES|CHEAP|NADEX|OMEGA|WATCH|CLICK|CLOUD|WEBER|OSAKA|COACH|CODES|MOVIE|PARIS|MONEY|PARTS|PARTY|MIAMI|VIDEO|PHOTO|CROWN|CYMRU|MEDIA|DABUR|DANCE|PIZZA|MANGO|PLACE|CARDS|CANON|POKER|WORKS|PRAXI|PRESS|PROMO|BUILD|VEGAS|WORLD|LUPIN|XEROX|LOTTO|BOSCH|LOTTE|BOOTS|REHAB|REISE|LOANS|BOATS|LIXIL|LINDE|BLACK|DEALS|BINGO|RICOH|DELTA|ROCKS|RODEO|TUSHU|LEXUS|LEGAL|VODKA|NOKIA|BIBLE|DRIVE|LAMER|TRUST|DUBAI|BEATS|EARTH|KYOTO|EDEKA|EMAIL|BAIDU|EPSON|SENER|AZURE|SEVEN|KOELN|AUTOS|SHARP|SHELL|SHOES|FAITH|TRADE|AUDIO|JETZT|SKYPE|TOURS|SMILE|TORAY|FINAL|FOREX|IRISH|SOLAR|SPACE|TOOLS|STADA|ARCHI|FORUM|GIFTS|APPLE|AMICA|GIVES|STUDY|STYLE|TOKYO|SUCKS|GLASS|IINET|GLOBO|GMAIL|HOUSE|TODAY|GREEN|SWISS|TMALL|TIROL|HORSE|HONDA|TIRES|HOMES|GRIPE|TATAR|GROUP|ADULT|GUCCI|GUIDE|ACTOR|CITIC|VIVA|MODA|DOCS|FILM|PROD|CALL|PROF|IMMO|CAFE|BUZZ|DIET|FAST|VANA|FARM|QPON|DESI|FANS|JOBS|READ|LGBT|CLUB|GOOG|BOOK|BOND|HSBC|MTPC|LIDL|REIT|RENT|LIFE|DELL|JPRS|BLUE|REST|HAUS|LIKE|CITY|BING|RICH|WANG|GIFT|LIMO|DCLK|ROOM|NAME|RSVP|RUHR|TUBE|NAVY|BIKE|SAFE|KDDI|LINK|SALE|LIVE|INFO|FAIL|BEST|NEWS|SAPO|SARL|SAXO|FAGE|VOTO|BEER|LOAN|BBVA|VOTE|NICO|GGEE|BANK|SCOR|SCOT|BAND|GENT|SEAT|GOLF|SEEK|KIWI|LOVE|GBIZ|XBOX|SEXY|LTDA|ERNI|LUXE|GOLD|SHIA|AUTO|GAME|SHOW|ICBC|FUND|MAIF|SITE|TOYS|KRED|SKIN|HOST|TOWN|GURU|HELP|AUDI|SNCF|CHAT|FORD|DATE|ASIA|DVAG|SOHU|FISH|ARTE|SONY|PAGE|ARPA|ARMY|CERN|WORK|STAR|WINE|PARS|GUGE|MEET|CYOU|YOGA|MEME|ITAU|CASH|CASA|MENU|CARS|HERE|LAND|SURF|JAVA|PICS|MINI|COOP|PING|PINK|WIKI|WIEN|COOL|ZARA|PLAY|CARE|WEIR|ZERO|PLUS|MOBI|TAXI|TIPS|AERO|TEAM|TECH|CAMP|ADAC|ZONE|POHL|DOHA|PORN|POST|AARP|OVH|CRS|MTN|REN|DOG|MTR|CSC|CAT|AIG|GLE|LAT|IBM|LAW|CBA|ICE|ICU|RIO|RIP|UBS|LDS|CBN|BUY|IFM|AEG|NEC|TUI|NET|RUN|GMO|RWE|GMX|TRV|CEB|NEW|AXA|CEO|EAT|GOO|NGO|NHK|FIT|ING|SAP|INK|BOM|SAS|GOP|GOT|SBS|INT|SCA|SCB|GOV|DAD|EDU|XYZ|CFA|NRA|NRW|NTT|COM|NYC|LOL|OBI|CFD|FLY|DAY|IST|ONE|ONG|SEW|SEX|ONL|SFR|XIN|OOO|BOO|FOO|ORG|LTD|BZH|WTF|IWC|HOW|BBC|CAB|WTC|JCB|SKI|BID|SKY|CAL|ACO|JLC|JLL|VIP|PET|VIN|MAN|FOX|JMP|BCN|BOT|FRL|JOT|MBA|SOY|JOY|WME|ESQ|TOP|SRL|MED|PID|PIN|XXX|BIO|BIZ|STC|FYI|VET|ABB|MEN|KFH|MEO|GAL|WIN|EUS|CAR|MIL|KIA|KIM|DEV|HIV|MMA|PRO|AFL|ADS|BAR|GDN|AAA|MOE|TAB|MOI|MOM|GEA|PUB|KPN|TAX|UOL|UNO|TCI|APP|KRD|BMS|BMW|TEL|BET|MOV|BNL|FAN|RED|DNP|THD|WED|ZIP|KN|TH|TF|TD|TC|SZ|SY|TJ|TK|TL|TM|SX|TN|TO|SV|SU|ST|SR|SO|SN|SM|SL|SK|SJ|TR|SI|SH|SG|SE|SD|SC|SB|SA|TT|RW|RU|RS|TV|TW|TZ|ZW|RO|UG|UK|RE|QA|PY|US|UY|UZ|VA|PW|PT|VC|VE|PS|PR|PN|PM|PL|VG|VI|PK|PH|PG|PF|PE|PA|OM|NZ|NU|NR|NP|VN|NO|NL|NI|NG|NF|NE|VU|NC|NA|MZ|MY|MX|MW|MV|MU|MT|MS|MR|MQ|MP|MO|WF|MN|MM|ML|MK|MH|MG|ME|MD|MC|MA|LY|WS|LV|LU|LT|LS|LR|LK|LI|LC|LB|LA|KZ|KY|KW|KR|KP|TG|KM|KI|KH|KG|KE|JP|JO|JM|JE|IT|IS|IR|IQ|IO|IN|IM|IL|IE|ID|HU|HT|HR|HN|HM|HK|GY|GW|GU|GT|GS|GR|GQ|GP|GN|GM|GL|GI|GH|GG|GF|GE|GD|GB|GA|FR|FO|FM|FK|FJ|FI|EU|ET|ES|ER|EG|EE|EC|DZ|DO|DM|DK|DJ|DE|CZ|CY|CX|CW|CV|CU|CR|CO|CN|CM|CL|CK|CI|CH|CG|CF|CD|CC|CA|BZ|BY|BW|BV|BT|BS|BR|BO|BN|BM|BJ|BI|BH|BG|BF|BE|BD|BB|BA|AZ|AX|AW|AU|AT|AS|AR|AQ|YE|AO|AM|AL|AI|YT|ZA|AG|AF|AE|ZM|AD|AC|UA)"  
    status = is_site_alive(link)
    if (status == False):
        return "Site URL not up"
    text = getContents(status)
    filter_text = cleanCode(text)
    for filtered in filter_text:
        splittelLine = filtered.split(" ")
        for split in splittelLine:
            if split.startswith(keyTuple):  
                instances['Registry_Keys'].append(split)
            elif split.endswith(fileExtension): 
                instances['File_Name'], instances['File_Path'] = checkFilePath(split, instances['File_Name'], instances['File_Path'])
            elif (re.search(domain_reg, split.upper())):
                instances['Domain_Name'], instances['Urls'] =  getDomain(split, instances['Domain_Name'], instances['Urls'])
            elif (not wordnet.synsets(split)) and ("http" not in split) and ("https" not in split):  
            	instances['Hashes']= getHash(split, instances['Hashes'])
    instances['IP_Address']= getIPAdr(filter_text)
    writeAllToFile(instances)


# In[189]:


def main():
    link = input("Plese input URL for crawling: ")
    if  ("http://" not in link and "https://" not in link):
        link = "http://" + link
    running(link)


# In[ ]:


if __name__== "__main__":
  main()
