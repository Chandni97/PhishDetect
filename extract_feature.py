# dataset from https://www.phishtank.com/developer_info.php,
#              https://ak.quantcast.com/quantcast-top-sites.zip


import sys
import csv
import pandas as pd
import regex
from tldextract import extract
import ssl
from urllib.request import urlopen, Request
import xml.etree.ElementTree as ET
import datetime
from bs4 import BeautifulSoup
import urllib, bs4, re
from googlesearch import search
import whois
from datetime import datetime
import time
import requests
import urllib.request
from urllib.parse import urlencode
import subprocess
import urllib3, requests, json



import socket

def url_having_ip(url):
    match= re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
    if match:
        return 1
    else:
        return 0


def SSLfinal_State(url):
    try:
        # check wheather contains https
        if (regex.search('^https', url)):
            usehttps = 1
        else:
            usehttps = 0
        # getting the certificate issuer to later compare with trusted issuer
        # getting host name
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname=host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if (certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0]
        trusted_Auth = ['AC Camerfirma, S.A', 'Actalis', 'Agencia Notarial de Certificación (ANCERT)', 'Amazon', 'Asseco Data Systems S.A. (previously Unizeto Certum)', 'Comodo', 'Symantec', 'GoDaddy', 'GlobalSign', 'DigiCert', 'StartCom', 'Entrust', 'Verizon',
                        'A-Trust','Trustwave', 'Unizeto', 'Buypass', 'QuoVadis', 'Deutsche Telekom', 'Network Solutions',
                        'SwissSign', 'Google Trust Services (GTS)','Government of Australia' ,'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 'Doster', 'VeriSign', 'Google',
                        'Government of India, Ministry of Communications & Information Technology, Controller of Certifying Authorities (CCA)',
                        'Symantec / VeriSign']

        # getting age of certificate
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear - startingYear

        # checking final conditions
        #print(str(usehttps) + " , " + certificate_Auth + " , " + str(Age_of_certificate))
        if ((usehttps == 1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate >= 1)):
            return 0  # legitimate
        else:
            return 1  # phishing

    except Exception as e:
        return 1

def url_short(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 1
    else:
        return 0

def having_at_symbol(url):
    symbol=regex.findall(r'@',url)
    if(len(symbol)==0):
        return 0
    else:
        return 1

def doubleSlash(url):
#since the position starts from, we have given 6 and not 7 which is according to the document
    list=[x.start(0) for x in re.finditer('//', url)]
    if list[len(list)-1]>6:
        return 1
    else:
        return 0


def domain_registration_length(domain):

    if isinstance(domain.expiration_date, list):
        expiration_date = domain.expiration_date[0]
    else:
        expiration_date = domain.expiration_date
    expiration_date = str(expiration_date).split(' ')[0]
    expiration_date = datetime.strptime(str(expiration_date), '%Y-%m-%d')
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')
    registration_length = abs((expiration_date - today).days)

    return round(registration_length/365,2)


def favicon(soup, domain):

    if isinstance(domain.domain_name, list):
        domain = domain.domain_name[0].lower()
    else:
        domain = domain.domain_name.lower()

    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
            if domain in head.link['href']:
                return 0
            else:
                return 1
    return 0

def https_token(url):
    match = re.search('https://|http://', url)
    if match.start(0) == 0:
        url = url[match.end(0):]
    match = re.search('http|https', url)
    if match:
        return 1
    else:
        return 0

def request_url(soup, domain):
    i = 0
    success = 0

    if isinstance(domain.domain_name, list):
        domain = domain.domain_name[0].lower()
    else:
        domain = domain.domain_name.lower()

    for img in soup.find_all('img', src=True):
        dots = [x.start(0) for x in re.finditer('\.', img['src'])]
        if domain not in img['src']:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
        if domain not in audio['src']:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
        if domain not in embed['src']:
            success = success + 1
        i = i + 1

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start(0) for x in re.finditer('\.', i_frame['src'])]
        if domain not in i_frame['src']:
            success = success + 1
        i = i + 1

    try:
        percentage = success / float(i)
        return round(percentage, 2)
    except:
        return 0



def url_of_anchor(soup, domain):
    i = 0
    unsafe = 0

    if isinstance(domain.domain_name, list):
        domain = domain.domain_name[0].lower()
    else:
        domain = domain.domain_name.lower()

    for a in soup.find_all('a', href=True):
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
    try:
        percentage = unsafe / float(i)
        return round(percentage, 2)
    except:
        return 0


def links_in_tags(soup, domain):
   i=0
   success =0

   if isinstance(domain.domain_name, list):
       domain = domain.domain_name[0].lower()
   else:
       domain = domain.domain_name.lower()

   for link in soup.find_all('link', href= True):
      dots=[x.start(0) for x in re.finditer('\.',link['href'])]
      if domain not in link['href']:
         success = success + 1
      i=i+1

   for script in soup.find_all('script', src= True):
      dots=[x.start(0) for x in re.finditer('\.',script['src'])]
      if domain not in script['src']:
         success = success + 1
      i=i+1
   try:
       percentage = success / float(i)
       return round(percentage, 2)
   except:
       return 0


def sfh(soup, domain):

    if isinstance(domain.domain_name, list):
        domain = domain.domain_name[0].lower()
    else:
        domain = domain.domain_name.lower()

    for form in soup.find_all('form', action= True):
      if form['action'] =="" or form['action'] == "about:blank" :
         return 1
      elif domain not in form['action']:
          return 1
      else:
            return 0
    return 0

def submitting_to_email(soup):
   for form in soup.find_all('form', action= True):
      if "mailto:" in form['action']:
         return 1
      else:
          return 0
   return 0

def abnormal_url(domain,url):

    if isinstance(domain.domain_name, list):
        for domains in domain.domain_name:
            if domains.lower() in url:
                return 0
        return 1
    else:
        if domain.domain_name.lower() in url:
            return 0
        else:
            return 1



def redirect(url):
    count = 0
    while True:
        r = requests.head(url)
        if 300 < r.status_code < 400:
            url = r.headers['location']
            count=count+1
        else:
          return count

def iframe(soup):
    for iframe in soup.find_all('iframe', width=True, height=True, frameBorder=True):
        if iframe['width']=="0" and iframe['height']=="0" and iframe['frameBorder']=="0":
            return 1
        else:
            return 0
    return 0

def age_of_domain(domain):

    if isinstance(domain.creation_date, list):
        creation_date = domain.creation_date[0]
    else:
        creation_date = domain.creation_date

    creation_date = str(creation_date).split(' ')[0]

    if isinstance(domain.expiration_date, list):
        expiration_date = domain.expiration_date[0]
    else:
        expiration_date = domain.expiration_date

    expiration_date = str(expiration_date).split(' ')[0]


    creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d')
    expiration_date = datetime.strptime(str(expiration_date), '%Y-%m-%d')
    ageofdomain = abs((expiration_date - creation_date).days)
    return ageofdomain/30

def web_traffic(url):

    try:
        with urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url) as response:
            html = response.read()
    except:
        return 1

    tree = ET.fromstring(html.decode())
    try:
        rank = (tree.findall('*/REACH'))[0].attrib['RANK']
    except:
        return 1
    if (int(rank)<100000):
        return 0
    else:
        return 1


def statistical_report(url,hostname):
    url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
    try:
        ip_address=socket.gethostbyname(hostname)
    except:
        print ('Connection problem. Please check your internet connection!')
##### 1st line is phishtank top 10 domain ips and 2nd, 3rd, 4th, 5th, 6th lines are top 50 domain ips from stopbadware #####
    ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                       '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                       '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                       '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                       '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                       '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
    if url_match:
        return 1
    elif ip_match:
        return 1
    else:
        return 0


















