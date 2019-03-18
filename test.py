import requests
import json
import chardet
headers = {
    'cookie': '__cfduid=d841138834612557badfc6795b25bf5ef1552567752; csrftoken=3M6Zr5VyZByIdgLifA4Jb9n3ggGLcvG4',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36',
    'accept': 'application/json',
    'referer': 'https://linux.huntingmalware.com/analysis/17697/behavior/',
    'authority': 'linux.huntingmalware.com',
    'x-requested-with': 'XMLHttpRequest',
}

res = requests.get('https://linux.huntingmalware.com/analysis/chunk/17697/541/1/', headers=headers)
print(res.content)