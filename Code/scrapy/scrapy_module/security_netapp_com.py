import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''

    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    info = soup.find(name = 'div', attrs = {
        'class' : 'luci-long-form-text',
    })
    if info != None:
        try:
            # print(handleText(info.h2.text))
            res += 'Title:\n' + format_text(info.h2.text) + '\n\n'
        except Exception:
            pass
        
    info = soup.findAll(name = 'div', attrs = {
        'class' : 'n-tabs__content',
    })
    titles = ['Overview:\n', 'Affected Products:\n', 'Remediation:\n', 'Revision History:\n']
    if info != None:
        for index, item in enumerate(info):
            # print(handleText(item.text))
            res += titles[index] + format_text(item.text) + '\n\n'

    return res

if __name__ == '__main__':
    url = 'https://security.netapp.com/advisory/ntap-20190910-0003/'
    res = scrapy(url)
    print(res)