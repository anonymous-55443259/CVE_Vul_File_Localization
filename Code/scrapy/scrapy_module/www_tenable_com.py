import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''

    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    info = soup.find(name = 'h1', attrs = {
        'class' : 'giga hmb',
    })
    if info != None:
        # print(info.text)
        res += 'Title: ' + info.text + '\n'

    info = soup.find(name = 'div', attrs = {
        'class' : 'onethird last',
    })
    if info != None:
        # print(info.text)
        res += format_text(info.text) + '\n\n'

    info = soup.find_all(name = 'div', attrs = {
        'class' : 'widget-container',
    })
    # print(len(info))
    for item in info:
        # print(item.text)
        res += format_text(item.text) + '\n'
        
    return res

if __name__ == '__main__':
    url = 'https://www.tenable.com/security/tns-2016-21'
    res = scrapy(url)
    print(res)