import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):
    
    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'div', attrs = {
        'class' : 'rfcmarkup',
    })
    if info != None:
        l = info.text.find('5.1.2.  Unaut')
        r = info.text.find('with a resultCode of\n')
        res = info.text[l:r]

        l = res.find('Harrison')
        r = res.find('The distinguished')
        res = res[:l] + res[r:]
        res = format_text(res)

    return res


if __name__ == '__main__':
    url = 'https://tools.ietf.org/html/rfc4513#section-5.1.2'
    res = scrapy(url)
    print(res)