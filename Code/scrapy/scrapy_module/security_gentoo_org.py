import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''
    
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'h1', attrs = {
        'class' : 'first-header',
    })
    if info != None:
        # print(info.text)
        res += format_text(info.text)

    info = soup.find(name = 'div', attrs = {
        'class' : 'col-12 col-md-10',
    })
    if info != None:
        # print(info.text)
        res += format_text(info.text)
    
    return res

if __name__ == '__main__':
    url = 'https://security.gentoo.org/glsa/202003-48'
    res = scrapy(url)
    print(res)