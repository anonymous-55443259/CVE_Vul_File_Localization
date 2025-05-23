import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    tp = soup.find(name = 'div', attrs = {
        'class' : 'bx--col-md-2 bx--col-lg-4',
    })
    if tp: tp.decompose()
    tp = soup.find(name = 'div', attrs = {
        'class' : 'clearfix text-formatted field field--name-field-disclaimer field--type-text-long field--label-above',
    })
    if tp: tp.decompose()

    info = soup.find(name = 'div', attrs = {
        'class' : 'region region-content',
    })
    if info:
        res += format_text(info.text)
    
    if 'isg400001843' in url:
        r = res.rfind('List of fixes')
        res = res[:r]

    # save_text('tp', res)
    return res


if __name__ == '__main__':
    url = 'http://www-01.ibm.com/support/docview.wss?uid=isg400001843'
    res = scrapy(url)
    print(res)