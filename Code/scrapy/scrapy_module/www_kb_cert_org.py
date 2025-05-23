import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):
        
    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'div', attrs = {
        'class' : 'mainbody section',
    })

    info.find(name = 'div', attrs = {
        'class' : 'row',
    }).decompose()

    a_tags = info.find_all(name = 'div', attrs = {
        'class' : 'vinfo notaffected extravendors',
    })
    for tag in a_tags:
        tag.decompose()

    a_tags = info.find_all(name = 'div', attrs = {
        'class' : 'vinfo notaffected info extravendors',
    })
    for tag in a_tags:
        tag.decompose()

    a_tags = info.find_all(name = 'div', attrs = {
        'class' : 'vinfo unknown extravendors',
    })
    for tag in a_tags:
        tag.decompose()


    if info != None:
        # print(info.text)
        res += format_text(info.text)

    return res


if __name__ == '__main__':
    url = 'https://www.kb.cert.org/vuls/id/228519'
    res = scrapy(url)
    print(res)