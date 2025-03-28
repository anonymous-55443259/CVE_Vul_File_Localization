import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'div', attrs = {
        'id' : 'maincontent',
    })
    repeat = info.find_all(name = 'div', attrs = {
        'class' : 'editable-message-form',
    })
    for item in repeat:
        item.decompose()
    if info != None:
        res += format_text(info.text)

    if '1847478' in url:
        r = res.find('Kernel:')
        res = res[:r]

    return res


if __name__ == '__main__':
    url = 'https://bugs.launchpad.net/keystone/+bug/1873290'
    res = scrapy(url)
    print(res)