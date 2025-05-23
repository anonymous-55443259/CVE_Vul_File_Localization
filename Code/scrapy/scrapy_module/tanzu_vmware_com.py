import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'div', attrs = {
        'class' : 'content',
    })
    if info != None:
        # print(info.text)
        res += format_text(info.text)

    return res


if __name__ == '__main__':
    url = 'https://tanzu.vmware.com/security/cve-2016-9877'
    res = scrapy(url)
    print(res)