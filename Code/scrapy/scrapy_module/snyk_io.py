import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):
    if 'io/vuln' in url:
        return scrapy_vuln(url)
    else:
        from . import common
        return common.scrapy(url)


def scrapy_vuln(url: str):

    res = ''

    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'h1', attrs = {
        'class' : 'vue--heading title',
    })
    if info != None:
        # print(handleText(info.text))
        res += 'Title:\n' + format_text(info.text, ' ') + '\n\n'

    titles = ['How to fix:\n', 'Overview:\n', 'Details:\n']
    info = soup.findAll(name = 'div', attrs = {
        'class' : 'vue--markdown-to-html markdown-description',
    })

    if info != None:
        for index, item in enumerate(info):
            if index > 2:
                break
            # print(item.text)
            # print('---------------------------------------------')
            res += titles[index] + item.text + '\n'
    
    return res


if __name__ == '__main__':
    url = 'https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1019353'
    res = scrapy(url)
    print(res)