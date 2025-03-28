import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):
    
    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'div', attrs = {
        'class' : 'row',
    })
    appendix = info.find(name = 'td', attrs = {
        'class' : 'bug-attach-tags',
    })
    if appendix != None:
        appendix.decompose()
    
    if info != None:
        res += format_text(info.text)

    return res


if __name__ == '__main__':
    url = 'https://mantisbt.org/bugs/view.php?id=15453'
    res = scrapy(url)
    print(res)