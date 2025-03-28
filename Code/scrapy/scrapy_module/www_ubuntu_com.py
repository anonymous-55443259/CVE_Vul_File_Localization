import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy_sub(url):
    res= ''

    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    
    if '4118-1' in url:
        info = soup.find_all(name = 'div', attrs = {
            'class' : 'col-8',
        })
        if info != None:
            info[2].decompose()
            info[1].decompose()
        
    title = "Title:\n"
    info = soup.section.h1
    if info != None:
        title += info.text + '\n'
    
    info = soup.section.find(name = 'table', attrs = {
        'class' : 'cve-table',
    })
    if info != None and len(info.text) > 20000:
        info.decompose()

    info = soup.section.p.find_next(name = 'p')
    if info != None:
        title += info.text
    res += title + '\n' + "Content:\n"

    info = soup.section.find_all(name = 'div', attrs = {
        'class' : 'row',
    })
    for item in info:
        res += format_text(item.text)

    return res


def scrapy(url: str):

    res = ''
    try:
        res = scrapy_sub(url)
    except Exception as e:
        # print(e)
        try:
            res = scrapy_sub(url)
        except Exception:
            try:
                res = scrapy_sub(url)
            except Exception:
                pass
    return res


if __name__ == '__main__':
    url = 'https://usn.ubuntu.com/4118-1/'
    res = scrapy(url)
    print(res)