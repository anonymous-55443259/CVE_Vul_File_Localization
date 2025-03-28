import requests
from bs4 import BeautifulSoup, element
from util.general import format_text


def scrapy(url: str):
    res = ''

    if 'Changes-in-DBI' in url:
        return res
    
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    if 'MRASH' in url or 'Module-Signature' in url:
        info = soup.find(name = 'pre', attrs = {
            'id' : 'metacpan_source',
        })
        if info != None:
            res = format_text(info.text)
    else:
        info = soup.find(name = 'div', attrs = {
            'class' : 'pod anchors',
        })
        if info != None:
            for item in info:
                if isinstance(item, element.Tag):
                    id = item.get('id')
                    if id == 'Acknowledgements':
                        break
                res += item.text

    return res


if __name__ == '__main__':
    url = 'https://metacpan.org/release/MRASH/IPTables-Parse-1.6/source/Changes'
    res = scrapy(url)
    print(res)