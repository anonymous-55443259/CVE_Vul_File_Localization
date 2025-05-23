import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):
    res = ''
    if any(item in url for item in ['9842889', '36540', '36539', '36649', '36650']):
        return res

    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find_all(name = 'div', attrs = {
        'class' : 'container-fluid',
    })
    for i, item in enumerate(info):
        if i == 0: continue
        res += format_text(item.text)
    if '10395909' in url:
        l = res.find('------------------------------------------------------------\n[  243.867497]')
        r = res.find('Once a thread')
        res = res[:l] + res[r:]
    elif '11447049' in url or '10836283' in url:
        l = res.find('Comments')
        r = res.find('Patch')
        res = res[:l] + res[r:]
    return res


if __name__ == '__main__':
    url = 'https://patchwork.kernel.org/patch/10503415/'
    res = scrapy(url)
    print(res)