import requests
from bs4 import BeautifulSoup, element
from util.io import save_text
from util.general import format_text



def scrapy(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'div', attrs = {
        'class' : 'devsite-article-body clearfix',
    })
    if info != None:
        flag = False
        flag2 = False
        if '2019-05-01' in url:
            flag2 = True
        for i, data in enumerate(info):
            if isinstance(data, element.Tag):
                id = data.get('id')
                # print(id)
                if id in ['announcements']:
                    flag = True
                    flag2 = True
                elif id in ['mitigations', 'acknowledgements']:
                    flag = False
                elif flag2:
                    flag = True

            if flag:
                res += format_text(data.text)
        
    return res


if __name__ == '__main__':
    url = 'https://source.android.com/docs/security/bulletin/2019-05-01'
    res = scrapy(url)
    print(res)