import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    if 'SECURITY' in url:
        info = soup.find_all(name = 'div', attrs = {
            'class' : 'sect1',
        })
        if info == None:
            for item in info:
                if hasattr(item, 'h2') and hasattr(item, 'div'):
                    res += item.h2.text + ':\n' + format_text(item.div.text) + '\n\n'
        else:
            info = soup.find(name = 'div', attrs = {
                'class' : 'col-lg-9',
            })
            if hasattr(info, 'h2'):
                target_tag = info.h2
                # print(target_tag.text)
                for sibling in target_tag.find_previous_siblings():
                    sibling.extract()
                # print(handleText(info.text))
                res += format_text(info.text) + '\n\n'
    else:
        info = soup.find(name = 'div', attrs = {
            'class' : 'app-container',
        })
        if info != None:
            res += format_text(info.text)

    return res
        

if __name__ == '__main__':
    url = 'https://jenkins.io/security/advisory/2018-09-25/#SECURITY-1029'
    res = scrapy(url)
    print(res)