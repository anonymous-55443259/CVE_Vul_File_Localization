import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'td', attrs = {
        'class' : 'content',
    })
    if info:
        res += format_text(info.text)

    if '69923' in url:
        l = res.find('Version: (la')
        r = res.find('My initial')
        res = res[:l] + res[r:]
    elif '74603' in url:
        l = res.find('*** buffer')
        r = res.find('Patches')
        res = res[:l] + res[r:]
    elif '72494' in url:
        l = res.find('[---------')
        r = res.find('Patches')
        res = res[:l] + res[r:]
    elif '72730' in url:
        l = res.find('Before')
        r = res.find('Patches')
        res = res[:l] + res[r:]
    elif '77509' in url:
        l = res.find('valgrind ./')
        r = res.find('Patches')
        res = res[:l] + res[r:]
    elif '71488' in url:
        l = res.find('Actual result:')
        r = res.find('Patches')
        res = res[:l] + res[r:]
    elif '68819' in url:
        l = res.find('With a very')
        r = res.find('Patches')
        res = res[:l] + res[r:]
    elif '76130' in url:
        l = res.find('Test script:')
        r = res.find('Apparently')
        res = res[:l] + res[r:]
    elif '67397' in url:
        r = res.find('For Windows:')
        res = res[:r]
    elif 'bug=74435&' in url:
        r = res.find('literal 11464')
        res = res[:r]
    elif '53632' in url:
        r = res.find('CPU:')
        res = res[:r]
    elif '19280' in url:
        l = res.find('[Switching')
        r = res.find('Subject:')
        res = res[:l] + res[r:]
    elif '75981' in url:
        l = res.find('NO CRASH')
        r = res.find('Patches')
        res = res[:l] + res[r:]
        r = res.find('$ nc -vvlp 8888')
        res = res[:r]
    elif '72340' in url:
        l = res.find('Test script:')
        r = res.find('[2016-06-13 03:25 UTC]')
        res = res[:l] + res[r:]
    elif '76582' in url:
        r = res.rfind('-Status: Open')
        res = res[:r]
    elif '64830' in url:
        r = res.find('-Status: Open')
        res = res[:r]
    elif '20927' in url:
        r = res.find('Thank you for')
        res = res[:r]
    elif '70068' in url:
        r = res.find('(gdb) bt')
        res = res[:r]
        
    return res


if __name__ == '__main__':
    
    url = 'https://bugs.php.net/bug.php?id=70068'
    res = scrapy(url)
    print(res)