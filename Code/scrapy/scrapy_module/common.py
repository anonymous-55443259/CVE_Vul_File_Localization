import requests
from bs4 import BeautifulSoup
from util.io import save_text
from util.general import format_text


def scrapy(url: str):
    # if url == 'https://www.akamai.com/blog/security-research/exploiting-critical-spoofing-vulnerability-microsoft-cryptoapi':
    #     return None
    res = ''
    if 'pypi.python.org/pypi/Pillow' in url:
        return res
    
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    info = soup.body
    if info != None:
        # print(info.text)
        res += format_text(info.text)
    elif url == 'https://bugzilla.suse.com/attachment.cgi?id=844938':
        res += str(soup.contents)

    if 'bugs.php.net/bug.php?id=76130' in url:
        l = res.find('Test script')
        r = res.find('Actual result')
        res = res[:l] + res[r:]

        l = res.find('Base64')
        r = res.find('Thanks for the')
        res = res[:l] + res[r:]

    return res


if __name__ == '__main__':
    # with open('/Volumes/NVD/experiment_data/datasets/completion/url_list/typo3.org', 'r') as f:
    #     data = f.readlines()

    # for url in data:
    #     url = url.strip()
    #     res = scrapy(url)
    #     print(len(res))

    url = 'https://mantisbt.org/bugs/view.php?id=15453'
    res = scrapy(url)
    print(res)
    # save_text('tp', res)