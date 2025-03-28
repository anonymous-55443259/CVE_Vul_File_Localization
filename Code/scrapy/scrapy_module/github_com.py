import requests
from bs4 import BeautifulSoup
from util.general import format_text


def scrapy(url: str):
    if 'security' in url:
        # 也许要改成'/security/'
        return scrapy_security(url)
    elif 'issue' in url and 'pull' not in url:
        return scrapy_issue(url)
    # elif '.md' in url:
    #     return scrapy_md(url)
    else:
        # 其他类型的网页主要是代码变更，没有直接与漏洞相关的信息
        return None


# def scrapy_md(url: str):
#     from selenium import webdriver
#     from selenium.webdriver.common.by import By
#     from selenium.webdriver.support.ui import WebDriverWait
#     from selenium.webdriver.support import expected_conditions as EC
    
#     res = ''
#     driver = webdriver.Chrome()
#     driver.get(url)

#     element = WebDriverWait(driver, 10)

#     # content = driver.page_source
#     # with open('./test/test.html', 'w') as f:
#     #     print(content, file=f)

#     title = driver.find_element(By.CLASS_NAME, 'markdown-body entry-content container-lg').text
#     # print(title)
#     res += title
#     driver.quit()

#     return res


def scrapy_security(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'h1', attrs = {
        'class' : 'gh-header-title',
    })
    if info != None:
        # print(handleText(info.text))
        res += 'Title:\n' + format_text(info.text) + '\n\n'

    info = soup.find(name = 'div', attrs = {
        'class' : 'Bow-row border-0 clearfix',
    })
    if info != None:
        # print(handleText(info.text))
        res += 'Package:\n' + format_text(info.text) + '\n\n'

    info = soup.find(name = 'div', attrs = {
        'class' : 'markdown-body comment-body p-0',
    })
    if info != None:
        # print(handleText(info.text))
        res += 'Description:\n' + format_text(info.text)
    
    return res


def scrapy_issue(url: str):

    res = ''
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')

    info = soup.find(name = 'bdi', attrs = {
        'class' : 'js-issue-title markdown-title',
    })
    if info != None:
        # print(handleText(info.text))
        res += 'Title:\n' + format_text(info.text) + '\n\n'

    info = soup.find(name = 'div', attrs = {
        'class' : 'js-discussion',
    })
    if info != None:
        tag = info.find(name = 'div', attrs = {
            'class' : 'TimelineItem pt-0 js-comment-container js-socket-channel js-updatable-content',
        })
        if tag != None and hasattr(tag, 'text') and len(tag.text) > 10000:
            tag.decompose()

        tags = info.find_all(name = 'div', attrs = {
            'class' : 'js-timeline-item js-timeline-progressive-focus-container'
        })
        # print(len(tags))

        for tag in tags:
            if hasattr(tag, 'text') and len(tag.text) > 8000:
                tag.decompose()

        res += 'Content:\n' + format_text(info.text) + '\n'

    if 'webrtc/issues/1708' in url:
        l = res.find('./data-channels-create')
        r = res.rfind('ICE', 0)
        res = res[:l] + res[r:]

    return res


if __name__ == '__main__':
    url = 'https://github.com/yetingli/SaveResults/blob/main/md/vfsjfilechooser2.md'
    res = scrapy(url)
    print(res)