import math
import inspect
import threading
from urllib.parse import urlparse
from collections import defaultdict


RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"  # 默认颜色

def print_location(message: str = ''):
    frame = inspect.currentframe()
    file_name = frame.f_code.co_filename
    # function_name = frame.f_code.co_name
    line_number = frame.f_lineno
    
    print(f'{RED}{message}File "{file_name}", line {line_number}{RESET}')


def multi_thread(data_list: list, target, chunk_size = 300, github_tokens = None):
    if github_tokens:
        chunk_size = max(1, math.ceil(len(data_list) / len(github_tokens)))
    chunks = [data_list[i:i + chunk_size] for i in range(0, len(data_list), chunk_size)]

    threads = []
    for i in range(len(chunks)):
        if github_tokens:
            args = (chunks[i], github_tokens[i],)
        else:
            args = (chunks[i],)
        thread = threading.Thread(target = target, args = args)
        threads.append(thread)
    
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()


def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc


def count_range(data: list, interval: list):
    res = {}
    for i in range(len(interval)):
        if i == 0:
            res[f'1-{interval[0]}'] = 0
        if i == len(interval) - 1:
            res[f'>{interval[-1]}'] = 0
            continue
        else:
            l = interval[i] + 1
            r = interval[i + 1]
            res[f'{l}-{r}'] = 0

    for item in data:
        for i, value in enumerate(interval):
            if (i == 0 and item <= value) or (i == len(interval) - 1) or (item <= interval[i + 1]):
                if i == 0 and item <= value:
                    res[f'1-{value}'] += 1
                elif i == len(interval) - 1:
                    res[f'>{value}'] += 1
                else:
                    res[f'{value + 1}-{interval[i + 1]}'] += 1
                break
    return res


def format_text(text: str, separator = '\n'):
    lines = text.split('\n')

    # 去除每行前后的空格，并过滤掉空行
    stripped_lines = [line.strip() for line in lines if line.strip()]

    result = separator.join(stripped_lines)
    return result


# 文件名相同
filter_file = [
    'changelog', 'news', 'changes', 'version', 'readme', 'license', 'authors', 'todo', 'history', 'copying', 'relnotes', 'thanks', 'notice', 'whatsnew', 'notes', 'release', 'release_notes', 'testlist', 'testsuite', 'test'
]
# 以这些后缀结尾的文件
filter_suffix = [
    '.md', '.txt', '.docx', '.pdf', '.rst', '.changes', '.rdoc', '.mdown',
    '.command', '.out', '.err', '.stderr', '.stdout', '.test',
    '.jpg', '.png', '.svg', '.mp4', '.gif', '.exr',
    '.csv', '.rdf',
    '.ttf', '.otf', '.woff', '.woff2',
    '.mock', '.stub', '.fake',
    '.pptx', '.key',
    '.bak', '.zip', '.gz', '.rar',
    '.gitignore',
    '.lib', '.jpeg', '.ppt', '.xlsx', '.xls', '.doc', '.ico', '.bmp', '.tar.gz', '.tgz', '.css', '.cygport',
    '.docs', '.wav'
]
# 路径中包含
filter_path = [
    'note', 'license', 'test'
]

def rule_based_filtering(full_file_name: str):
    full_file_name = full_file_name.lower()
    file_name = full_file_name.split('/')[-1]
    file_path = '/'.join(full_file_name.split('/')[:-1])
    if any(file_name == item for item in filter_file):
        return False
    if any(file_name.endswith(suffix) for suffix in filter_suffix):
        return False
    if any(item in file_path for item in filter_path):
        return False
    return True


def print_tree(tree, prefix="", ):
    items = list(tree.keys())
    for index, key in enumerate(items):
        is_last = (index == len(items) - 1)
        connector = "└── " if is_last else "├── "
        print(prefix + connector + key)
        next_prefix = prefix + ("    " if is_last else "│   ")
        print_tree(tree[key], next_prefix)


def generate_tree_str(files: list):
    def build_tree(paths):
        tree = defaultdict(dict)
        for path in paths:
            parts = path.strip('/').split('/')
            current = tree
            for part in parts:
                if part not in current:
                    current[part] = {}
                current = current[part]
        return tree

    def rec(tree, prefix="", ):
        items = list(tree.keys())
        res = ''
        for index, key in enumerate(items):
            is_last = (index == len(items) - 1)
            connector = "└── " if is_last else "├── "
            res += prefix + connector + key + '\n'
            next_prefix = prefix + ("    " if is_last else "│   ")
            res += rec(tree[key], next_prefix)
        return res

    tree = build_tree(files)
    return rec(tree)


def format_text(text: str, separator = '\n'):
    lines = text.split('\n')

    # 去除每行前后的空格，并过滤掉空行
    stripped_lines = [line.strip() for line in lines if line.strip()]

    result = separator.join(stripped_lines)
    return result

