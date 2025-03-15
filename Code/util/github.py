import os
import pytz
import time
import tqdm
import base64
import atexit
import requests
from datetime import datetime

from util.io import load_json, load_pickle, save_json, save_pickle, save_text
from util.general import print_location, multi_thread


github_tokens = load_json('.github_tokens.json')

module_path = 'experiment_data2/github'

repo_existence_dict_update = False
repo_existence_dict_path = f'{module_path}/repo_existence_dict'
repo_existence_dict = load_pickle(f'{repo_existence_dict_path}.pkl') if os.path.exists(f'{repo_existence_dict_path}.pkl') else {}

repo_file_content_update = False
repo_file_content_dict_path = f'{module_path}/repo_file_content_dict'
repo_file_content_dict = load_pickle(f'{repo_file_content_dict_path}.pkl') if os.path.exists(f'{repo_file_content_dict_path}.pkl') else {}

repo_all_branch_update = False
repo_all_branch_dict_path = f'{module_path}/repo_all_branch_dict'
repo_all_branch_dict = load_pickle(f'{repo_all_branch_dict_path}.pkl') if os.path.exists(f'{repo_all_branch_dict_path}.pkl') else {}

latest_commit_before_date_update = False
latest_commit_before_date_dict_path = f'{module_path}/latest_commit_before_date_dict'
latest_commit_before_date_dict = load_pickle(f'{latest_commit_before_date_dict_path}.pkl') if os.path.exists(f'{latest_commit_before_date_dict_path}.pkl') else {}

repo_file_list_update = False
repo_file_list_dict_path = f'{module_path}/repo_file_list_dict'
repo_file_list_dict = load_pickle(f'{repo_file_list_dict_path}.pkl') if os.path.exists(f'{repo_file_list_dict_path}.pkl') else {}


def on_exit():
    if repo_existence_dict_update:
        save_json(f'{repo_existence_dict_path}.json', repo_existence_dict)
        save_pickle(f'{repo_existence_dict_path}.pkl', repo_existence_dict)
    if repo_file_content_update:
        # save_json(f'{repo_file_content_dict_path}.json', repo_file_content_dict)
        save_text(repo_file_content_dict_path, repo_file_content_dict, 'w')
        save_pickle(f'{repo_file_content_dict_path}.pkl', repo_file_content_dict)
    if repo_all_branch_update:
        save_json(f'{repo_all_branch_dict_path}.json', repo_all_branch_dict)
        save_pickle(f'{repo_all_branch_dict_path}.pkl', repo_all_branch_dict)
    if latest_commit_before_date_update:
        save_text(latest_commit_before_date_dict_path, latest_commit_before_date_dict, 'w')
        save_pickle(f'{latest_commit_before_date_dict_path}.pkl', latest_commit_before_date_dict)
    if repo_file_list_update:
        # save_text(repo_file_list_dict_path, repo_file_list_dict, 'w')
        save_pickle(f'{repo_file_list_dict_path}.pkl', repo_file_list_dict)

atexit.register(on_exit)


def get_repo_from_commit_url(url: str):
    left_parttern = 'github.com/'
    right_parttern = '/commit'
    if left_parttern in url and right_parttern in url:
        return url[
            url.find(left_parttern) + len(left_parttern):
            url.find(right_parttern)
        ]
    else:
        print_location(f'commit url error! url is {url}\n')
        return ''


def check_api_limit(headers, tokens = ''):
    if 'X-RateLimit-Remaining' not in headers or 'X-RateLimit-Reset' not in headers:
        print_location(f'secondary rate limits!, token: {tokens}')
        time.sleep(100)
        return False
    remaining = headers['X-RateLimit-Remaining']
    reset_time = int(headers['X-RateLimit-Reset'])
    if int(remaining) == 0:
        reset_time_utc = datetime.utcfromtimestamp(reset_time)
        beijing_timezone = pytz.timezone('Asia/Shanghai')
        reset_time_beijing = reset_time_utc.replace(tzinfo=pytz.utc).astimezone(beijing_timezone)
        now_beijing = datetime.now(beijing_timezone)
        time_to_reset = (reset_time_beijing - now_beijing).total_seconds() + 2
        if time_to_reset > 50:
            print(time_to_reset, tokens)
        # print(f'剩余重置时间：{time_to_reset} seconds')
        if time_to_reset < 0:
            time_to_reset = 1
        time.sleep(time_to_reset)
    return True


def get_original_repo_name(repo_full_name: str, token: str):
    url = f"https://api.github.com/repos/{repo_full_name}"
    headers = {'Authorization': f'token {token}'}
    response = requests.get(url, headers = headers)
    check_api_limit(response.headers, token)
    if response.ok:
        repo = response.json()
        if 'parent' in repo.keys() and 'full_name' in repo['parent']:
            res = repo['parent']['full_name']
        else:
            res = repo_full_name
        return res
    else:
        # print(f"Failed to retrieve information for {repo_full_name}")
        return repo_full_name


def get_latest_repo_name(old_full_name, token: str):
    url = f'https://api.github.com/repos/{old_full_name}'
    headers = {'Authorization': f'token {token}'}
    response = requests.get(url, headers = headers)
    check_api_limit(response.headers, token)
    if response.ok:
        repo = response.json()
        res = repo['full_name'] if 'full_name' in repo.keys() else old_full_name
        return res
    else:
        print_location(f'Failed to retrieve information for {old_full_name}')
        return old_full_name
    

def search_repo(params: dict, token: str):
    url = f'https://api.github.com/search/repositories'
    headers = {'Authorization': f'token {token}'}
    response = requests.get(url, headers = headers, params = params)
    check_api_limit(response.headers, token)
    if response.ok:
        data = response.json()
        repositories = data['items']
        return {repo['full_name'] for repo in repositories}
    return set()
    

def check_repo_exist(repos):

    def check_single_repo(repo_name: str, token: str):
        if repo_name not in repo_existence_dict:
            url = f'https://api.github.com/repos/{repo_name}'
            headers = {'Authorization': f'token {token}'}
            response = requests.get(url, headers = headers)
            check_api_limit(response.headers, token)
            # print(response.text)
            repo_existence_dict[repo_name] = response.ok
            global repo_existence_dict_update
            repo_existence_dict_update = True
        return repo_existence_dict[repo_name]
    
    def anonymous(repo_list, token: str):
        for repo in tqdm.tqdm(repo_list):
            check_single_repo(repo, token)
        on_exit()

    if type(repos) == str:
        return check_single_repo(repos, github_tokens[0])
    elif type(repos) == list and type(repos[0]) == str:
        to_check = {
            repo
            for repo in repos
            if repo not in repo_existence_dict
        }
        multi_thread(list(to_check), anonymous, github_tokens = github_tokens)
    else:
        assert False


def get_latest_commit_before_date(tuples):
    def get_single_tuple(tuple: tuple, token: str):
        if tuple not in repo_all_branch_dict:
            repo_name, branch, date = tuple
            url = f'https://api.github.com/repos/{repo_name}/commits'
            if branch:
                url += f'?sha={branch}'
            headers = {'Authorization': f'token {token}'}
            params = {
                'per_page': 1,
                'until': date,
            }
            try:
                response = requests.get(url, params = params, headers = headers)
                if not check_api_limit(response.headers, token):
                    response = requests.get(url, params = params, headers = headers)
                    check_api_limit(response.headers, token)
                if response.ok:
                    commits = response.json()
                    if commits:
                        latest_commit_before_date_dict[tuple] = (commits[0]['sha'], commits[0]['commit']['committer']['date'])
                    else:
                        latest_commit_before_date_dict[tuple] = None
                    global latest_commit_before_date_update
                    latest_commit_before_date_update = True
                else:
                    latest_commit_before_date_dict[tuple] = None
            except Exception as e:
                print_location(e)
                return None

        return latest_commit_before_date_dict[tuple]
    
    def anonymous(tuple_list, token: str):
        for tuple in tqdm.tqdm(tuple_list):
            get_single_tuple(tuple, token)
        on_exit()

    if type(tuples) == tuple:
        return get_single_tuple(tuples, github_tokens[0])
    elif type(tuples) == list and type(tuples[0]) == tuple:
        to_check = {
            tuple
            for tuple in tuples
            if tuple not in latest_commit_before_date_dict
        }
        print(f'to_check size: {len(to_check)}')
        multi_thread(list(to_check), anonymous, github_tokens = github_tokens)
    else:
        assert False


def get_all_branch(repos):
    def get_single_repo(repo_name: str, token: str):
        if repo_name not in repo_all_branch_dict:
            url = f'https://api.github.com/repos/{repo_name}/branches'
            headers = {'Authorization': f'token {token}'}
            page = 1
            branches = []
            while True:
                params={'page': page, 'per_page': 100}
                response = requests.get(url, headers = headers, params = params)
                check_api_limit(response.headers, token)
                if response.ok:
                    try:
                        data = response.json()
                        if len(data) == 0:
                            break
                        branches += [branch['name'] for branch in data]
                    except Exception as e:
                        print_location(e)
                        continue
                page += 1
            repo_all_branch_dict[repo_name] = branches
            global repo_all_branch_update
            repo_all_branch_update = True

        return repo_all_branch_dict[repo_name]
    
    def anonymous(repo_list, token: str):
        for repo in tqdm.tqdm(repo_list):
            get_single_repo(repo, token)
        on_exit()

    if type(repos) == str:
        return get_single_repo(repos, github_tokens[0])
    elif type(repos) == list and type(repos[0]) == str:
        to_check = {
            repo
            for repo in repos
            if repo not in repo_all_branch_dict
        }
        multi_thread(list(to_check), anonymous, github_tokens = github_tokens)
    else:
        assert False
    

def get_file_list(tuples):
    def get_single_repo(tuple: tuple, token: str, base_path = ''):
        if tuple not in repo_file_list_dict:
            repo_name, sha = tuple
            url = f'https://api.github.com/repos/{repo_name}/git/trees/{sha}?recursive=1'
            headers = {'Authorization': f'token {token}'}
            try:
                response = requests.get(url, headers = headers)
                check_api_limit(response.headers, token)
                if not response.ok:
                # with open(f'{commit_sha}', 'w') as f:
                #     print(json.dumps(response.json()), file=f)
                    return []
                data = response.json()
                if data['truncated']:
                    url = url.split('?')[0]
                    response = requests.get(url, headers = headers)
                    check_api_limit(response.headers, token)
                    if not response.ok:
                        return []
                    res = []
                    for item in response.json()['tree']:
                        if item['type'] == 'blob':
                            res.append((
                                base_path + '/' + item['path'] if base_path else item['path'],
                                item['type'] == 'tree'
                            ))
                        elif item['type'] == 'tree':
                            res += get_single_repo(
                                (repo_name, item['sha']),
                                token,
                                base_path + '/' + item['path'] if base_path else item['path']
                            )
                    # print(len(res))
                    repo_file_list_dict[tuple] = res
                else:
                    res = [
                        (base_path + '/' + item['path'] if base_path else item['path'], item['type'] == 'tree')
                        for item in response.json()['tree']
                    ]
            except Exception as e:
                print_location(e)
                return []
            repo_file_list_dict[tuple] = res
            global repo_file_list_update
            repo_file_list_update = True
        return repo_file_list_dict[tuple]
    
    def anonymous(tuple_list, token: str):
        for repo in tqdm.tqdm(tuple_list):
            get_single_repo(repo, token)
        # on_exit()

    if type(tuples) == tuple:
        return get_single_repo(tuples, github_tokens[0])
    elif type(tuples) == list and type(tuples[0]) == tuple:
        to_check = {
            tuple
            for tuple in tuples
            if tuple not in repo_file_list_dict
        }
        print(f'to_check size: {len(to_check)}')
        if to_check:
            multi_thread(list(to_check), anonymous, github_tokens = github_tokens)
    else:
        assert False


def get_file_content(files):
    
    def get_single_file(file_tuple: tuple, token: str):
        if file_tuple not in repo_file_content_dict:
            repo, sha, file_path = file_tuple
            url = f'https://api.github.com/repos/{repo}/contents/{file_path}?ref={sha}'
            headers = {'Authorization': f'token {token}'}
            response = requests.get(url, headers = headers)
            check_api_limit(response.headers, token)
            if response.ok:
                try:
                    content = response.json().get('content', None)
                    if content:
                        content = base64.b64decode(content).decode('utf-8')
                        repo_file_content_dict[file_tuple] = content
                        global repo_file_content_update
                        repo_file_content_update = True
                        return content
                except Exception as e:
                    print_location(f'{file_tuple}\n{e}')
            else:
                print_location(f'{file_tuple}\n{response.text}')
            return None
        
        return repo_file_content_dict[file_tuple]
            
    
    def anonymous(file_list, token: str):
        for file_tuple in tqdm.tqdm(file_list):
            get_single_file(file_tuple, token)
        on_exit()

    if type(files) == tuple:
        return get_single_file(files, github_tokens[0])
    elif type(files) == list and type(files[0]) == tuple:
        to_check = {
            file_tuple
            for file_tuple in files
            if file_tuple not in repo_file_content_dict
        }
        # print(next(iter(to_check)))
        multi_thread(list(to_check), anonymous, github_tokens = github_tokens)
    else:
        assert False


if __name__ == '__main__':
    a = [("mpetroff/pannellum", "d0c38ece315eb1d0bad73f768ca36d837ead160c"), ("fusionpbx/fusionpbx",
        "8b70c366d85b154b81491849237aadcb43bf77d9")]
    get_file_list(a)