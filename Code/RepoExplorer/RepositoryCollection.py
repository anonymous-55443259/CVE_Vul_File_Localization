import os
import tqdm
import copy
import shutil
import random
from datetime import datetime
from util.io import *
from util.github import *
from util.gpt import calc_token, query_openai
from util.general import get_domain, multi_thread


class RepositoryCollection:

    def __init__(self, experiment_data_path: str, module_name: str):
        self.experiment_data_path = experiment_data_path

        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)

        self.prompt = load_json(f'{module_name}/prompt.json')

        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        self.cve_list = [
            cve
            for cve, item in self.cve_data_all.items()
            if 'augmented_desc' in item
        ]

        print(len(self.cve_list))

        self.repo_from_url = f'{self.module_path}/repo_from_url'
        os.makedirs(self.repo_from_url, exist_ok = True)

        self.repo_from_gpt = f'{self.module_path}/repo_from_gpt'
        os.makedirs(self.repo_from_gpt, exist_ok = True)

        os.makedirs(f'{self.repo_from_gpt}/prompt', exist_ok = True)
        os.makedirs(f'{self.repo_from_gpt}/result', exist_ok = True)

        self.max_try = 10


    def start(self):
        # self.sync()

        # self.search_reference_url()
        # self.check_result(self.repo_from_url)

        self.query_gpt()
        # self.check_result(self.repo_from_gpt)

        # self.union_result()


    # def sync(self):
    #     dir_list = [
    #         (f'{self.repo_from_gpt}/prompt', f'{self.module_path}/deprecated/repo_from_gpt/prompt'),
    #         (f'{self.repo_from_gpt}/result', f'{self.module_path}/deprecated/repo_from_gpt/result'),
    #     ]
    #     for source, dest in dir_list:
    #         file_list = os.listdir(source)
    #         if '.DS_Store' in file_list:
    #             file_list.remove('.DS_Store')
    #         for file in file_list:
    #             cve = file.split('.')[0]
    #             if cve not in self.cve_list:
    #                 copy_file(f'{source}/{file}', f'{dest}/{file}')
    #                 os.remove(f'{source}/{file}')


    def search_reference_url(self):
        # 搜索cve的reference url, 如果有github url则提取repo
        print(f'start search reference url, cve count: {len(self.cve_list)}')
        
        res = {}
        for cve in tqdm.tqdm(self.cve_list):
            for url in self.cve_data_all[cve]['reference_list']:
                if get_domain(url) == 'github.com':
                    repo_full_name = '/'.join(url.split('/')[3:5])
                    if '#' in repo_full_name:
                        repo_full_name = repo_full_name[:repo_full_name.find('#')]
                    if cve in res:
                        res[cve].add(repo_full_name)
                    else:
                        res[cve] = {repo_full_name}
            if cve in res:
                res[cve] = list(res[cve])
        
        print(f'found {len(res)}/{len(self.cve_list)}, {len(self.cve_list) - len(res)} rest')
        print('end search reference url\n')

        # 检查提取到的repo是否存在
        print('start check if the repo exists')
        check_repo_exist(list({
            repo
            for repos in res.values()
            for repo in repos
        }))
        repo_to_delete = []
        for cve, repos in copy.deepcopy(res).items():
            repo_to_delete = []
            for repo in repos:
                if not check_repo_exist(repo):
                    repo_to_delete.append(repo)
            for repo in repo_to_delete:
                res[cve].remove(repo)
            if len(res[cve]) != 1:
                del res[cve]
                print('del', cve)
            else:
                res[cve] = res[cve][0]
        print('end check if the repo exists')
        
        print(f'found {len(res)}/{len(self.cve_list)}, {len(self.cve_list) - len(res)} rest')
        save_json(f'{self.repo_from_url}/collected_repos.json', res)
        save_pickle(f'{self.repo_from_url}/collected_repos.pkl', res)


    def check_result(self, target: str, update_to_cve_data_all = False):
        print('start check repo')

        incorrect_cve_dic = {}
        data = load_pickle(f'{target}/collected_repos.pkl')
        for cve, repos in tqdm.tqdm(data.items()):
            flag = False
            for repo in repos:
                if any(repo.lower() == ans.lower() for ans in self.cve_data_all[cve]['repo_list']):
                    flag = True
                    break
            if not flag:
                incorrect_cve_dic[cve] = repos
        print(f'first check: {len(incorrect_cve_dic)} cve incorrect')

        def get_latest_and_original_repo_name(repo_name: str, token: str):
            if repo_name not in repo_past_name:
                latest_repo_name = get_latest_repo_name(repo_name, token)
                original_repo_name = get_original_repo_name(repo_name, token)
                repo_past_name[repo_name] = {}
                repo_past_name[repo_name]['latest_name'] = latest_repo_name
                repo_past_name[repo_name]['original_name'] = original_repo_name
            return (
                repo_past_name[repo_name]['latest_name'],
                repo_past_name[repo_name]['original_name']
            )
        
        def check_repo_name(cve_list: list, token: str):
            for cve in tqdm.tqdm(cve_list):
                flag = False
                for repo in incorrect_cve_dic[cve]:
                    past_name = get_latest_and_original_repo_name(repo, token)
                    for repo_ans in self.cve_data_all[cve]['repo_list']:
                        ans_past_name = get_latest_and_original_repo_name(repo_ans, token)
                        if past_name[0].lower() == ans_past_name[0].lower() or past_name[1].lower() == ans_past_name[1].lower():
                            flag = True
                            break
                if flag:
                    del incorrect_cve_dic[cve]
        
        # 检查是否是改过名的或fork的repo
        if os.path.exists(f'{self.repo_data_path}/repo_past_name.json'):
            repo_past_name = load_json(f'{self.repo_data_path}/repo_past_name.json')
        else:
            repo_past_name = {}

        multi_thread([cve for cve, _ in incorrect_cve_dic.items()], check_repo_name, tokens = github_tokens)

        # if incorrect_cve_dic:
        #     save_json(f'{target}/incorrect_repo.json', incorrect_cve_dic)
        #     save_pickle(f'{target}/incorrect_repo.pkl', incorrect_cve_dic)
        
        save_json(f'{self.repo_data_path}/repo_past_name.json', repo_past_name)
        save_pickle(f'{self.repo_data_path}/repo_past_name.pkl', repo_past_name)

        if update_to_cve_data_all:
            for cve in data:
                self.cve_data_all[cve]['collected_repo_correction'] = cve not in incorrect_cve_dic
            save_json(f'{self.project_root_path}/cve_data_all.json', self.cve_data_all)
            save_pickle(f'{self.project_root_path}/cve_data_all.pkl', self.cve_data_all)

        print('accuracy: {:.2f}%,'.format((len(data) - len(incorrect_cve_dic)) / len(data) * 100), 
              f'{len(data) - len(incorrect_cve_dic)}/{len(data)}, {len(incorrect_cve_dic)} rest')
        print('end check repo')


    def query_gpt(self):

        def generate_prompt():
            tp = copy.deepcopy(self.prompt)
            for cve in tqdm.tqdm(cve_list_rest):
                tp[1]['content'] = f'CVE ID: {cve}\nproduct: {", ".join(self.cve_data_all[cve]["cpe_product"])}'
                save_json(f'{self.repo_from_gpt}/prompt/{cve}.json', tp)

        def anonymous(cve_list_sub: list):
            # for cve in tqdm.tqdm(cve_list_sub):
            # for cve in tqdm.tqdm(random.sample(cve_list_sub, 1)):
            for cve in tqdm.tqdm(['CVE-2016-10648']):
                dir = f'{self.repo_from_gpt}/result/{cve}'
                os.makedirs(dir, exist_ok = True)
                res_path = f'{dir}/final.json'
                if os.path.exists(res_path):
                    continue
                max = -1
                for file in os.listdir(dir):
                    if file in ['.DS_Store']: continue
                    tp = int(file[0])
                    if tp > max:
                        max = tp
                if max != -1:
                    cnt = max + 1
                    # print(f'233, cnt = {cnt}')
                    messages = load_json(f'{dir}/{max}.json')
                else:
                    cnt = 1
                    messages = load_json(f'{self.repo_from_gpt}/prompt/{cve}.json')
                while cnt < self.max_try:
                    try:
                        res = query_openai(
                            messages,
                            model = 'gpt-4o-mini',
                            tool_choice = None
                        )
                        repo = res.content.replace('"', '')
                        messages.append({
                            'role': 'assistant',
                            'content': repo
                        })
                        if check_repo_exist(repo):
                            save_json(res_path, messages)
                            break
                        else:
                            messages.append({
                                'role': 'user',
                                'content': 'The Github repository you provided does not exist, please provide a new repository name. Maybe you can provide a forked version of the repository. Note that only output the repository name, and do not out any prompt information.'
                            })
                            save_json(f'{dir}/{cnt}.json', messages)
                    except Exception as e:
                        save_text(f'{self.repo_from_gpt}/result/error_list', f'{cve}\n\n{e}', 'a')
                        break
                    cnt += 1
                else:
                    if not os.path.exists(res_path):
                        pass

        cve_list_done = list(load_pickle(f'{self.repo_from_url}/collected_repos.pkl').keys())
        cve_list_gpt = set(self.cve_list) - set(cve_list_done)
        cve_list_rest = copy.deepcopy(cve_list_gpt)
        # generate_prompt()

        for cve in cve_list_gpt:
            if os.path.exists(f'{self.repo_from_gpt}/result/{cve}/final.json') or os.path.exists(f'{self.repo_from_gpt}/result/{cve}/9.json'):
                cve_list_rest.remove(cve)
        
        if cve_list_rest:
            print(f'start query gpt, rest size: {len(cve_list_rest)}')
            multi_thread(list(cve_list_rest), anonymous, chunk_size = 1000)
            # multi_thread(list(cve_list_rest), anonymous, chunk_size = int(len(cve_list_rest) / 6))
            print('end query gpt')
        

        res = {}
        for cve in os.listdir(f'{self.repo_from_gpt}/result'):
            path = f'{self.repo_from_gpt}/result/{cve}/final.json'
            if cve in ['.DS_Store', 'error_list'] or cve in cve_list_done or not os.path.exists(path):
                continue
            res[cve] = load_json(path)[-1]['content']
        
        save_json(f'{self.repo_from_gpt}/collected_repos.json', res)
        save_pickle(f'{self.repo_from_gpt}/collected_repos.pkl', res)
        print(f'get {len(res)}/{len(cve_list_gpt)}, {len(cve_list_gpt) - len(res)} rest')


    def union_result(self):
        path_list = [self.repo_from_url, self.repo_from_gpt]
        res = {}
        for path in path_list:
            full_path = f'{path}/collected_repos.json'
            data = load_json(full_path)
            # print(len(data))
            res.update(data)

        # print(len(res))
        save_json(f'{self.module_path}/collected_repos.json', res)
        save_pickle(f'{self.module_path}/collected_repos.pkl', res)
        
        # self.check_result(self.module_root_path)

        not_found = 0
        for cve in self.cve_data_all:
            if 'collected_repo' in self.cve_data_all[cve]:
                del self.cve_data_all[cve]['collected_repo']
            if cve in self.cve_list and cve not in res:
                # print(cve, 'not found')
                not_found += 1

        for cve, repo in res.items():
            self.cve_data_all[cve]['collected_repo'] = repo
        print(f'{len(res)}/{len(self.cve_list)} found repo, {not_found} not found')
        save_json(f'{self.experiment_data_path}/cve_data_all.json', self.cve_data_all)
        save_pickle(f'{self.experiment_data_path}/cve_data_all.pkl', self.cve_data_all)