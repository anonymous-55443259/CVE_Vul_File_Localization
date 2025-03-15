import os

import pandas as pd

from util.io import load_json, save_json, load_pickle
from util.github import get_repo_from_commit_url, check_repo_exist, get_file_content
from util.general import GREEN, RESET


class GroundTruth:

    def __init__(self, experiment_data_path: str, module_name: str):
        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)


    def start(self):
        self.jialong()
        # self.jiamou()
        # self.combine()

    
    def jialong(self):
        df = pd.read_excel(f'{self.module_path}/2024.xlsx')
        new = []

        for index, row in df.iterrows():
            if '2024' not in row['id']:
                continue
            new.append([row['id'], row['link'], row['risky function']])

        new_df = pd.DataFrame(new, columns=['id', 'patch', 'fun'])

        new_col = []
        dict_res = {}
        for index, row in new_df.iterrows():
            files = row['fun']
            all = set()
            for file in files.split('\n'):
                tp = file[file.find('.') + 1:]
                if tp == '':
                    continue
                tp = tp.split('/')
                if len(tp) >= 2:
                    last = len(tp) - 1
                    pos = -1
                    for index in range(last, -1, -1):
                        if '.' in tp[index] and (index == 0 or '.' not in tp[index - 1]):
                            pos = index
                            break
                    if pos != -1:
                        res = '/'.join(tp[:pos + 1])
                        # print(print(row['id'], file, end = '\n'), res)
                        # sys.exit()
                    else:
                        print(row['id'], file, end = '\n')
                else:
                    # print(row['id'], tp, end = '\n')
                    res = tp[0]
                all.add(res)
            # print(row['id'], ', '.join(all))
            new_col.append(','.join(all))
            
            # 存在一个CVE有多个commit的情况，扔掉这些数据
            if row['id'] in dict_res:
                # for item in dict_res[row['id']]:
                #     if get_repo_from_commit_url(row['patch']) == item['repository']:
                #         item['commits'].append(row['patch'])
                #         item['vulnerability_files'] = list(all | set(item['vulnerability_files']))
                #         break
                # else:
                #     dict_res[row['id']].append({
                #         "repository": get_repo_from_commit_url(row['patch']),
                #         "commits": [row['patch']],
                #         "vulnerability_files": list(all)
                #     })
                del dict_res[row['id']]
            else:
                dict_res[row['id']] = {
                    "repository": get_repo_from_commit_url(row['patch']),
                    "commits": [row['patch']],
                    "vulnerability_files": list(all)
                }
        
        new_df['file'] = new_col
        new_df.to_csv(f'{self.module_path}/jialong_cleaned.csv')
        save_json(f'{self.module_path}/jialong_candidates.json', dict_res)
        cnt = 0
        for item in dict_res.values():
            if len(item['vulnerability_files']) > 1:
                cnt += 1
        print(f'{GREEN}jia long: {len(dict_res)} candidate CVE, {cnt} with multi vul files{RESET}')

        # self.filter(dict_res)

    
    def jiamou(self):
        data = load_pickle(f'{self.module_path}/ground_truth.pkl')
        cnt = 0
        res = {}
        for k, v in data.items():
            repo = str(list(v['vulnerability_files'].keys())[0])
            if (
                len(v['vulnerability_files']) == 1
                # len(v['commits']) == 1 and
                # all(item in v['commits'][0] for item in ['github.com', '/commit/', repo]) and
                # os.path.exists(f'/Volumes/Data/Vulnerability_Localization/experiment_data/ground_truth/gt_file_content/{k}')
            ):
                cnt += 1
                res[k] = {
                    "repository": repo,
                    "commits": v['commits'],
                    "vulnerability_files": list(v['vulnerability_files'].values())[0]
                }

        self.filter(res, True)
        print(f'{GREEN}jia mou: {len(res)} candidate CVE{RESET}')
        save_json(f'{self.module_path}/jiamou_candidates.json', res)


    def filter(self, data: dict, delinvalid: bool = False):
        # repo存在
        check_repo_exist([
            item['repository']
            for item in data.values()
        ])

        tp = set()
        for cve, item in data.items():
            repo = item['repository']
            if not check_repo_exist(repo):
                # print(cve)
                tp.add(cve)

        if delinvalid:
            for cve in tp:
                del data[cve]
                print(f'del {cve}')
        
        # 确保file能爬下来
        # get_file_content([
        #     (item['repository'], commit[commit.find('/commit/') + 8:], file)
        #     for item in data.values()
        #     for commit in item['commits']
        #     for file in item['vulnerability_files']
        # ])

        # tp.clear()
        # repo_file_content_dict = load_pickle('experiment_data/github/repo_file_content_dict.pkl')
        # for (k, a, b, c) in [
        #     (k, item['repository'], commit[commit.find('/commit/') + 8:], file)
        #     for k, item in data.items()
        #     for commit in item['commits']
        #     for file in item['vulnerability_files']
        # ]:
        #     if (a, b, c) not in repo_file_content_dict:
        #         # print(k)
        #         tp.add(k)

        # if delinvalid:
        #     for cve in tp:
        #         del data[cve]


    def combine(self):
        a = load_json(f'{self.module_path}/jialong_candidates.json')
        b = load_json(f'{self.module_path}/jiamou_candidates.json')
        # print(len(a))
        # print(len(b))
        # print(len(set(a.keys()) | set(b.keys())))
        # for cve in a:
        #     if cve in b:
        #         print(cve)
        
        a.update(b)
        cnt = 0
        for item in a.values():
            if len(item['vulnerability_files']) > 1:
                cnt += 1
        print(f'{GREEN}all: {len(a)} candidate CVE, {cnt} with multi vul files{RESET}')
        save_json(f'{self.module_path}/all_candidates.json', a)