import os
import tqdm
import random
import difflib
from util.io import load_json, load_pickle, save_json, save_pickle, save_text
from util.github import get_all_branch, get_latest_commit_before_date, get_file_list
from util.general import multi_thread, rule_based_filtering


class CommitCollection:

    def __init__(self, experiment_data_path: str, module_name: str, repo_file_list_dict_path):
        self.experiment_data_path = experiment_data_path
        self.repo_file_list_dict_path = repo_file_list_dict_path

        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)

        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        self.cve_list = [
            cve
            for cve, item in self.cve_data_all.items()
            if 'collected_repo' in item
        ]

        print(len(self.cve_list))

        self.repo_all = list({
            self.cve_data_all[cve]['collected_repo']
            for cve in self.cve_list
        })
        print(f'repo count: {len(self.repo_all)}')


    def start(self):
        # print(f'start search repo\'s all branch')
        # get_all_branch(self.repo_all)
        # print('end search repo\'s all branch\n')

        # 分支太多，只搜默认分支了
        # get_latest_commit_before_date(list({
        #     (self.cve_data_all[cve]['collected_repo'], '', self.cve_data_all[cve]['published_date'])
        #     for cve in self.cve_list
        #     # for branch in get_all_branch(self.cve_data_all[cve]['collected_repo'])
        # }))
        collected_commits = self.select_commit()
        
        # self.check_commit_accuracy(list(collected_commits.keys()))
        # self.check_commit_accuracy(list(load_json('experiment_data/repository/repository_collection/repo_from_url/collected_repos.json').keys()))
        # self.check_commit_accuracy(list(load_json('experiment_data/repository/repository_collection/repo_from_gpt/collected_repos.json').keys()))


    def select_commit(self):
        path = f'{self.module_path}/collected_commits'
        if os.path.exists(f'{path}.pkl'):
            return load_pickle(f'{path}.pkl')
        
        collected_commits = {}
        data = load_pickle(f'{self.experiment_data_path}/github/latest_commit_before_date_dict.pkl')
        for cve in tqdm.tqdm(self.cve_list):
            published_date = self.cve_data_all[cve]['published_date']
            repo = self.cve_data_all[cve]['collected_repo']
            if data[(repo, '', published_date)]:
                collected_commits[cve] = (repo, data[(repo, '', published_date)][0])

        save_json(f'{path}_1.json', collected_commits)
        save_pickle(f'{path}_1.pkl', collected_commits)

        # get_file_list(list(collected_commits.values()))

        # check一下commit是否为空，标准是rule_based_filtering筛选后有文件
        to_delete_list = []
        file_list_dict = load_pickle(self.repo_file_list_dict_path)
        for cve, v in tqdm.tqdm(collected_commits.items()):
            if v not in file_list_dict:
                print(cve)
                to_delete_list.append(cve)
                continue
            repo, sha = v
            if not any(not isdir and rule_based_filtering(file) for file, isdir in file_list_dict[(repo, sha)]):
                to_delete_list.append(cve)
        print(f'to_delete_list size: {len(to_delete_list)}')
        print(to_delete_list)
        print(f'before: {len(collected_commits)}')
        for cve in to_delete_list:
            del collected_commits[cve]
        print(f'after: {len(collected_commits)}')
                
        save_json(f'{path}.json', collected_commits)
        save_pickle(f'{path}.pkl', collected_commits)
        
        for cve, v in self.cve_data_all.items():
            if 'collected_commit' in v:
                del v['collected_commit']
            if cve in collected_commits:
                self.cve_data_all[cve]['collected_commit'] = collected_commits[cve][1]
            elif 'collected_repo' in v:
                del v['collected_repo']
                
        
        save_json(f'{self.experiment_data_path}/cve_data_all.json', self.cve_data_all)
        save_pickle(f'{self.experiment_data_path}/cve_data_all.pkl', self.cve_data_all)

        return collected_commits


    def check_commit_accuracy(self, cve_list: list):
        # 筛选repo和file相同的CVE
        def check_by_name():
            res_path = f'{self.module_path}/cve_list_check_by_content.json'
            # if os.path.exists(res_path):
            #     return load_json(res_path)
            correct_cnt = 0
            correct_cnt2 = 0
            total_count = len(cve_list)
            print('check size:', total_count)
            rest_cve_list = []

            corrected_gt = {}
            for cve in tqdm.tqdm(cve_list):
                if 'collected_commit' not in self.cve_data_all[cve]:
                    continue
                repo = self.cve_data_all[cve]['collected_repo']
                sha = self.cve_data_all[cve]['collected_commit']
                repo_gt = self.cve_data_all[cve]['repository']
                files_gt = [
                    file.lower()
                    for file in self.cve_data_all[cve]['vulnerability_files']
                ]
                cnt = 0
                tp = []
                for file, _ in file_list_dict[(repo, sha)]:
                    if cnt == len(files_gt): break
                    if file.lower() in files_gt:
                        cnt += 1
                        tp.append(file)
                if cnt == len(files_gt):
                    correct_cnt += 1
                    corrected_gt[cve] = {
                        'repo': repo,
                        'vulnerability_files': tp
                    }
                    if repo.lower() == repo_gt.lower():
                        correct_cnt2 += 1
                else:
                    rest_cve_list.append(cve)

            save_json(res_path, rest_cve_list)
            save_json(f'{self.module_path}/corrected_gt.json', corrected_gt)
            print(f'{correct_cnt}/{total_count} cve with same repo and file (ignore repo), {correct_cnt / total_count}')
            print(f'{correct_cnt2}/{total_count} cve with same repo and file, {correct_cnt2 / total_count}')

        file_list_dict = load_pickle(self.repo_file_list_dict_path)
        check_by_name()
        # self.check_different_repo_and_same_file(cve_list_check_by_content)

    # def check_different_repo_and_same_file(self, cve_list: list):
    #     # 先把需要比较的文件爬下来
    #     # to_scrapy_list = []
    #     # for cve in tqdm.tqdm(cve_list):
    #     #     for repo, sha in self.collected_commits[cve]:
    #     #         to_check_files_path = self.get_same_files_path(cve, repo, sha)
    #     #         if not to_check_files_path:
    #     #             to_check_files_path = self.get_similar_files_path(cve, repo, sha)
    #     #         for file in to_check_files_path:
    #     #             to_scrapy_list.append((cve, repo, file, sha))
        
    #     # def get_gt_file(to_scrapy_list_sub: list, token: str):
    #     #     for (cve, repo, file, sha) in tqdm.tqdm(to_scrapy_list_sub):
    #     #         dir = f'{self.module_root_path}/to_check_files/{cve}'
    #     #         file_name = repo.replace('/', '_') + '_' + file.replace('/', '_')
    #     #         save_path = f'{dir}/{file_name}'
    #     #         if os.path.exists(save_path):
    #     #             continue
    #     #         res = get_file_content(repo, sha, file, token)
    #     #         if res:
    #     #             # print(save_path)
    #     #             os.makedirs(dir, exist_ok = True)
    #     #             save_text(save_path, res)

    #     # print(f'to_scrapy_list size: {len(to_scrapy_list)}')
    #     # multi_thread(to_scrapy_list, get_gt_file, tokens = github_tokens)
        
    #     correct_commits = load_pickle(f'{self.module_root_path}/correct_commits_1.pkl')
    #     problem_cve_list = []       # 有问题的CVE，等之后有时间把这些CVE重跑一下，maybe数据能提升一些
    #     for cve in tqdm.tqdm(cve_list):
    #         # 先看有没有gt files
    #         gt_files_path = self.get_gt_files_path(cve)
    #         if not gt_files_path:
    #             # print(f'{cve} no gt')
    #             problem_cve_list.append((cve, 'no gt'))
    #             continue
    #         # 再看有没有待比较的文件
    #         if not os.path.exists(f'{self.module_root_path}/to_check_files/{cve}'):
    #             problem_cve_list.append((cve, 'no files'))
    #             continue
    #         for repo, sha in self.collected_commits[cve]:
    #             if cve in correct_commits and repo in correct_commits[cve]:     # 已经找到答案
    #                 continue
    #             to_check_files_path = [ 
    #                 f'{self.module_root_path}/to_check_files/{cve}/{file}'
    #                 for file in os.listdir(f'{self.module_root_path}/to_check_files/{cve}')
    #                 if file not in ['.DS_Store']
    #             ]
    #             threshold = 0.8
    #             if not to_check_files_path:     # commit为空，应该在collected中删掉这些
    #                 # save_text(f'{self.module_root_path}/to_delete_commit', (cve, repo, sha), 'a')
    #                 problem_cve_list.append((cve, 'no files'))
    #                 continue
    #             try:
    #                 max_simi, ans = 0, ''
    #                 for to_check_file_path in to_check_files_path:
    #                     content = load_file(to_check_file_path)
    #                     if len(content) > 300000:
    #                         print(f'1, {cve}, {repo}')
    #                         print(f'to_check_file_path: {to_check_file_path}')
    #                         print(f'gt_files_path: {gt_files_path}')
    #                         problem_cve_list.append((cve, f'large content1: {to_check_file_path}'))
    #                         continue
    #                     for gt_file_path in gt_files_path:
    #                         gt_content = load_file(gt_file_path)
    #                         if len(gt_content) > 300000:
    #                             print(f'2, {cve}, {repo}')
    #                             print(f'to_check_file_path: {to_check_file_path}')
    #                             print(f'gt_file_path: {gt_file_path}')
    #                             problem_cve_list.append((cve, f'large content2: {gt_file_path}'))
    #                             continue
    #                         simi = difflib.SequenceMatcher(None, gt_content, content).ratio()
    #                         if simi > max_simi:
    #                             max_simi = simi
    #                             ans = to_check_file_path
    #                 if max_simi > threshold:
    #                     if cve not in correct_commits:
    #                         correct_commits[cve] = {}
    #                     repo_updated = repo.replace('/', '—')
    #                     tp = len(f'{self.specified_repo_path}/{cve}/{repo_updated}/')
    #                     correct_commits[cve][repo] = ans[tp:]
    #             except Exception as e:
    #                 print(f'error587, {e}')     # 有一些类似链接的文件夹，在repo_file_list中isdir为false
    #                 problem_cve_list.append((cve, f'exception: {e}'))
    #                 continue

    #     save_json(f'{self.module_root_path}/correct_commits.json', correct_commits)
    #     save_pickle(f'{self.module_root_path}/correct_commits.pkl', correct_commits)

    #     save_text(f'{self.module_root_path}/problem_cve_list', problem_cve_list)
    #     save_pickle(f'{self.module_root_path}/problem_cve_list.pkl', problem_cve_list)

    
    # def get_gt_files_path(self, cve):
    #     gt_files_path = []
    #     for root, _, files in os.walk(f'{self.gt_content_path}/{cve}'):
    #         for file in files:
    #             if file not in ['.DS_Store']:
    #                 gt_files_path.append(os.path.join(root, file))
    #     return gt_files_path


    # def get_similar_files_path(self, cve, repo, sha):
    #     vul_files = {
    #         file.lower()
    #         for file in self.cve_data_all[cve]['file_list']
    #     }
    #     file_name_similarity = [
    #         (file, difflib.SequenceMatcher(None, vul_file, file.lower()).ratio())
    #         for file, isdir in self.repo_file_list[repo][sha]
    #         if not isdir and rule_based_filtering(file)
    #         for vul_file in vul_files
    #     ]
    #     file_name_similarity = sorted(file_name_similarity, key = lambda x: x[1], reverse = True)
    #     res = [ file
    #         for file, similarity in file_name_similarity[:5]
    #         if similarity > 0.8
    #     ]
    #     if not res:
    #         if file_name_similarity:
    #             res.append(file_name_similarity[0][0])
    #         else:
    #             return []
    #     return res
    #     repo_updated = repo.replace('/', '—')
    #     repo_dir = f'{self.specified_repo_path}/{cve}/{repo_updated}'
    #     if not os.path.exists(repo_dir):
    #         print(f'error333, {repo_dir} not exist')
    #         return []
    #     return [
    #         f'{repo_dir}/{file}'
    #         for file in res
    #     ]
            
    
    # def get_same_files_path(self, cve, repo, sha):
    #     vul_files = {
    #         file.lower()
    #         for file in self.cve_data_all[cve]['file_list']
    #     }
    #     res = []
    #     for file, _ in self.repo_file_list[repo][sha]:
    #         if file.lower() in vul_files:
    #             res.append(file)
    #     return res
    #     repo_updated = repo.replace('/', '—')
    #     repo_dir = f'{self.specified_repo_path}/{cve}/{repo_updated}'
    #     if not os.path.exists(repo_dir):
    #         print(f'error233, {repo_dir} not exist')
    #         return []
    #     return [
    #         f'{repo_dir}/{file}'
    #         for file in res
    #     ]