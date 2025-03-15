import os
import tqdm
import random
import shutil
from util.io import *
from util.github import *
from util.general import multi_thread


class RepositoryClone:

    def __init__(self, experiment_data_path: str, module_name: str, repo_file_list_dict_path: str):
        self.experiment_data_path = experiment_data_path
        self.repo_file_list_dict_path = repo_file_list_dict_path

        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)

        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        self.cve_list = [
            cve
            for cve in load_json(f'{experiment_data_path}/repository/commit_collection/corrected_gt.json')
        ]
        print(len(self.cve_list))

        self.repo_all = list({
            self.cve_data_all[cve]['collected_repo']
            for cve in self.cve_list
        })
        print(f'repo count: {len(self.repo_all)}')

        self.common_dir = f'{self.module_path}/common'
        os.makedirs(self.common_dir, exist_ok = True)

        self.instance_dir = f'{self.module_path}/instance'
        os.makedirs(self.instance_dir, exist_ok = True)


    def start(self):
        self.clone_common_repo()
        self.clone_instance_repo()
        self.verify_specified_repo()
        self.clone_instance_repo()

    
    def clone_common_repo(self):
        def anonymous(repo_list_sub: dict):
            for repo in tqdm.tqdm(repo_list_sub):
                # print(repo_full_name)
                repo_updated = repo.replace('/', '__')
                # print(repo_updated)

                dest_dir = f'{self.common_dir}/{repo_updated}'
                if os.path.exists(dest_dir):
                    continue
                # cmd = f'git clone --depth=1 {url}.git {path}/{repo_updated}'
                # tp = f'/Volumes/Data/Vulnerability_Localization/experiment_data/repository/repo_all/{repo.replace("/", "—")}'
                # if os.path.exists(tp):
                #     shutil.move(tp, f'{self.common_dir}/{repo_updated}')
                cmd = f'git clone --depth=1 git@github.com:{repo}.git {dest_dir}'
                if os.system(cmd) != 0:
                    save_text(f'{self.common_dir}/error_list', repo, 'a')
        
        to_do = [
            repo
            for repo in self.repo_all
            if not os.path.exists(f"{self.common_dir}/{repo.replace('/', '__')}")
        ]
        if to_do:
            print(f'to_do: {len(to_do)}')
            # multi_thread(to_do, anonymous, chunk_size = int(len(to_do) / 4))
            multi_thread(to_do, anonymous, chunk_size = 1200)

    
    def clone_instance_repo(self):

        def anonymous(repo_list_sub: dict):
            for repo in tqdm.tqdm(repo_list_sub):
                # if repo == 'torvalds/linux':
                #     continue
                repo_updated = repo.replace('/', '__')
                for sha in rest_specified_repo_dic[repo]:
                    dest_path_repo = f'{self.instance_dir}/{repo_updated}__{sha}'
                    source_path_repo = f'{self.common_dir}/{repo_updated}'
                    if os.path.exists(dest_path_repo) or not os.path.exists(source_path_repo):
                        continue

                    cmd1 = f'cd {source_path_repo} && git fetch origin {sha} --depth=1 1>/dev/null'
                    # cmd2 = f'cd {source_path_repo} && git clean -fd && git checkout . 1>/dev/null'
                    cmd2 = f'cd {source_path_repo} && git clean -fd 1>/dev/null'
                    cmd3 = f'cd {source_path_repo} && git checkout {sha} 1>/dev/null'
                    print('run cmd1', cmd1)
                    if os.system(cmd1) != 0:
                        save_text(f'{self.instance_dir}/error_list', f'cmd1, {repo}, {sha}', 'a')
                        print('cmd1 error')
                        continue
                    print('run cmd2', cmd2)
                    if os.system(cmd2) != 0:
                        save_text(f'{self.instance_dir}/error_list', f'cmd2, {repo}, {sha}', 'a')
                        print('cmd2 error')
                        continue
                    print('run cmd3', cmd3)
                    if os.system(cmd3) != 0:
                        save_text(f'{self.instance_dir}/error_list', f'cmd3, {repo}, {sha}', 'a')
                        print('cmd3 error')
                        continue

                    cmd = f"rsync -a --exclude='.git' {source_path_repo} {self.instance_dir}"
                    
                    print('run cmd4', cmd)
                    if os.system(cmd) != 0:
                        save_text(f'{self.instance_dir}/error_list', f'cmd4, {repo}, {sha}', 'a')
                        print('cmd4 error')

                    os.rename(f'{self.instance_dir}/{repo_updated}', dest_path_repo)
        
        to_do = list({
            (self.cve_data_all[cve]['collected_repo'], self.cve_data_all[cve]['collected_commit'])
            for cve in self.cve_list
            if not os.path.exists(f'{self.instance_dir}/{self.cve_data_all[cve]["collected_repo"].replace("/", "__")}__{self.cve_data_all[cve]["collected_commit"]}')
        })
        if to_do:
            print(f'rest cnt: {len(to_do)}')
            rest_specified_repo_dic = {}
            for (repo, sha) in to_do:
                rest_specified_repo_dic.setdefault(repo, []).append(sha)
        
            repos = list(rest_specified_repo_dic.keys())
            if repos:
                multi_thread(repos, anonymous, chunk_size = 300)


    def verify_specified_repo(self):
        total_count = 0
        error_count = 0
        error_list = []
        file_list_dict = load_pickle(self.repo_file_list_dict_path)
        to_do = list({
            (self.cve_data_all[cve]['collected_repo'], self.cve_data_all[cve]['collected_commit'])
            for cve in self.cve_list
        })
        for (repo, sha) in tqdm.tqdm(to_do):
            repo_updated = repo.replace('/', '__')
            path = f'{self.instance_dir}/{repo_updated}__{sha}'
            if not os.path.exists(path):
                # save_text(f'{self.module_path}/error_list', f'{cve} {repo} not exist', 'a')
                error_list.append((repo, sha))
                error_count += 1
                continue
            total_count += 1
            for file_path, _ in file_list_dict[(repo, sha)]:
                if not os.path.islink(f'{path}/{file_path}') and not os.path.exists(f'{path}/{file_path}'):
                    error_list.append((repo, sha))
                    print(repo, sha)
                    # try:
                    #     print('start delete original data')
                    #     shutil.rmtree(path)
                    #     print('end delete original data')
                    # except Exception as e:
                    #     print('error', path)
                    error_count += 1
                    break
        print(f'total_count: {total_count}, error_count: {error_count}')

        save_json(f'{self.instance_dir}/specified_repo_error_list.json', error_list)