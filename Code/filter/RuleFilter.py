import os
import re
import ast
import sys
import tqdm
import copy
import random
from util.gpt import query_openai
from util.general import print_location
from util.io import load_pickle, load_json, save_json, load_file, copy_file, save_text
from util.general import multi_thread, rule_based_filtering, generate_tree_str


class RuleFilter:

    def __init__(self, experiment_data_path: str, module_name: str, repo_file_list_dict_path, repo_instance_dir: str):
        self.experiment_data_path = experiment_data_path
        self.module_name = module_name
        self.repo_file_list_dict_path = repo_file_list_dict_path
        self.repo_instance_dir = repo_instance_dir

        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)

        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        self.cve_list = [
            cve
            for cve in load_json(f'{experiment_data_path}/repository/commit_collection/corrected_gt.json')
        ]
        print(len(self.cve_list))

        self.keywords_rule = f'{self.module_path}/keywords/rule'
        os.makedirs(self.keywords_rule, exist_ok = True)
        self.keywords_prompt_dir = f'{self.module_path}/keywords/llm/prompt'
        os.makedirs(self.keywords_prompt_dir, exist_ok = True)
        self.keywords_result_dir = f'{self.module_path}/keywords/llm/result'
        os.makedirs(self.keywords_result_dir, exist_ok = True)
        self.keywords_handled_result_dir = f'{self.module_path}/keywords/llm/handled_result'
        os.makedirs(self.keywords_handled_result_dir, exist_ok = True)

        self.name_result_dir = f'{self.module_path}/filter_result/keywords/name'
        os.makedirs(self.name_result_dir, exist_ok = True)
        self.content_result_dir = f'{self.module_path}/filter_result/keywords/content'
        os.makedirs(self.content_result_dir, exist_ok = True)
        self.keywords_all_result_dir = f'{self.module_path}/filter_result/keywords/all'
        os.makedirs(self.keywords_all_result_dir, exist_ok = True)

        # self.filter_prompt_dir = f'{self.module_path}/filter_result/llm/prompt'
        # os.makedirs(self.filter_prompt_dir, exist_ok = True)
        # self.llm_filter_result_dir = f'{self.module_path}/filter_result/llm/result'
        # os.makedirs(self.llm_filter_result_dir, exist_ok = True)
        # self.llm_filter_handled_result_dir = f'{self.module_path}/filter_result/llm/handled_result'
        # os.makedirs(self.llm_filter_handled_result_dir, exist_ok = True)

        # self.all_result_dir = f'{self.module_path}/filter_result/all'
        # os.makedirs(self.all_result_dir, exist_ok = True)


    def start(self):
        # self.generate_keywords_by_rule()
        # self.generate_keywords_by_llm()
        # self.filter_by_keywords()
        # self.filter_by_llm()
        self.check_recall(self.name_result_dir)
        self.check_recall(self.content_result_dir)
        self.union_result()
        self.check_recall(self.keywords_all_result_dir)


    def generate_keywords_by_rule(self):
        for cve in tqdm.tqdm(self.cve_list):
            desc = self.cve_data_all[cve]['augmented_desc']
            words = re.split(r'[\s]+', desc)
            words = list(set(words))
            res = []
            for word in words:
                if word[-1] == '.' or word[-1] == ',':
                    word = word[:-1]
                if word and any(word[0] == c for c in ['"', '`', "'", '(']):
                    word = word[1:]
                if word and any(word[-1] == c for c in ['"', '`', "'", ')']):
                    word = word[:-1]
                word = word.lower()
                if len(word) > 1:
                    res.append(word)
            res = list(set(res))
            save_json(f'{self.keywords_rule}/{cve}.json', res)


    def generate_keywords_by_llm(self):
        def generate_prompt():
            for cve in self.cve_list:
                tp = copy.deepcopy(load_json(f'{self.module_name}/prompt_keywords.json'))
                tp[1]['content'] = self.cve_data_all[cve]['augmented_desc']
                save_json(f'{self.keywords_prompt_dir}/{cve}.json', tp)

        def anonymous(cve_list: list):
            # for cve in tqdm.tqdm(cve_list):
            for cve in tqdm.tqdm(random.sample(cve_list, 1)):
            # for cve in tqdm.tqdm(['CVE-2001-1009']):
                messages = load_json(f'{self.keywords_prompt_dir}/{cve}.json')
                try:
                    res = query_openai(
                        messages,
                        tool_choice = None,
                        model = 'gpt-4o-mini'
                    )
                    messages.append({
                        'role': 'assistant',
                        'content': res.content
                    })
                    save_json(f'{self.keywords_result_dir}/{cve}.json', messages)
                except Exception as e:
                    pass
        
        def handle_result():
            for file in os.listdir(self.keywords_result_dir):
                if 'CVE' not in file: continue
                # if os.path.exists(f'{self.keywords_handled_result_dir}/{file}'):
                #     continue
                tp = load_json(f'{self.keywords_result_dir}/{file}')[-1]['content'].replace('```python', '').replace('```', '')
                try:
                    keywords = ast.literal_eval(tp)
                    keywords = list({
                        word    # 这里控制大小写
                        for word in keywords
                        if len(word) > 1
                    })
                    save_json(f'{self.keywords_handled_result_dir}/{file}', keywords)
                except Exception as e:
                    print_location(f'{self.keywords_result_dir}/{file}, {e}')
 

        # generate_prompt()

        # rest_cve_list = [
        #     cve
        #     for cve in self.cve_list
        #     if not os.path.exists(f'{self.keywords_result_dir}/{cve}.json')
        # ]
        # if rest_cve_list:
        #     print(f'rest size: {len(rest_cve_list)}')
        #     multi_thread(rest_cve_list, anonymous, chunk_size = int(len(rest_cve_list) / 4))
        #     # multi_thread(rest_cve_list, anonymous, chunk_size = 2500)
        
        handle_result()

    
    def filter_by_keywords(self):
        def anonymous(cve_list: list):
            repo_file_list_dict = load_pickle(self.repo_file_list_dict_path)
            for cve in tqdm.tqdm(cve_list):
            # for cve in tqdm.tqdm(random.sample(cve_list, 1)):
                if not os.path.exists(f'{self.keywords_handled_result_dir}/{cve}.json'):
                    print_location(f'{cve} keywords not exist')
                    continue
                # if os.path.exists(f'{self.content_result_dir}_backup/{cve}.json'):
                #     copy_file(f'{self.content_result_dir}_backup/{cve}.json', f'{self.content_result_dir}/{cve}.json')
                #     continue
                keywords = load_json(f'{self.keywords_handled_result_dir}/{cve}.json')

                repo = self.cve_data_all[cve]['collected_repo']
                sha = self.cve_data_all[cve]['collected_commit']
                repo_dir = f'{self.repo_instance_dir}/{repo.replace("/", "__")}__{sha}'
                if not os.path.exists(repo_dir):
                    print_location(f'{cve} repo not exist')
                    continue

                res_name = []
                res_content = []
                for file, isdir in repo_file_list_dict[(repo, sha)]:
                    if isdir or not rule_based_filtering(file): continue
                    
                    if any(file.endswith(f'/{keyword}') or file == keyword for keyword in keywords if '.' in keyword):
                        res_name.append(file)
                    
                    try:
                        tp = load_file(f'{repo_dir}/{file}')
                        cnt_content = len([
                            keyword
                            for keyword in keywords
                            if keyword.lower() not in content_filter_words and keyword in tp
                        ])
                        if cnt_content > 0:
                            res_content.append((file, cnt_content))
                    except Exception as e:
                        pass
                
                if res_name:
                    save_json(f'{self.name_result_dir}/{cve}.json', res_name)
                if res_content:
                    res_content = sorted(res_content, key = lambda x: x[1], reverse = True)
                    save_json(f'{self.content_result_dir}/{cve}.json', res_content)

        
        rest_cve_list = [
            cve
            for cve in self.cve_list
            # if not os.path.exists(f'{self.content_result_dir}/{cve}.json')
            if not any(os.path.exists(f'{path}/{cve}.json') for path in [self.name_result_dir, self.content_result_dir])
        ]
        if rest_cve_list:
            print(f'rest size: {len(rest_cve_list)}')
            content_filter_words = load_json(f'{self.module_name}/content_filter_words.json')
            # multi_thread(rest_cve_list, anonymous, chunk_size = int(len(rest_cve_list) / 4))
            multi_thread(rest_cve_list, anonymous, chunk_size = 10000)


    def filter_by_llm(self):
        def generate_prompt():
            prompt = load_json(f'{self.module_name}/prompt_filter.json')
            for cve in tqdm.tqdm(self.cve_list):
                # if os.path.exists(f'{self.filter_prompt_dir}/{cve}.json'):
                #     continue
                desc = self.cve_data_all[cve]['augmented_desc']
                repo = self.cve_data_all[cve]['collected_repo']
                sha = self.cve_data_all[cve]['collected_commit']
                if not os.path.exists(f'{self.filter_prompt_dir}/{cve}_file_list.json'):
                    exclude_files = load_json(f'{self.keywords_all_result_dir}/{cve}.json') if os.path.exists(f'{self.keywords_all_result_dir}/{cve}.json') else []
                    file_list = [
                        file
                        for file, isdir in repo_file_list_dict[(repo, sha)]
                        if not isdir and rule_based_filtering(file) and file not in exclude_files
                    ]
                    save_json(f'{self.filter_prompt_dir}/{cve}_file_list.json', file_list)
                else:
                    file_list = load_json(f'{self.filter_prompt_dir}/{cve}_file_list.json')
                content = f'CVE Description:\n{desc}\n\nfile list:\n{generate_tree_str(file_list)}'
                save_text(f'{self.filter_prompt_dir}/{cve}_user_prompt.md', content)
                tp = copy.deepcopy(prompt)
                tp[1]['content'] = content
                save_json(f'{self.filter_prompt_dir}/{cve}.json', tp)

        def anonymous(cve_list: list):
            # for cve in tqdm.tqdm(cve_list):
            # for cve in tqdm.tqdm(random.sample(cve_list, 1)):
            for cve in tqdm.tqdm(['CVE-2018-8809']):
                if os.path.exists(f'{self.llm_filter_result_dir}/{cve}.json'):
                    continue
                messages = load_json(f'{self.filter_prompt_dir}/{cve}.json')
                try:
                    res = query_openai(
                        messages,
                        tool_choice = None,
                        model = 'gpt-4o-mini'
                    )
                    messages.append({
                        'role': 'assistant',
                        'content': res.content
                    })
                    save_json(f'{self.llm_filter_result_dir}/{cve}.json', messages)
                except Exception as e:
                    pass
        
        def handle_result():
            for file in os.listdir(self.llm_filter_result_dir):
                if 'CVE' not in file: continue
                # if os.path.exists(f'{self.llm_filter_handled_result_dir}/{file}'):
                #     continue
                tp = load_json(f'{self.llm_filter_result_dir}/{file}')[-1]['content'].replace('```python', '').replace('```', '')
                try:
                    files = ast.literal_eval(tp)
                    save_json(f'{self.llm_filter_handled_result_dir}/{file}', files)
                except Exception as e:
                    print_location(f'{self.llm_filter_result_dir}/{file}, {e}')

        # repo_file_list_dict = load_pickle(self.repo_file_list_dict_path)
        # generate_prompt()

        rest_cve_list = [
            cve
            for cve in self.cve_list
            if not os.path.exists(f'{self.llm_filter_result_dir}/{cve}.json')
        ]
        if rest_cve_list:
            print(f'rest size: {len(rest_cve_list)}')
            # multi_thread(rest_cve_list, anonymous, chunk_size = int(len(rest_cve_list) / 4))
            multi_thread(rest_cve_list, anonymous, chunk_size = 1000)
            handle_result()


    def union_result(self):
        for cve in tqdm.tqdm(self.cve_list):
            res = set()
            if os.path.exists(f'{self.name_result_dir}/{cve}.json'):
                for file in load_json(f'{self.name_result_dir}/{cve}.json'):
                    res.add(file)
            if os.path.exists(f'{self.content_result_dir}/{cve}.json'):
                f = len(res) != 0
                for index, (file, cnt) in enumerate(load_json(f'{self.content_result_dir}/{cve}.json')):
                    if f:
                        if index >= 20:
                            break
                    else:
                        if index >= 200 or cnt == 1:
                            break
                    res.add(file)
            # if os.path.exists(f'{self.llm_filter_handled_result_dir}/{cve}.json'):
            #     for file in load_json(f'{self.llm_filter_handled_result_dir}/{cve}.json'):
            #         res.add(file)
            if res:
                save_json(f'{self.keywords_all_result_dir}/{cve}.json', list(res))
                # save_json(f'{self.all_result_dir}/{cve}.json', list(res))


    def check_recall(self, dir: str):
        total_cnt = 0
        corr_cnt = 0
        for cve in tqdm.tqdm(self.cve_list):
            if not os.path.exists(f'{dir}/{cve}.json'):
                continue
            total_cnt += 1
            data = load_json(f'{dir}/{cve}.json')
            f = False
            tp = [
                file.lower()
                for file in self.cve_data_all[cve]['vulnerability_files']
            ]
            for file in data:
                if type(file) != str:
                    # keywords = file[2]
                    file = file[0]
                    # if file[1] == 1:
                    #     break
                if file.lower() in tp:
                    # if file not in tp:
                    #     print(cve, file, self.cve_data_all[cve]['vulnerability_files'])
                    #     sys.exit()
                    f = True
                    break
            if f:
                corr_cnt += 1
            # else:
            #     for key in keywords:
            #         if key in count:
            #             count[key] += 1
            #         else:
            #             count[key] = 1
                # print(self.cve_data_all[cve]['vulnerability_files'])
                # print(f'{self.keywords_handled_result_dir}/{cve}.json')
                # print(f'{self.path_result_dir}/{cve}.json')
                # print('_' * 100)
        
        # count = dict(sorted(count.items(), key=lambda item: item[1]), reversed = True)
        # print(count)
        # save_json('tp.json', list(tp))
        print(f'{corr_cnt}/{total_cnt}, {corr_cnt / total_cnt}') 