import os
import sys
import tqdm
import json
import time
import copy
import random
import pandas as pd

from util.io import load_json, save_json, save_text, load_file
from util.gpt import calc_token, query_openai
from util.general import multi_thread, RED, GREEN, YELLOW, BLUE, RESET
from googlesearch import search
from scrapy.scrapy_module import common



class Augmentation:
    
    def __init__(self, experiment_data_path: str, module_name: str, scrapy_result_dir: str):
        self.experiment_data_path = experiment_data_path
        
        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)

        self.scrapy_result_dir = f'{experiment_data_path}/{scrapy_result_dir}'
        
        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        self.cve_list = list(self.cve_data_all.keys())

        self.sys_prompt = load_file(f'{module_name}/prompt.md')
        self.tools = load_json(f'{module_name}/tools.json')
        
        self.prompt_dir = f'{self.module_path}/prompt'
        os.makedirs(self.prompt_dir, exist_ok = True)

        self.result_dir = f'{self.module_path}/result'
        os.makedirs(self.result_dir, exist_ok = True)

        self.max_try = 9


    def start(self):
        # self.generate_prompt()
        # self.augment()
        # self.sync()
        self.handle_result()
        
    
    def generate_prompt(self):
        for cve in tqdm.tqdm(self.cve_list):
            content = f'# original description:\n{self.cve_data_all[cve]["original_description"]}\n# supplementary information:\n'
            supplementary_info = ''
            # 有一些没有爬取结果
            path = f'{self.scrapy_result_dir}/{cve}.csv'
            if os.path.exists(path):
                df = pd.read_csv(path)
                for _, row in df.iterrows():
                    if not isinstance(row.text, str):
                        continue
                    text_len = len(row.text)
                    if 0 < text_len < 150 or row.state == 1:
                        continue
                    if calc_token(content + supplementary_info + row.text) > 120000:
                        continue
                    supplementary_info += row.text
            if supplementary_info:
                content += supplementary_info
            else:
                content += 'null'
            messages = [
                {
                    'role': 'system',
                    'content': self.sys_prompt
                },
                {
                    'role': 'user',
                    'content': content
                }
            ]
            save_json(f'{self.prompt_dir}/{cve}.json', messages)


    def count_prompt_total_token(self, prompt_dir: str):
        total = 0
        for cve in tqdm.tqdm(os.listdir(prompt_dir)):
            if cve in ['.DS_Store']: continue
            messages = load_json(f'{prompt_dir}/{cve}')
            for item in messages:
                total += calc_token(item['content'])
        token_M = int(total / 1000000)
        print(f'prompt total token: {token_M}M, price: {token_M * 0.15}$')


    def augment(self):

        def anonymous(cve_list: list):
            # for cve in tqdm.tqdm(cve_list):
            for cve in tqdm.tqdm(random.sample(cve_list, 2)):
            # for cve in tqdm.tqdm(['CVE-2017-7459', 'CVE-2021-29573']):
                target_path = f'{self.result_dir}/{cve}'
                os.makedirs(target_path, exist_ok = True)
                if os.path.exists(f'{target_path}/final.json'):
                    continue
                max = -1
                for file in os.listdir(target_path):
                    if file in ['.DS_Store']: continue
                    tp = int(file[0])
                    if tp > max:
                        max = tp
                if max != -1:
                    cnt = max + 1
                    # print(f'233, cnt = {cnt}')
                    messages = load_json(f'{target_path}/{max}.json')
                else:
                    cnt = 1
                    messages = load_json(f'{self.prompt_dir}/{cve}.json')
                while cnt < self.max_try:
                    try:
                        res = query_openai(
                            messages,
                            tools = self.tools,
                            model = 'gpt-4o-mini'
                        )
                        # res = res.content.replace('```', '').replace('```json', '').replace('json', '')
                        if 'tool_calls' in res:
                            messages.append({
                                'role': 'assistant',
                                'content': res['content'],
                                'tool_calls': res['tool_calls']
                            })
                            for tool_call in res['tool_calls']:
                                arguments = json.loads(tool_call['function']['arguments'])
                                function_call_res = getattr(self, tool_call['function']['name'])(**arguments)
                                if not function_call_res:
                                    function_call_res = 'no result\n'
                                messages.append({
                                    'role': 'tool',
                                    'tool_call_id': tool_call['id'],
                                    'content': function_call_res
                                })
                            save_json(f'{target_path}/{cnt}.json', messages)
                            # break
                        else:
                            messages.append({
                                'role': 'assistant',
                                'content': res['content']
                            })
                            save_json(f'{target_path}/final.json', messages)
                            break
                    except Exception as e:
                        save_text(f'{self.result_dir}/error_list', f'{cve}\n\n{e}', 'a')
                        break
                    cnt += 1
                else:
                    if not os.path.exists(f'{target_path}/final.json'):
                        messages.append({
                            'role': 'user',
                            'content': 'Based on the above information, augment the original description. Only output the augmented description.'
                        })
                        res = query_openai(
                            messages,
                            tools = self.tools,
                            tool_choice = 'none',
                            model = 'gpt-4o-mini')
                        messages.append({
                            'role': 'assistant',
                            'content': ['content']
                        })
                        save_json(f'{self.result_dir}/final.json', messages)
        
        rest_cve = copy.deepcopy(self.cve_list)
        for cve in self.cve_list:
            if os.path.exists(f'{self.result_dir}/{cve}/final.json'):
                rest_cve.remove(cve)
        print('rest size: ', len(rest_cve))
        # multi_thread(rest_cve, anonymous, chunk_size = int(len(rest_cve) / 8))
        multi_thread(rest_cve, anonymous, chunk_size = 3000)


    def google_search(self, keyword: str):
        try:
            results = search(keyword, num_results = 8)
            time.sleep(10)
            return '\n'.join(
                [
                    url
                    for _, url in enumerate(list(results))
                    if 'nvd.nist.gov/vuln/detail/' not in url
                ][:5]
            )
        except Exception as e:
            print(f"{RED}google search error: {e}{RESET}")
        return ''


    def access_web_page(self, URL: str):
        return common.scrapy(URL)


    def printMessages(self, path: str):
        data = load_json(path)
        # print(type(data))
        # print(len(data))
        print('_' * 200)
        for item in data:
            if item['role'] == 'system':
                print(f'{RED}')
                print(f'{item["role"]}:\n{item["content"]}')
            if item['role'] == 'user':
                print(f'{BLUE}')
                print(f'{item["role"]}:\n{item["content"]}')
            if item['role'] == 'assistant':
                print(f'{GREEN}')
                print(f'assistant:\n{item["tool_calls"] if "tool_calls" in item else item["content"]}')
            if item['role'] == 'tool':
                print(f'{YELLOW}')
                print(f'{item["role"]}:\n{item["content"]}')
            print(f'{RESET}')
        print('_' * 200 + '\n')


    def handle_result(self):
        cnt = 0
        for cve in self.cve_list:
            path = f'{self.module_path}/result/{cve}/final.json'
            if os.path.exists(path):
                desc = load_json(path)[-1]['content']
                self.cve_data_all[cve]['augmented_desc'] = desc
                cnt += 1
        print(f'{cnt} cve augmented!')
        save_json(f'{self.experiment_data_path}/cve_data_all.json', self.cve_data_all)



    # def sync(self):
    #     dir_list = [
    #         (f'{self.embedding_text_dir}', f'{self.module_root_path}/deprecated/embedding_text'),
    #         (f'{self.embedding_result_dir}', f'{self.module_root_path}/deprecated/embedding_result'),
    #         (f'{self.augmentation_prompt_dir}', f'{self.module_root_path}/deprecated/augmentation_prompt'),
    #         (f'{self.augmentation_result_dir}', f'{self.module_root_path}/deprecated/augmentation_result')
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