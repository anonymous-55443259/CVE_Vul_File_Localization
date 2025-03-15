import os
import ast
import tqdm
import json
import copy
import random
import difflib
from util.io import load_json, save_json, save_text, load_file
from util.gpt import query_openai, calc_token
from util.general import multi_thread, generate_tree_str, print_location

class LocationAgent:

    def __init__(self, experiment_data_path: str, module_name: str, filtered_files_path: str, repo_instance_dir: str):
        self.experiment_data_path = experiment_data_path
        self.filtered_files_path = filtered_files_path
        self.repo_instance_dir = repo_instance_dir

        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)

        self.prompt = load_json(f'{module_name}/prompt.json')
        self.tools = load_json(f'{module_name}/tools.json')

        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        self.cve_list = [
            cve
            for cve in self.cve_data_all
            if os.path.exists(f'{filtered_files_path}/{cve}.json')
        ]
        print(len(self.cve_list))

        self.prompt_dir = f'{self.module_path}/prompt'
        os.makedirs(self.prompt_dir, exist_ok = True)
        self.result_dir = f'{self.module_path}/result'
        os.makedirs(self.result_dir, exist_ok = True)
        self.handled_result_dir = f'{self.module_path}/handled_result'
        os.makedirs(self.handled_result_dir, exist_ok = True)

        self.max_try = 20
    

    def start(self):
        self.query_gpt()
        # self.handle_result()


    def query_gpt(self):

        def generate_prompt():
            tp = copy.deepcopy(self.prompt)

            for cve in tqdm.tqdm(self.cve_list):
                content = f'CVE Description:\n{self.cve_data_all[cve]["augmented_desc"]}\n\nrepository files:\n{generate_tree_str(load_json(f"{self.filtered_files_path}/{cve}.json"))}'
                tp[1]['content'] = content
                save_json(f'{self.prompt_dir}/{cve}.json', tp)
                save_text(f'{self.prompt_dir}/{cve}.md', content)

        def anonymous(cve_list_sub: list):
            # for cve in tqdm.tqdm(cve_list_sub):
            # for cve in tqdm.tqdm(random.sample(cve_list_sub, 1)):
            # for cve in tqdm.tqdm(['CVE-2022-0355', 'CVE-2017-12430', 'CVE-2022-24066']):
            for cve in tqdm.tqdm(['CVE-2022-1795']):
                target_path = f'{self.result_dir}/{cve}'
                os.makedirs(target_path, exist_ok = True)
                if os.path.exists(f'{target_path}/final.json'):
                    continue
                max = -1
                for file in os.listdir(target_path):
                    if file in ['.DS_Store']: continue
                    tp = int(file.split('.')[0])
                    if tp > max:
                        max = tp
                if max != -1:
                    cnt = max + 1
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
                        if res.tool_calls:
                            messages.append({
                                'role': 'assistant',
                                'content': res.content,
                                'tool_calls': [
                                    {
                                        'id': tool_call.id,
                                        'type': tool_call.type,
                                        'function': {
                                            'name': tool_call.function.name,
                                            'arguments':  tool_call.function.arguments
                                        }
                                    }
                                    for tool_call in res.tool_calls
                                ]
                            })
                            for tool_call in res.tool_calls:
                                arguments = json.loads(tool_call.function.arguments)
                                function_call_res = getattr(self, tool_call.function.name)(**arguments, cve = cve)
                                if not function_call_res:
                                    pass
                                messages.append({
                                    'role': 'tool',
                                    'tool_call_id': tool_call.id,
                                    'content': function_call_res
                                })
                            save_json(f'{target_path}/{cnt}.json', messages)
                        else:
                            messages.append({
                                'role': 'assistant',
                                'content': res.content
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
                            'content': 'Based on the above information, output a Python-formatted list of file names associated with the vulnerability. Note that only the file list is output, without any prompt information.'
                        })
                        res = query_openai(
                            messages,
                            tools = self.tools,
                            tool_choice = 'none',
                            model = 'gpt-4o-mini')
                        messages.append({
                            'role': 'assistant',
                            'content': res.content
                        })
                        save_json(f'{target_path}/final.json', messages)
        
        # generate_prompt()

        rest_cve = copy.deepcopy(self.cve_list)
        for cve in self.cve_list:
            if os.path.exists(f'{self.result_dir}/{cve}/final.json'):
                rest_cve.remove(cve)
        if rest_cve:
            print('rest size: ', len(rest_cve))
            # multi_thread(rest_cve, anonymous, chunk_size = int(len(rest_cve) / 4))
            multi_thread(rest_cve, anonymous, chunk_size = 1000)


    def view_file_contents(self, file_name, cve):
        repo = self.cve_data_all[cve]['collected_repo']
        sha = self.cve_data_all[cve]['collected_commit']
        path = f'{self.repo_instance_dir}/{repo.replace("/", "__")}__{sha}'
        if not os.path.exists(path):
            assert False
        path = f'{path}/{file_name}'
        if not os.path.exists(path):
            return f'{file_name} not exist.'
        try:
            return load_file(path)
        except Exception as e:
            print_location(e)
        return f'{file_name} not exist.'


    def handle_result(self):
        cnt = 0
        total_cnt = 0
        for file in os.listdir(self.result_dir):
            if 'CVE' not in file: continue
            res = load_json(f'{self.result_dir}/{file}')
            file_list = res[-1]['content'].replace('```python', '').replace('```', '')
            try:
                file_list = ast.literal_eval(file_list)
            except Exception as e:
                print(e, f'{self.result_dir}/{file}')
                continue
            
            if len(file_list) == 0:
                continue
            
            total_cnt += 1
            save_json(f'{self.handled_result_dir}/{file}', file_list)
            cve = file.split('.')[0]
            real_files = self.cve_data_all[cve]['vulnerability_files']
            f = False
            for a in file_list:
                if f: break
                for b in real_files:
                    if a.lower() == b.lower():
                        print(cve)
                        f = True
                        break
            if f:
                cnt += 1
        print(f'{cnt}/{total_cnt} =', float(cnt)/float(total_cnt))