import os
import csv
import sys
import tqdm
import importlib
import pandas as pd

from scrapy.scrapy_module import common
from util.io import save_text, save_json, save_pickle, load_json, load_pickle, copy_file
from util.general import multi_thread, count_range, get_domain
from util.gpt import calc_token


class Scrapy:
    
    def __init__(self, experiment_data_path: str, module_name: str):
        self.module_path = f'{experiment_data_path}/{module_name}'
        os.makedirs(self.module_path, exist_ok = True)
    
        self.cve_data_all = load_json(f'{experiment_data_path}/cve_data_all.json')
        
        self.cve_list = list(self.cve_data_all.keys())
        self.scrapy_module = {}
        self.domain_parttern = load_json('scrapy/domain_pattern.json')
        self.url_pattern = load_json('scrapy/url_pattern.json')

        self.scrapy_result = f'{self.module_path}/scrapy_result'
        os.makedirs(self.scrapy_result, exist_ok = True)

        self.scrapy_result_statistics = f'{self.module_path}/scrapy_result_statistics'
        os.makedirs(self.scrapy_result_statistics, exist_ok = True)

        self.domain_statistics = f'{self.module_path}/domain_statistics'
        os.makedirs(self.domain_statistics, exist_ok = True)

        self.error_list = f'{self.scrapy_result_statistics}/error_list.csv'
        if not os.path.exists(self.error_list):
            pd.DataFrame({
                'cve': [],
                'url': [],
                'domain': [],
                'text': []
            }).to_csv(
                self.error_list,
                index = False,
                quotechar = '"',
                quoting = csv.QUOTE_ALL
            )
        
        self.long_text = f'{self.scrapy_result_statistics}/long_text.csv'
        self.short_text = f'{self.scrapy_result_statistics}/short_text.csv'

        if not os.path.exists(f'{self.domain_statistics}/valid_url.pkl'):
            self.count_url()
        self.valid_url = load_pickle(f'{self.domain_statistics}/valid_url.pkl')
        # print(len(self.valid_url))


    def start(self):
        # self.sync()
        # self.scrapy_all_url()
        # self.re_scrapy(domain_list = self.domain_parttern['to_update_domain_list'])
        self.re_scrapy(file_path = self.error_list)
        # self.count_scrapy_result()

    
    def sync(self):
        cve_list_done = [
            file.split('.')[0] for file in os.listdir(self.scrapy_result)
            if file not in ['.DS_Store']
        ]
        cnt = 0
        for cve in self.cve_list:
            path = f'/Volumes/Data/Vulnerability_Localization/experiment_data/scrapy/scrapy_result/{cve}.csv'
            if cve not in cve_list_done and os.path.exists(path):
                copy_file(path, f'{self.scrapy_result}/{cve}.csv')
                # os.remove(f'{self.scrapy_result}/{cve}.csv')
                cnt += 1
        if cnt > 0:
            print(f'scrapy module update {cnt} cve')


    def count_url(self):
        domain_cve = {}
        domain_url = {}
        reference_len_list = []
        valid_url = {}
        valid_total_amount = 0

        for cve in tqdm.tqdm(self.cve_list):
            url_list = self.cve_data_all[cve]['reference_list']
            reference_len_list.append(len(url_list))
            valid_url[cve] = {}
            for url in url_list:
                domain = get_domain(url)
                if domain in domain_url:
                    domain_url[domain].add(url)
                    domain_cve[domain].add(cve)
                else:
                    domain_url[domain] = {url}
                    domain_cve[domain] = {cve}
                if url in self.url_pattern['not_handle_url_list']:
                    continue
                if domain in self.domain_parttern['particular_domain_list']:
                    valid_total_amount += 1
                    if domain in self.domain_parttern['add_suffix_domain_list']:
                        url += f'#{cve}'
                    if 'particular_domain_list' in valid_url[cve]:
                        valid_url[cve]['particular_domain_list'].append(url)
                    else:
                        valid_url[cve]['particular_domain_list'] = [url]
                elif domain not in self.domain_parttern['not_handle_domain_list']:
                    valid_total_amount += 1
                    if 'common' in valid_url[cve]:
                        valid_url[cve]['common'].append(url)
                    else:
                        valid_url[cve]['common'] = [url]
                
            if not valid_url[cve]:
                del valid_url[cve]
        
        domain_url_count = {k: len(v) for k, v in domain_url.items()}
        domain_url_count = dict(sorted(domain_url_count.items(), key = lambda item: item[1], reverse = True))
        save_text(f'{self.domain_statistics}/domain_count', domain_url_count)

        domain_cve = {k: list(v) for k, v in domain_cve.items()}
        save_json(f'{self.domain_statistics}/domain_cve.json', domain_cve)
        save_pickle(f'{self.domain_statistics}/domain_cve.pkl', domain_cve)

        domain_url = {k: list(v) for k, v in domain_url.items()}
        save_json(f'{self.domain_statistics}/domain_url.json', domain_url)

        save_json(f'{self.domain_statistics}/valid_url.json', valid_url)
        save_pickle(f'{self.domain_statistics}/valid_url.pkl', valid_url)

        total_amount = sum(reference_len_list)
        print(f'url total amount: {total_amount}')
        print(f'valid total amount: {valid_total_amount}')
        print(f'cve average url amount: {total_amount / len(self.cve_list)}')
        
        distribution = count_range(reference_len_list, [2, 5, 10, 20, 50, 100])
        print(distribution)


    def get_module_name(self, domain: str):
        module_name = domain.replace('.', '_').replace('-', '_')
        if module_name == 'www_debian_org':
            module_name = 'lists_debian_org'
        elif module_name == 'h20566_www2_hpe_com':
            module_name = 'support_hpe_com'
        elif module_name == 'kb_cert_org':
            module_name = 'www_kb_cert_org'
        elif module_name in ['usn_ubuntu_com', 'ubuntu_com']:
            module_name = 'www_ubuntu_com'
        elif module_name == 'www_talosintelligence_com':
            module_name = 'talosintelligence_com'
        elif module_name == 'openwall_com':
            module_name = 'www_openwall_com'
        elif module_name == 'bugzilla_suse_com':
            module_name = 'bugzilla_redhat_com'
        elif module_name == 'launchpad_net':
            module_name = 'bugs_launchpad_net'
            
        return module_name


    def scrapy_single_url(self, cve: str, url: str, is_paticular: bool, retry: bool, save_to_error_list: bool):
        domain = get_domain(url)
        state = 0           # 0表示无异常
        try:
            module_name = self.get_module_name(domain)
            # print(module_name)
            if is_paticular:
                if module_name not in self.scrapy_module.keys():
                    self.scrapy_module[module_name] = importlib.import_module(f'scrapy.scrapy_module.{module_name}')
                res = self.scrapy_module[module_name].scrapy(url)
            else:
                res = common.scrapy(url)
        except Exception as e:
            if not retry:     # retry一次
                res = self.scrapy_single_url(cve, url, is_paticular, True, True)
                return res
            else:
                res = e
                state = 1
                if save_to_error_list:
                    df = pd.read_csv(self.error_list)
                    df.loc[len(df)] = [cve, url, domain, e]
                    df.to_csv(
                        self.error_list,
                        index = False, 
                        quotechar = '"',
                        quoting = csv.QUOTE_ALL
                    )
        return [url, domain, state, res]


    def scrapy_all_url_sub(self, cve_list: list):
        for cve in tqdm.tqdm(cve_list):
            if os.path.exists(f'{self.scrapy_result}/{cve}.csv') or cve not in self.valid_url:
                continue
            url_list = self.valid_url[cve]
            df = pd.DataFrame({
                'url': [],
                'domain': [],
                'state': [],
                'text': []
            })
            # for url in tqdm.tqdm(url_list):
            if 'particular_domain_list' in url_list:
                for url in url_list['particular_domain_list']:
                    df.loc[len(df)] = self.scrapy_single_url(cve, url, True, False, True)
            if 'common' in url_list:
                for url in url_list['common']:
                    df.loc[len(df)] = self.scrapy_single_url(cve, url, False, False, True)
            df.to_csv(
                f'{self.scrapy_result}/{cve}.csv',
                index = False, 
                quotechar = '"',
                quoting = csv.QUOTE_ALL
            )


    def scrapy_all_url(self):
        cve_list_done = {
            file.split('.')[0] for file in os.listdir(self.scrapy_result)
            if file not in ['.DS_Store']
        }
        cve_list_todo = list(set(self.cve_list) - cve_list_done)
        # print(len(cve_list_todo))
        multi_thread(cve_list_todo, self.scrapy_all_url_sub, chunk_size = 2)


    def re_scrapy(self, file_path = None, domain_list = None):
        
        def re_scrapy_by_domain(domain_list: list):
            print('start update valid_url')
            self.count_url()
            self.valid_url = load_pickle(f'{self.domain_statistics}/valid_url.pkl')
            print('end update valid_url')
            
            domain_cve = load_json(f'{self.domain_statistics}/domain_cve.json')
            cve_list_to_re_scrapy = list({ cve
                for domain in domain_list
                for cve in domain_cve[domain]
            })
            print(f'find {len(cve_list_to_re_scrapy)} affected cve')

            # 删除原来的scrapy结果
            cnt = 0
            for cve in cve_list_to_re_scrapy:
                path = f'{self.scrapy_result}/{cve}.csv'
                if os.path.exists(path):
                    cnt += 1
                    os.remove(path)
            print(f'delete {cnt} original scrapy result')
            multi_thread(cve_list_to_re_scrapy, self.scrapy_all_url_sub, chunk_size = 15)


        def re_scrapy_by_file(data_path):

            def re_scrapy_by_file_sub(data_list: list):
                for row in tqdm.tqdm(data_list):
                    cve = row[0]
                    url = row[1]
                    # domain = row[2]
                    # if domain in ['lua-users.org']: 
                    #     index = (df['cve'] == cve) & (df['url'] == url)
                    #     df.loc[index, 'text'] = 'done'

                    df_cve = pd.read_csv(f'{self.scrapy_result}/{cve}.csv')
                    res = self.scrapy_single_url(
                        cve,
                        url,
                        is_paticular = get_domain(url) in self.domain_parttern['particular_domain_list'],
                        retry = False,
                        save_to_error_list = (data_path != self.error_list)
                    )
                    if res[2] == 0:
                        df_cve.loc[df_cve['url'] == url] = res
                        df_cve.to_csv(
                            f'{self.scrapy_result}/{cve}.csv',
                            index = False, 
                            quotechar = '"',
                            quoting = csv.QUOTE_ALL
                        )
                        index = (df['cve'] == cve) & (df['url'] == url)
                        df.loc[index, 'text'] = 'done'
                        print(f'{cve}, {url} update success, len: {len(res[3])}')
                    else:
                        print(f'{cve}, {url} updated failure')

            if not os.path.exists(data_path):
                print('error, file not exist')
                return

            df = pd.read_csv(data_path)
            print(f'before rescrapy: {len(df)} records')
            multi_thread(df.values.tolist(), re_scrapy_by_file_sub, chunk_size = 50)
            
            df = df.drop(df[df['text'] == 'done'].index)
            print(f'after rescrapy: {len(df)} records')
        
            df.to_csv(
                data_path,
                index = False, 
                quotechar = '"',
                quoting = csv.QUOTE_ALL
            )

        if file_path:
            re_scrapy_by_file(file_path)
        elif domain_list:
            re_scrapy_by_domain(domain_list)


    def count_scrapy_result(self):
        df_long_text = pd.DataFrame({
            'cve': [],
            'url': [],
            'domain': [],
            'len': [],
            'text': []
        })
        df_short_text = pd.DataFrame({
            'cve': [],
            'url': [],
            'domain': [],
            'len': [],
            'text': []
        })
        token_len_list = []
        
        for cve in tqdm.tqdm(self.cve_list):
            if not os.path.exists(f'{self.scrapy_result}/{cve}.csv'):
                continue
            df = pd.read_csv(f'{self.scrapy_result}/{cve}.csv')
            for _, row in df.iterrows():
                # print(row.url)
                if isinstance(row.text, str):
                    length = len(row.text)
                    if 0 < length < 150:
                        df_short_text.loc[len(df_short_text)] = [cve, row.url, row.domain, length, row.text]
                    else:
                        token_len_list.append(calc_token(row.text))
                        if length > 50000:
                            df_long_text.loc[len(df_long_text)] = [cve, row.url, row.domain, length, row.text]

        df_long_text.to_csv(
            self.long_text,
            index = False, 
            quotechar = '"',
            quoting = csv.QUOTE_ALL
        )
        df_short_text.to_csv(
            self.short_text,
            index = False, 
            quotechar = '"',
            quoting = csv.QUOTE_ALL
        )

        print(f'long_text size:{len(df_long_text)}, short_text size: {len(df_short_text)}')
        print(f'total token: {sum(token_len_list)}')
        print(count_range(token_len_list, [150, 300, 500, 1000, 1800, 5000, 10000, 20000]))
