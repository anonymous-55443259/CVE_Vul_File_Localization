import os
import re
import sys
import tqdm
import shutil
from util.io import load_pickle, save_pickle, copy_file, save_json, load_json
from util.general import get_domain

'''
从NVD官网下载的json数据中提取需要的部分, 然后与ground_truth_data合并成一个dict
- reference_list: 
    type: [str]
- original_description:
    type: str
- published_date:
    type: str
- cpe_product:
    type: [str]
- cpe_uri:
    type: [str]
- commits:
    type: [str]
- repository:
    type: str
- vulnerability_files:
    type: [str]
'''


def get_product_from_cpe(s: str):
    s = s.replace('\\:', '')
    pattern = r'(?<=:)([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):'
    match = re.search(pattern, s)
    if match:
        return match.group(4)
    else:
        return None


def filter_json_file(cve_list: list, cve_json_path: str, target_path: str):
    file_list = []
    for root, _, files in os.walk(cve_json_path):
        for file in files:
            if file not in ['.DS_Store', 'delta.json', 'deltaLog.json']:
                file_list.append(os.path.join(root, file))

    for file in file_list:
        cve_id = file.split('/')[-1].split('.')[0]
        if cve_id not in cve_list:
            continue

        try:
            data = load_json(file)
            if data['cveMetadata']['state'] == 'REJECTED':
                print('REJECTED', cve_id)
                continue
            if 'references' not in data['containers']['cna'].keys():
                print('no reference', cve_id)
                continue
            # references = data['containers']['cna']['references']
            copy_file(file, f'{target_path}/{cve_id}.json')
        except Exception as e:
            # print(e)
            print(f'error: open {cve_id}.json failure')


def preprocessing_data(ground_truth_path: str, experiment_data_path: str, cve_json_path: str, cpe_json_path: str):
    path = f'{experiment_data_path}/cve_data_all.json'
    if os.path.exists(path):
        return load_json(path)
    
    gt = load_json(ground_truth_path)
    temp_path = f'{experiment_data_path}/cve_json_{len(gt)}'
    os.makedirs(temp_path, exist_ok = True)

    cve_list = {item for item in gt.keys()}

    # print('start traverse cve json file')
    # filter_json_file(
    #     cve_list = cve_list,
    #     cve_json_path = cve_json_path,
    #     target_path = temp_path
    # )
    # print('end traverse cve json file')

    cve_data_all = {}
    for cve in cve_list:
        cve_data_all[cve] = {}
        # filePath = f'{temp_path}/{cve}.json'
        # data = load_json(filePath)
        # cve_data_all[cve]['original_description'] = data['containers']['cna']['descriptions'][0]['value']
        # cve_data_all[cve]['reference_list'] = [dic['url'] for dic in data['containers']['cna']['references']]

    domains = set()
    print('start traverse cpe json file')
    for file in tqdm.tqdm(os.listdir(cpe_json_path)):
        if file in ['.DS_Store', 'cves']: continue
        if '2024' not in file: continue
        
        fileName = f'{cpe_json_path}/{file}'
        data = load_json(fileName)['CVE_Items']
        for cve_dic in data:
            # print(cve_dic.keys())
            # sys.exit()
            for url in cve_dic['cve']['references']['reference_data']:
                # print(url['url'])
                domain = get_domain(url['url'])
                domains.add(domain)
                
            cve = cve_dic['cve']['CVE_data_meta']['ID']
            if cve not in cve_list: continue

            cve_data_all[cve]['original_description'] = cve_dic['cve']['description']['description_data'][0]['value']
            cve_data_all[cve]['reference_list'] = [
                url['url']
                for url in cve_dic['cve']['references']['reference_data']
            ]
            cpe_uri_set = set()
            cpe_product_set = set()
            try:
                cpe_list = cve_dic['configurations']['nodes'][0]['cpe_match']
            except Exception as e:
                print(cve, e)
            if not cpe_list:
                cpe_list = cve_dic['configurations']['nodes'][0]['children'][0]['cpe_match']
            for cpe_dic in cpe_list:
                cpe_uri = cpe_dic['cpe23Uri']
                cpe_product_set.add(get_product_from_cpe(cpe_uri))
                cpe_uri_set.add(cpe_uri)
            cve_data_all[cve]['cpe_uri'] = list(cpe_uri_set)
            cve_data_all[cve]['cpe_product'] = list(cpe_product_set)

            time = cve_dic.get('publishedDate')
            cve_data_all[cve]['published_date'] = time
    print((len(domains)))
    print('end traverse cpe json file')

    for cve, v in gt.items():
        cve_data_all[cve]['commits'] = v['commits']
        cve_data_all[cve]['repository'] = v['repository']
        cve_data_all[cve]['vulnerability_files'] = v['vulnerability_files']

    cve_data_all = correct_data(cve_data_all)

    save_json(path, cve_data_all)

    # shutil.rmtree(temp_path)
    
    return cve_data_all


def correct_data(cve_data_all: dict):
    # 手动修正一些数据
    # 重复数据
    url = 'https://talosintelligence.com/vulnerability_reports/TALOS-2021-1297'
    for cve in ['CVE-2021-21845', 'CVE-2021-21843', 'CVE-2021-21837', 'CVE-2021-21846', 'CVE-2021-21847', 'CVE-2021-21852', 'CVE-2021-21839', 'CVE-2021-21844', 'CVE-2021-21838']:
        if cve in cve_data_all:
            cve_data_all[cve]['reference_list'].remove(url)

    return cve_data_all