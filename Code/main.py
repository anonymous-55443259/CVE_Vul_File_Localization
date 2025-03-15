import os

from ground_truth.ground_truth import GroundTruth
from dataset.preprocessing_data import preprocessing_data
from scrapy.Scrapy import Scrapy
from augmentation.Augmentation import Augmentation
from repository.RepositoryCollection import RepositoryCollection
from repository.RepositoryClone import RepositoryClone
from repository.CommitCollection import CommitCollection
from filter.RuleFilter import RuleFilter
from location.LocationAgent import LocationAgent
# from codebert.CodebertAll import CodebertAll


experiment_data_path = 'experiment_data2'
os.makedirs(experiment_data_path, exist_ok = True)

# gt = GroundTruth(
#     experiment_data_path = experiment_data_path,
#     module_name = 'ground_truth'
# )
# gt.start()

# cve_data_all = preprocessing_data(
#     f'{experiment_data_path}/ground_truth/all_candidates.json',
#     experiment_data_path,
#     f'{experiment_data_path[:-1]}/metadata/cves',
#     f'{experiment_data_path[:-1]}/metadata',
# )
# print(len(cve_data_all))    # 9178

# scrapy = Scrapy(
#     experiment_data_path = experiment_data_path,
#     module_name = 'scrapy'
# )
# scrapy.start()

# augmentation = Augmentation(
#     experiment_data_path = experiment_data_path,
#     module_name = 'augmentation',
#     scrapy_result_dir = 'scrapy/scrapy_result'
# )
# augmentation.start()

# repositoryCollection = RepositoryCollection(
#     experiment_data_path = experiment_data_path,
#     module_name = 'repository/repository_collection',
# )
# repositoryCollection.start()

# commitCollection = CommitCollection(
#     experiment_data_path = experiment_data_path,
#     module_name = 'repository/commit_collection',
#     repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl'
# )
# commitCollection.start()

# repositoryClone = RepositoryClone(
#     experiment_data_path = experiment_data_path,
#     module_name = 'repository/repository_clone',
#     repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl'
# )
# repositoryClone.start()

# ruleFilter = RuleFilter(
#     experiment_data_path = experiment_data_path,
#     module_name = 'filter',
#     repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl',
#     repo_instance_dir = f'{experiment_data_path}/repository/repository_clone/instance'
# )
# ruleFilter.start()

locationAgent = LocationAgent(
    experiment_data_path = experiment_data_path,
    module_name = 'location',
    filtered_files_path = f'{experiment_data_path}/filter/filter_result/keywords/all',
    repo_instance_dir = f'{experiment_data_path}/repository/repository_clone/instance'
)
locationAgent.start()

# codebertAll = CodebertAll(
#     experiment_data_path = experiment_data_path,
#     corrected_gt_path = f'{experiment_data_path}/repository/commit_collection/corrected_gt.json',
#     module_name = 'codebert/ablation',
#     repo_instance_dir = f'{experiment_data_path}/repository/repository_clone/instance',
#     repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl'
# )
# codebertAll.start()