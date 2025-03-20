import os

from dataset.preprocessing_data import preprocessing_data
from scrapy.Scrapy import Scrapy
from CVEAnalyst.Augmentation import Augmentation
from RepoExplorer.RepositoryCollection import RepositoryCollection
from RepoExplorer.RepositoryClone import RepositoryClone
from RepoExplorer.CommitCollection import CommitCollection
from filter.RuleFilter import RuleFilter
from VulHunter.LocationAgent import LocationAgent
from codebert.CodebertAll import CodebertAll


experiment_data_path = 'experiment_data'
os.makedirs(experiment_data_path, exist_ok = True)

cve_data_all = preprocessing_data(
    f'{experiment_data_path}/ground_truth/candidates.json',
    experiment_data_path,
    f'{experiment_data_path}/metadata/cves',
    f'{experiment_data_path}/metadata',
)
print(len(cve_data_all))

scrapy = Scrapy(
    experiment_data_path = experiment_data_path,
    module_name = 'scrapy'
)
scrapy.start()

augmentation = Augmentation(
    experiment_data_path = experiment_data_path,
    module_name = 'augmentation',
    scrapy_result_dir = 'scrapy/scrapy_result'
)
augmentation.start()

repositoryCollection = RepositoryCollection(
    experiment_data_path = experiment_data_path,
    module_name = 'repository/repository_collection',
)
repositoryCollection.start()

commitCollection = CommitCollection(
    experiment_data_path = experiment_data_path,
    module_name = 'repository/commit_collection',
    repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl'
)
commitCollection.start()

repositoryClone = RepositoryClone(
    experiment_data_path = experiment_data_path,
    module_name = 'repository/repository_clone',
    repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl'
)
repositoryClone.start()

ruleFilter = RuleFilter(
    experiment_data_path = experiment_data_path,
    module_name = 'filter',
    repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl',
    repo_instance_dir = f'{experiment_data_path}/repository/repository_clone/instance'
)
ruleFilter.start()

locationAgent = LocationAgent(
    experiment_data_path = experiment_data_path,
    module_name = 'location',
    filtered_files_path = f'{experiment_data_path}/filter/filter_result/keywords/all',
    repo_instance_dir = f'{experiment_data_path}/repository/repository_clone/instance'
)
locationAgent.start()

codebertAll = CodebertAll(
    experiment_data_path = experiment_data_path,
    corrected_gt_path = f'{experiment_data_path}/repository/commit_collection/corrected_gt.json',
    module_name = 'codebert/ablation',
    repo_instance_dir = f'{experiment_data_path}/repository/repository_clone/instance',
    repo_file_list_dict_path = f'{experiment_data_path}/github/repo_file_list_dict.pkl'
)
codebertAll.start()