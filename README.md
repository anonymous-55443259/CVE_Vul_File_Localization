# Valor: Enhancing Vulnerability-Relevant File Discovery through an Agent-Based Framework

## Framework
![](./framework.png)

## Code

### CVE Analyst
The CVE Analyst agent first enhances the original CVE descriptions by collecting supplementary information from external references and online sources, addressing gaps and incomplete details.

### Repo Explorer
The Repo Explorer agent identifies relevant open-source repositories and filters candidate files based on the augmented CVE descriptions, effectively narrowing the scope for localizing vulnerability-relevant files.

### VulHunter
The Vul Hunter agent performs precise localization by analyzing file hierarchies and conducting LLM-based semantic analysis to identify vulnerability-relevant files.

## Dataset
- **cleaned_gt_commit_single**: cve and all of files in the related patching commit. Format: {(cve_id, repo_name): [vulnerable files]}
- **cve_github_can**: {cve_id: commit links, pull links, issue links, other links}, each cve can have multiple commit/pull/issue/other links. Some of the commits may be further conducted from pull links & issue links. The files from conducted commit links are involved in gt_commit but the conducted commit links are not involved in cve_github_can. This file may contain noises, some of the other links are mixed into commit links, need further filtering
- **cve_metadata**: full data can be downloaded from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

## Result
![](./Result/Overall_Performance.png)
![](./Result/RQ2_Accuracy.png)
![](./Result/RQ2_Completeness.png)
![](./Result/RQ3.png)
![](./Result/Ablation_Study.png)
![](./Result/RQ5.png)