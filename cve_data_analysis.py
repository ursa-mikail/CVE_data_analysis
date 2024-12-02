!git clone https://github.com/justakazh/CVE_Database.git
"""
Cloning into 'CVE_Database'...
remote: Enumerating objects: 522067, done.
remote: Counting objects: 100% (291/291), done.
remote: Compressing objects: 100% (61/61), done.
remote: Total 522067 (delta 262), reused 250 (delta 230), pack-reused 521776 (from 1)
Receiving objects: 100% (522067/522067), 515.93 MiB | 20.07 MiB/s, done.
Resolving deltas: 100% (513687/513687), done.
Updating files: 100% (244067/244067), done.
"""

import os
import json
import pandas as pd

# Define the path to the cloned repository
repo_path = './CVE_Database'

# List to store all the data
data = []

year_from = 2018 # 1999
year_to = 2020  # 2025

# Traverse through each year's directory
for year in range(year_from, year_to):  # Adjust the range based on available years
    print(f"Processing year: {year}")
    year_path = os.path.join(repo_path, str(year))
    if os.path.exists(year_path) and os.path.isdir(year_path):
        # Traverse through each JSON file in the year's directory
        for file_name in os.listdir(year_path):
            if file_name.endswith('.json'):
                file_path = os.path.join(year_path, file_name)
                # Read the JSON file
                with open(file_path, 'r', encoding='utf-8') as file:
                    json_data = json.load(file)
                    data.append(json_data)


# Convert the list of data into a DataFrame
df = pd.DataFrame(data)

# Print the first few rows of the DataFrame
print(df.head())

print(f"Total records: {len(df)}")
print(f"Summary statistics:\n{df.describe(include='all')}")

"""
Processing year: 2018
Processing year: 2019
                                                 cve
0  {'id': 'CVE-2018-15654', 'sourceIdentifier': '...
1  {'id': 'CVE-2018-8214', 'sourceIdentifier': 's...
2  {'id': 'CVE-2018-2768', 'sourceIdentifier': 's...
3  {'id': 'CVE-2018-15338', 'sourceIdentifier': '...
4  {'id': 'CVE-2018-19252', 'sourceIdentifier': '...
0: cve

Basic Analysis:
Total records: 31751
Summary statistics:
                                                      cve
count                                               31751
unique                                              31751
top     {'id': 'CVE-2018-15654', 'sourceIdentifier': '...
freq                                                    1
"""

# Extracting all keys from the dictionaries in the 'cve' column
all_keys = df['cve'].apply(lambda x: list(x.keys()))
print("All keys in each dictionary:", all_keys)

# Extracting unique keys from all dictionaries in the 'cve' column
unique_keys = set()
df['cve'].apply(lambda x: unique_keys.update(x.keys()))
unique_keys = list(unique_keys)
print("Unique keys across all dictionaries:", unique_keys)

"""
All keys in each dictionary: 0        [id, sourceIdentifier, published, lastModified...
1        [id, sourceIdentifier, published, lastModified...
2        [id, sourceIdentifier, published, lastModified...
3        [id, sourceIdentifier, published, lastModified...
4        [id, sourceIdentifier, published, lastModified...
                               ...                        
31746    [id, sourceIdentifier, published, lastModified...
31747    [id, sourceIdentifier, published, lastModified...
31748    [id, sourceIdentifier, published, lastModified...
31749    [id, sourceIdentifier, published, lastModified...
31750    [id, sourceIdentifier, published, lastModified...
Name: cve, Length: 31751, dtype: object
Unique keys across all dictionaries: ['sourceIdentifier', 'published', 'cisaVulnerabilityName', 'cisaActionDue', 'cveTags', 'references', 'vendorComments', 'weaknesses', 'descriptions', 'cisaExploitAdd', 'lastModified', 'configurations', 'metrics', 'id', 'evaluatorComment', 'vulnStatus', 'cisaRequiredAction']
"""

# Extracting the dictionary from the first row
first_row_dict = df.loc[0, 'cve']

# Display the key-value pairs for each key in the first row's dictionary
print("\nValues in the first row's dictionary:")
for key in unique_keys:
    value = first_row_dict.get(key, None)
    print(f"{key}: {value}")

"""

Values in the first row's dictionary:
sourceIdentifier: security@odoo.com
published: 2023-05-12T05:15:11.177
cisaVulnerabilityName: None
cisaActionDue: None
cveTags: []
references: []
vendorComments: None
weaknesses: None
descriptions: [{'lang': 'en', 'value': 'Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.'}]
cisaExploitAdd: None
lastModified: 2023-11-07T02:53:17.983
configurations: None
metrics: {}
id: CVE-2018-15654
evaluatorComment: None
vulnStatus: Rejected
cisaRequiredAction: None
"""

"""
Display 4 charts:

Distribution of CVSS Base Scores
CVSS Severity Distribution
Attack Vector Distribution
Number of CVEs per year
"""
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


# Extract relevant data from metrics
cvss_scores = []
cvss_severities = []
attack_vectors = []
publish_years = []

for index, row in df.iterrows():
    metrics = row['cve'].get('metrics', {})
    if 'cvssMetricV31' in metrics:
        for metric in metrics['cvssMetricV31']:
            cvss_data = metric.get('cvssData', {})
            if 'baseScore' in cvss_data:
                cvss_scores.append(cvss_data['baseScore'])
            if 'baseSeverity' in cvss_data:
                cvss_severities.append(cvss_data['baseSeverity'])
            if 'attackVector' in cvss_data:
                attack_vectors.append(cvss_data['attackVector'])
    # Extract the year from the 'published' date
    published_date = row['cve'].get('published', None)
    if published_date:
        publish_years.append(pd.to_datetime(published_date).year)

# Distribution of CVSS Base Scores
plt.figure(figsize=(10, 6))
sns.histplot(cvss_scores, bins=10, kde=True)
plt.title('Distribution of CVSS Base Scores')
plt.xlabel('CVSS Base Score')
plt.ylabel('Frequency')
plt.show()

# CVSS Severity Distribution
plt.figure(figsize=(10, 6))
sns.countplot(x=cvss_severities, order=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
plt.title('CVSS Severity Distribution')
plt.xlabel('CVSS Severity')
plt.ylabel('Count')
plt.show()

# Attack Vector Distribution
plt.figure(figsize=(10, 6))
sns.countplot(x=attack_vectors, order=['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL'])
plt.title('Attack Vector Distribution')
plt.xlabel('Attack Vector')
plt.ylabel('Count')
plt.show()

# Number of CVEs per year
plt.figure(figsize=(10, 6))
sns.countplot(x=publish_years)
plt.title('Number of CVEs per Year')
plt.xlabel('Year')
plt.ylabel('Count')
plt.show()

