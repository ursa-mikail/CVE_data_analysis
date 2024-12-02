# CVE Data Analysis

This project extracts and visualizes Common Vulnerabilities and Exposures (CVE) data, focusing on key metrics like CVSS base scores, CVSS severity, attack vectors, and the number of CVEs per year.

## Project Overview

The project involves the following steps:
1. Extracting relevant data from a DataFrame containing CVE information.
2. Visualizing the extracted data using `matplotlib` and `seaborn`.

## Visualizations

The following charts are generated:
1. **Distribution of CVSS Base Scores:** Shows the frequency distribution of CVSS base scores.
2. **CVSS Severity Distribution:** Displays the count of CVEs by severity level (LOW, MEDIUM, HIGH, CRITICAL).
3. **Attack Vector Distribution:** Illustrates the count of CVEs by attack vector (NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL).
4. **Number of CVEs per Year:** Plots the number of CVEs published each year.

### Distribution of CVSS Base Scores
![distribution_of_cvss_base_scores](distribution_of_cvss_base_scores.png)

### CVSS Severity Distribution
![cvss_severity_distribution](cvss_severity_distribution.png)

### Attack Vector Distribution
![attack_vector_distribution](attack_vector_distribution.png)

### Number of CVEs per Year
![number_of_cves_per_year](number_of_cves_per_year.png)

## Setup

1. Ensure you have Python installed.
2. Install the required libraries:
    ```bash
    pip install pandas matplotlib seaborn
    ```

## Usage

1. Run the script to generate the visualizations:
    ```python
    python cve_analysis.py
    ```

2. The script will display the following charts:
    - Distribution of CVSS Base Scores
    - CVSS Severity Distribution
    - Attack Vector Distribution
    - Number of CVEs per Year

