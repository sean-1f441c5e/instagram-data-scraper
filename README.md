# instagram-data-scraper

Scripts for automating the pulling of data from Instagram. The data is used in the creating of training data sets for various machine learning algorithms. There are 3 scripts of note here: `scrap.py`,`profiling_to_csv_v2.py` and `parse.py`. The scripts also require the `Tor Browser Bundle` and `geckodriver`. Please refer to the [TBB website](https://www.torproject.org/download/) and [geckodriver website](https://github.com/mozilla/geckodriver/releases) for instructions for download and installation. The dataset can be found at this [dropbox](https://www.dropbox.com/sh/9cyjc5rfssuryj9/AADNOPs2OGT6fwjhBuPNsMKWa?dl=0) link. Raw tcpdump data is not provided, as the size is too huge (estimated to be 65GB total). 

## Requirements

All the scripts requires the use of Python modules like `numpy`, `selenium` and `tb-selenium`. You can install all these required modules by running `sudo pip install -r requirements.txt`. If you do not have `pip`, you can install (asumming an Ubuntu installation) by running `sudo apt-get install python-pip`.

## Installation

1. Download package from Github.
1. Extract to directory of your choice.
1. Install the required python modules
1. Install the required `TBB` and `geckodriver` packages.

## Usage

1. Scrap
1. Parse
1. Feed result into K-Fingerprinting or WEKA

## scrap.py

This script creates a new dataset using a combination of `WEBSITE_NAME`/`PROFILE_NAME`. These 2 options can be found at the top of the script, along with other options and flags. Please refer to scrap.py for more information on the usage of the various options and flags. The script is able do simple resuming by checking for missing result files and downloading only the missiong result files. Examples of how to use the script is shown below.

Scrap Type | Command
---------- | -------
Normal web browser | `python scrap.py --normal`
Tor web browser | `python scrap.py --tor`

## profiling_to_csv_v2.py

Similar to scrap, this script also creates a new dataset. At the same time, it also generate Javascript profiling results, which are necessary for the new approach. It is able do simple resuming by checking for missing result files and downloading only the missiong  result files. There are no flags for this script, simply run

`python profiling_to_csv_v2.py`

## parse.py

This script looks at the raw tcpdump data and converts it into an input form suitable for either the K-Fingerprinting script or for use with WEKA. 

Parse Type | Command
---------- | -------
K-Fingerprinting | `python parse.py --k --src="./data" --dst="./preprocessed_k"`
WEKA | `python parse.py --weka --src="./data" --dst="./preprocessed_weka"`
New approach | `python parse.py --new --src="./data" --src2="./output" --dst="./preprocessed_new"`
New approach using filter of 250 bytes | `python parse.py --new --src="./data" --src2="./output" --dst="./preprocessed_new" --filter=250`
New approach using filter of 500 bytes | `python parse.py --new --src="./data" --src2="./output" --dst="./preprocessed_new" --filter=500`
New approach using filter of 750 bytes | `python parse.py --new --src="./data" --src2="./output" --dst="./preprocessed_new" --filter=750`
New approach using filter of 1000 bytes | `python parse.py --new --src="./data" --src2="./output" --dst="./preprocessed_new" --filter=1000`

Sometimes there are errors in the raw files that must be fixed before parsing. `parse.py` contains functions that is able to corect these errors.

Type | Command
---- | -------
Error checking for new approach | `python parse.py --check_new --src="./data" --src2="./output" --dst="./preprocessed_new"`
Error fixing for new approach | `python parse.py --fix_new --src="./data" --src2="./output" --dst="./preprocessed_new"`

## Classification

K-Fingerprinting is the primary classifier we use. Generally, you need to first build a dictionary of features before the actual classification. 

Dictionary Type | Command
--------------- | -------
All | `python k-FPv2.py --dictionary`
Instagram (normal) | `python k-FPv2.py --dictionary --single_dict insta`
Instagram (tor) | `python k-FPv2.py --dictionary --single_dict insta_tor`
Instagram (new_approach) | `python k-FPv2.py --dictionary --single_dict new`

Below are examples on how to get K-Fingerprinting to classify our datasets

Dataset Type | Command
------------ | -------
Instagram (normal) | `python k-FPv2.py --RF_closedworld --mon_type insta`
Instagram (tor) | `python k-FPv2.py --RF_closedworld --mon_type insta_tor`
Instagram (new_approach) | `python k-FPv2.py --RF_closedworld --mon_type new`
