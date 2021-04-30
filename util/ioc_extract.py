"""
*This script requires the GitHub library 'cyobstract' authored by Sam Perl from CMU-SEI, et al. for Indicators of Compromise Extraction (IOCs): https://github.com/cmu-sei/cyobstract.
We describe how to install it and its dependencies on the README

*This script is to be run after web_scraping the webpages/technical reports by running the command: "scrapy runspider scraper.py", which creates a '.../spiders/output/' folder

In this script, we define 3 helper functions for parsing the JSONs contained in this '/ouput/ folder, extracting dates for filtering the web_scraping scans, and extracting IoCs.
These are invoked in the main function initiate_ioc_extraction_main(), which returns 1) a dictionary of dictionaries (containing the IoCs extracted for each article in the webpage provided)
or 2) None with a print statement of the Error if it failled the IoC extraction.

  Output format of dict of dicts by initiate_ioc_extraction_main():
  #Structure format & example below:
                                                    {Original article link       , blog data + extracted IOCs}
    {domainname: {scrapyscantime_folder_name: {     {article1_name: {article_url: , data:    ,   md5:, cve,... }                }  }           }}

    {fireeye:    {20210429-1732:              {     {ar21-072d.json: {arcile_url:'https://us-cert.cisa.gov/ncas/analysis-reports/ar21-072d', data: 'complete_article_raw_text',md5: ('4580f7f2f2d7ac1af26693132c2e756d',    '78564702783ba738aa6a920f3b15a202',
    'ab3963337cf24dc2ade6406f11901e1f'), cve: ('CVE-2021-26855', 'CVE-2021-27065'),.....    }                }  }           }}
"""

import json
import os
import datetime
import sys
current_working_dir = os.getcwd()
cyobstract_subfolder = '/' + os.path.join(*current_working_dir.split('/'), 'cyobstract/cyobstract')
sys.path.insert(1, cyobstract_subfolder)
import extract



def read_file(fname,parent_dirs,desired_iocs_list):
  parent_name = fname.split('/')[-3]  #Parent name [ciso,fireeye]
  sub_parent_timecreatedfolder_name = fname.split('/')[-2] #sub-parent name (name is time when scrapy scan is performed)
  child_article_name = fname.split('/')[-1] #child folder name

  with open(fname) as f:
    data = json.load(f) #f.read() #json.parse --> gives a key value pair ---> then can do data[url] = whole_url , data[output] = parsed_text

  key = parent_name
  sub_key = sub_parent_timecreatedfolder_name
  sub_sub_key = child_article_name

  #Structure::::::::::::
    # {cisa: {scrapyscantime_folder_name: {     {article1_name: {ipv4: , md5,... }                }  }           }}

  try:
    parent_dirs[key][sub_key][sub_sub_key] = extract.extract_observables(data['scraped output']) 

    #Add new keys to dict:
    parent_dirs[key][sub_key][sub_sub_key]['data'] =data['scraped output'] #add key to store RAW data text of article as well
    parent_dirs[key][sub_key][sub_sub_key]['article_url'] = data['url']

  except Exception as e:
    print(e)

  #extracted IOCs --> {'ipv4addr': (), 'ipv6addr': (), 'ipv4range': (), 'ipv6range': (), 'ipv4cidr': (), 'ipv6cidr': (), 'asn': (), 'fqdn': (), 'email': (), 'filename': (), 'url': (), 'md5': ('11454bd782bb41db213d415e10a0fb3c',), 'sha1': (), 'sha256': (), 'ssdeep': (), 'filepath': (), 'regkey': (), 'useragent': (), 'cve': (), 'cc': (), 'isp': (), 'asnown': (), 'incident': (), 'malware': (), 'topic': ()}
  return parent_dirs



def parse_filename_date(dirpath):  
  #check if Scrapy scan is within time_duration timeframe (to look at scans only in the last X hours
  year_day_time = dirpath.split('/')[-1]
  year = year_day_time[:4]
  month = year_day_time[4:6]
  day = year_day_time[6:8]


  time =year_day_time[-4:] #HH:MM, i.e. '1249' for 12:49pm
  hour= int(time[:2]) #24h clock
  minutes= int(time[-2:])

  return hour



#Class for easily creating dict of dicts of dicts (used in function fetch_crawled_files())
class AutoVivification(dict): #https://stackoverflow.com/questions/651794/whats-the-best-way-to-initialize-a-dict-of-dicts-in-python
    """Implementation of perl's autovivification feature."""
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError: #Allows the creation of dicts with keys that do not have been defined before by returning an empty dict on eror
            value = self[item] = type(self)()
            return value



def fetch_crawled_files(directory, desired_iocs_list, time_duration_hours=1): #Grab Zain's outputs and extract iocs from each folder
  cntr = 0
  parent_dirs = AutoVivification() #dictionary of all parent dirs (our websites which we scan) -> {'cisa':, 'fireeye':}
  for dirpath, dirs, files in os.walk(directory):
    if cntr ==0:  #store root directories names, i.e. ['cisa', 'fireeye']
      for parent_name in dirs:
          parent_dirs[parent_name]  #create new key for each parent name; value will be populated with another dict of article names containing dict of IOCS
    #print(dirs, '~~~~~~~~~~~~~', cntr,parent_dir)
    cntr+=1
    for filename in files: # files = JSON
      #Search in the Json ---> key = url, value = whole_url
                              #key = output, value= actual_output

      fname = os.path.join(dirpath,filename) #whole path to file
      article_hour = parse_filename_date(dirpath)


      now = datetime.datetime.now()
      

      range_ = now.hour - time_duration_hours
      if article_hour > range_: #only get IocS of scan above range_ of time_duration_hours of last scans we want
        read_file(fname, parent_dirs,desired_iocs_list) #returns a dict will all data
  return parent_dirs



#Def Main (This function runs all other functions stated above)
def initiate_ioc_extraction_main(path_outputs,view_scraping_within_last_hours=1):  
  try:
      desired_iocs = ['ipv4addr', 'ipv6addr', 'ipv4range', 'ipv6range', 'ipv4cidr', 'ipv6cidr', 'asn', 'fqdn', 'email', 'filename', 'url', 'md5', 'sha1', 'sha256', 'ssdeep', 'filepath', 'regkey', 'useragent', 'cve', 'cc', 'isp', 'asnown', 'incident', 'malware', 'topic']
      ioc_extracted_dict = fetch_crawled_files(path_outputs, desired_iocs, view_scraping_within_last_hours)
      print("\n>>>>>>>>>>>>>Succesfully extracted<<<<<<<<<<<< \n")
      return ioc_extracted_dict
  except Exception as e:
      print('Error>>>', e)
      return None
