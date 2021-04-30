"""
This script forms a list of URLS by doing google_searches over the IOCS of a previously extracted article. We will generate new dictionaries from these URLS to *populate our dictionaries with further IOC information (future work, just adding it to the database currently and can query it thorugh SQL on i.e. an MD5 hash)*
Then it extracts the IOCS over each newly found url (through google searches), and adds the results to the '/ouput/' folder in the root direcory /Capstone-MISP-Module/
You maybe view the results by using the bash command: '$ls ouput/' to view the new directories (each new directory is a new website that was found automatically)
"""

from module_core import invoke_web_crawler
from util.ioc_extract import initiate_ioc_extraction_main 
import requests
from bs4 import BeautifulSoup
import re

#Helper 1
#Seaches for ioc in url text, if it finds it, it returns True. If it can not find it, it scrapes this url from the list by returning False
def url_find_ioc(ioc, url): 
  res = requests.get(url)
  html_page = res.content
  soup = BeautifulSoup(html_page, 'html.parser')
  #find the exact IOC
  if soup(text=re.compile(ioc)):
    #print('found the ioc')
    return True
  else:
    #print("string was not found")
    return False

# Helper 2
#search google for a string=search_string
def search_google(search_string,num_results=5,search_speed=5):
  try:
      from googlesearch import search
  except ImportError: 
      print("No module named 'google' found")
  
  google_dorks_formatted_string = '"{}"|"{}"'.format(search_string,search_string) #https://cdn-cybersecurity.att.com/blog-content/GoogleHackingCheatSheet.pdf #using an OR operator but for the same search, to exclusively search for documents containing said IOC (in this case the md5). 
  #Could also do and statements with & symbol to later seach upon i.e. 2 IOCS such as md5 and ipv4
  #Note: Websites like McAfee websites for some reason do not give you the text that contains the IOC, and redirect you to a subscription webpage when accessed from google searches. Will drop their keys to not contaminate our dataset
  url_list = list()                   
  for retrieved_url in search(search_string, tld="co.in", num=num_results, stop=num_results, pause=search_speed):
      if url_find_ioc(ioc=search_string,url=retrieved_url): #if url contains the exact string in the text , we scrape it by keeping the url
        url_list.append(retrieved_url)
      else: #if not, we skip this url (By doing this WE do NOT add it to the database, and keep it CLEAN)
        continue
  return url_list

#Helper 3
#Given an list of iocs, it does a google search for the top `num_results` of each ioc in the list, web-scrapes them, and stores results in '/output/' folder
def ioc_extractor_over_google(iocs_list,num_results=5,search_speed=5):
  complete_list_url = []
  for identifiers in iocs_list:
    print(identifiers)
    complete_list_url.extend(search_google(search_string=identifiers,num_results=num_results,search_speed=search_speed))

  for url_sample in complete_list_url:
    invoke_web_crawler(url_sample)


# Main function which calls the functions above

# Input:
#   dictionary=dictionary of IoCs created running `initiate_ioc_extraction_main()` ,
#   article_lookup= name of article in the dictionary, 
#   ioc= Types of IOCs to google search from this article on google, i.e.'md5', 
#   num_google_results= how many google results searched,
#   search_speed= speed of google searches (do not set too low to prevent getting IP banned by Google)
def recursive_ioc_extractor_from_article_name_and_ioc__over_google_searches(dictionary=None, article_lookup=None, ioc='md5', num_google_results=5,search_speed=3):
  if dictionary is None or article_lookup is None:
    print('You must provide a valid dictionary of IOCS and a "VALID" name of an article which is a key in this dictionary')
  else:
    for key,value in dictionary.items():
      for scan_time, article_name_dict in value.items():
        #print(article_name_dict.keys())
        if article_lookup in article_name_dict:
          #print(article_name_dict) #[article_lookup][ioc])
          try:
            #extract IOCS from specified article
            ioc_list = list(article_name_dict[article_lookup][ioc]) #I.e. md5 list extracted from 1 article
            
            print('ioc_list', ioc_list)
            #Perform google searches over the list of iocs, and extracts/populates the newly found articles+IOCS to the /ouput/ folder
            ioc_extractor_over_google(iocs_list=ioc_list,num_results=num_google_results,search_speed=search_speed)

          except Exception as e:
            print('could not find IOC: ', ioc, 'try using a different IOC or different article which DOSE contain the IOC you indicated')
            print(e)
            return None
