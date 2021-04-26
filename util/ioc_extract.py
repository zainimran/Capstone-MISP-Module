from cyobstract import extract
import json
import os
import datetime



#Class for easily creating dict of dicts of dicts
class AutoVivification(dict): #https://stackoverflow.com/questions/651794/whats-the-best-way-to-initialize-a-dict-of-dicts-in-python
  """Implementation of perl's autovivification feature."""
  def __getitem__(self, item):
      try:
          return dict.__getitem__(self, item)
      except KeyError: #Allows the creation of dicts with keys that do not have been defined before by returning an empty dict on eror
          value = self[item] = type(self)()
          return value


###########Sub-Functions for IOC extraction and file reading


def read_file(fname,parent_dirs,desired_iocs_list):
  #print('juicy parentdir', parent_dirs)

  parent_name = fname.split('/')[-3]  #Parent name [ciso,fireeye]
  sub_parent_timecreatedfolder_name = fname.split('/')[-2] #just sub-parent name (name is time when scrapy scan is performed)
  child_article_name = fname.split('/')[-1] #just child folder name
  #print(parent_name, sub_parent_timecreatedfolder_name, child_article_name)

  with open(fname) as f:
    data = json.load(f) #f.read() #json.parse --> gives a key value pair ---> then can do data[url] = whole_url , data[output] = parsed_text

  key = parent_name
  sub_key = sub_parent_timecreatedfolder_name
  sub_sub_key = child_article_name

  #Structure::::::::::::
    # {cisa: {scrapyscantime_folder_name: {     {article1_name: {ipv4: , md5,... }                }  }           }}

  try:
    parent_dirs[key][sub_key][sub_sub_key] = extract.extract_observables(data['scraped output']) #Matias, this is god tier good
    #parent_dirs[key][sub_key][sub_sub_key] = extract_fromlist(data, desired_iocs_list) #debugging matias

    #~~~New added keys:
    parent_dirs[key][sub_key][sub_sub_key]['data'] =data['scraped output'] #add key to store RAW data text of article as well
    parent_dirs[key][sub_key][sub_sub_key]['article_url'] = data['url']

  except Exception as e:
    print(e)
    #ioc_format --> {'ipv4addr': (), 'ipv6addr': (), 'ipv4range': (), 'ipv6range': (), 'ipv4cidr': (), 'ipv6cidr': (), 'asn': (), 'fqdn': (), 'email': (), 'filename': (), 'url': (), 'md5': ('11454bd782bb41db213d415e10a0fb3c',), 'sha1': (), 'sha256': (), 'ssdeep': (), 'filepath': (), 'regkey': (), 'useragent': (), 'cve': (), 'cc': (), 'isp': (), 'asnown': (), 'incident': (), 'malware': (), 'topic': ()}
  return parent_dirs


def parse_filename_date(dirpath):  
	#check if Scrapy scan is within time_duration timeframe (to look at scans only in the last 3 hours
	year_day_time = dirpath.split('/')[-1]
	year = year_day_time[:4]
	month = year_day_time[4:6]
	day = year_day_time[6:8]


	time =year_day_time[-4:] #HH:MM, i.e. '1249' for 12:49pm
	hour= int(time[:2]) #24h clock
	minutes= int(time[-2:])

	#Could use for later
	#datetimestring = '%s-%s-%s %d:%d'%(year,month,day  ,hour,minutes) #reformatting for easy convertion to python datetime format
	#print(datetimestring, 'datetimestring') #delete\

	return hour



def parse_filename_date(dirpath):  
  #check if Scrapy scan is within time_duration timeframe (to look at scans only in the last x hours
  year_day_time = dirpath.split('/')[-1]
  year = year_day_time[:4]
  month = year_day_time[4:6]
  day = year_day_time[6:8]


  time =year_day_time[-4:] #HH:MM, i.e. '1249' for 12:49pm
  hour= int(time[:2]) #24h clock
  minutes= int(time[-2:])

  return hour


def fetch_crawled_files(directory, desired_iocs_list, time_duration_hours=1): #Grab Zain's outputs and extract iocs from each folder
	cntr = 0
	parent_dirs = AutoVivification() #dictionary of all parent dirs (our websites which we scan) -> {'cisa':, 'fireeye':}
	for dirpath, dirs, files in os.walk(path_outputs):
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


def initiate_ioc_extraction_main():  
  try:
      desired_iocs = ['ipv4addr', 'ipv6addr', 'ipv4range', 'ipv6range', 'ipv4cidr', 'ipv6cidr', 'asn', 'fqdn', 'email', 'filename', 'url', 'md5', 'sha1', 'sha256', 'ssdeep', 'filepath', 'regkey', 'useragent', 'cve', 'cc', 'isp', 'asnown', 'incident', 'malware', 'topic']
      ioc_extracted_dict = fetch_crawled_files(path_outputs, desired_iocs, time_duration_hours=3)
      print("\n>>>>>>>>>>>>>Succesfully extracted<<<<<<<<<<<< \n")
      return ioc_extracted_dict
  except Exception as e:
      print('Error>>>', e)
      return None
