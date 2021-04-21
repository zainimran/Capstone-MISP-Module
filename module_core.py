import os
import sys
import json
import requests
import logging
import subprocess
import shlex
from util import sqlite_util
# PLACEHOLDER
# from util import ioc_extract

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(name)s:%(levelname)s:%(message)s')
log = logging.getLogger('module_core')

# Setup MISPERROR object
misperrors = { 
    'error':'Error'
}


# Setup MODULEINFO object
moduleinfo = {
    'version': '0.1', 
    'author': 'CMU Capstone Project - Mattias Rosner, Reginald Savoy, Ryan Chalk, Sachit Malik, Zain Imran',
    'description': '<TODO>',
    'module-type': ['expansion']
}


# Setup MISPATTRIBUTES object
mispattributes = {
    'input': ['url'],
    'output': ['text'],
}


# Setup MODULECONFIG object
moduleconfig = [
    'custom_API'
]



def introspection():
    """
    Introspection function which returns the input value required by the module, and the output format of the module

    """
    return mispattributes



def version():
    """
    Returns the metadata about the module (see moduleinfo above)
    
    """

    moduleinfo['config'] = moduleconfig
    return moduleinfo



def invoke_web_crawler():
    """
    Invokes the webcrawler that scrapes the URLs and fetches the blog posts

    Input:
        None

    Output:
        returncode: integer
            0: successful
            1: otherwise

    Raises Exception:
        No

    NOTE: 
        The dependencies of this submodule should be specified in either requirements.txt 
        or explicit instructions need to be given during the plugin installation.
    """
    
    rc = 0

    try:
        path_cwd = os.path.abspath('.')
        path_spider = os.path.join(path_cwd, 'web-crawler', 'infosecspider','spiders','scraper.py')
        command = f'scrapy runspider {path_spider}'
        input_args = shlex.split(command)
        # !NOTE!: Do not pass any input parameters to the below string, will result in code execution
        try:
            log.info('[+] Running the webcrawler module...')
            completed_proc_instance = subprocess.run(input_args, shell=True, check=True)
            log.info('[+] Successfully scraped data from the URLs...')
        except subprocess.CalledProcessError as e:
            log.error('[-] Failed to run the web crawler.')
            log.error(f'[--] Return code: {e.returncode}')
            rc = 1
        return rc
    except:
        rc = 1
        return rc


def invoke_ioc_extract(param1, param2):
    """
    Invokes the IOC extractor submodule

    Input:
        XYZ

    Output:
        XYZ

    Raises Exception:
        Yes/No

    NOTE: 
        The dependencies of this submodule should be specified in either requirements.txt 
        or explicit instructions need to be given during the plugin installation.
    """
    
    # PLACEHOLDER
    return {}



def invoke_store_iocs_in_db(extracted_iocs, database):
    """
    Stores the extracted IOCs into the local database

    Input:
        extracted_iocs: extracted IOCs in JSON/DICT format from ioc_extract submodule
        database: path to the database
            default: if no path is provided, defaults to local_ioc.db in the current directory
    
    Output:
        returncode: integer
            0: successful
            1: otherwise
    
    Raises Exception:
        No

    """

    rc = 0
    
    try:
        if database:
            rc = sqlite_util.store_in_local_ioc_db(extracted_iocs, database)
        else:
            rc = sqlite_util.store_in_local_ioc_db(extracted_iocs)
    except:
        rc = 1
    
    return rc



def handler(q=False):
    
    if q is False:
        return False
    
    # Scrape the URLs
    rc_wc = invoke_web_crawler()

    if rc_wc:
        misperrors['error'] = 'Unable to scrape the URLs'
        return misperrors['error']
    
    # Extract IOCs
    try:
        extracted_iocs_dict= {}
        extracted_iocs_dict = invoke_ioc_extract(para1, para2)
    except:
        log.error('[-] Failed to retrieve IOCs from the scraped data...')
        misperrors['error'] = 'Unable to retrieve IOCs from crawled webpages'
        return misperrors['error']
    
    # Store extracted IOCs in the database
    if extracted_iocs_dict:
        rc_db = invoke_store_iocs_in_db(extracted_iocs_dict, database='local_ioc.db')
        if rc_db:
            log.error('[-] Failed to store the IOCs in the database...')
            # Even if it fails to store, we would still like to alert the user
            extracted_iocs_dict['error'] = 'Failed to store the retreived IOCs in the database'

    # Return the results back to the user
    response = {'results': [{'types': mispattributes['output'], 'values': extracted_iocs_dict}]}
    
    return response