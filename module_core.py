import os
import sys
import json
import requests
import logging
import subprocess
import shlex
from util import sqlite_util
from util import ioc_extract, ioc_extract_expander

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
    'input': ['action', 'url', 'recursive', 'md5', 'sha1', 'sha256', 'ipv4', 'malware_name'],
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



def invoke_web_crawler(url):
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
        
        if not url:
            command = f'scrapy runspider {path_spider}'
        else:
            command = f'scrapy runspider {path_spider} -a url={url}'

        input_args = shlex.split(command)

        # !NOTE!: Do not pass any input parameters to the below string, will result in code execution
        try:
            log.info('[+] Running the webcrawler module...')
            completed_proc_instance = subprocess.run(input_args, check=True)
            log.info('[+] Successfully scraped data from the URLs...')
        except subprocess.CalledProcessError as e:
            log.error('[-] Failed to run the web crawler.')
            log.error(f'[--] Return code: {e.returncode}')
            rc = 1

    except:
        rc = 1
    
    return rc


def invoke_ioc_extract(output_path, time_duration):
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
    
    try:
        iocs_dict = ioc_extract.initiate_ioc_extraction_main(path_outputs=output_path, view_scraping_within_last_hours=time_duration)
        
        # Check if it is an empty dict or a None type object
        if not iocs_dict:
            
            # If so, set it as an empty dict object
            iocs_dict = {}

    except:
        log.error('[-] Failed to run ioc extraction submodule on the scraped data...')
        iocs_dict = {}
    
    return iocs_dict



def invoke_web_scraper_recursive(ioc_extract_dict, article, ioc_category):
    """
    <TODO: WIP>

    """
    rc_rec = 0

    try:
        rc_rec = ioc_extract_expander.recursive_ioc_extractor_from_article_name_and_ioc__over_google_searches(dictionary=ioc_extract_dict, 
        article_lookup=article, 
        ioc=ioc_category, 
        num_google_results=10,
        search_speed=3)

    except:
        rc_rec = 1
    
    return rc_rec



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



def invoke_retrieve_from_local_ioc_db(input_dict, database):
    """
    Given an input dict containing ioc_type and ioc_value to search in the database,
    Finds and returns all the matching entries for each ioc_type and ioc_value so specified.

    Input:
        input_dict <dict> 
            Example:
                {
                    'md5' : md5_value,
                    'sha256' : sha256_value,
                    'ipv4': ip_addr,
                    'malware_name': malwarename
                }
    
    Output:
        response_dict <dict>
            Example:
                {
                    'md5:md5_value' : [[retreived_instance_1], [retreived_instance_2], ..., [retreived_instance_k]]
                    ...
                    'error' : ['error_str_1', 'error_str_2', .... ,] # In case of any errors for each searched value
                }

    Raises Exception:
        No

    """

    response_dict = {}
    response_dict['error'] = []
    
    try:
        for _ioc_type, _ioc_val in input_dict.items():
            output_list, error = sqlite_util.retrieve_from_local_ioc_db(_ioc_type, _ioc_val, database)
            
            if error != 'SUCCESS':
                response_dict['error'].append(error)
                continue
            
            key = _ioc_type + ":" + _ioc_val
            response_dict[key] = output_list
        
    except:
        response_dict['error'].append('Failed to retrieve the IoCs from Local DB...')
    
    return response_dict
        


def handler(q=False):
    """
    [*] CORE API Request Handler Function
    
    """
    
    if q is False:
        return False
    
    _request = json.loads(q)

    # input_param_list = ['action', 'url', 'recursive', 'md5', 'sha1', 'sha256', 'ipv4', 'malware_name']
    valid_actions = ['scrape', 'get_from_db']
    valid_iocs = ['md5', 'sha1', 'sha256', 'ipv4', 'malware_name']
    valid_recursive_flags = [0, 1]


    # Fetch the action so requested, if not a valid action, return the MISPERROR object with error value set
    try:
        action_requested = _request['action']
        if action_requested not in valid_actions:
            misperrors['error'] = 'Invalid action specified. Please select one from: scrape, get_from_db'
            return misperrors['error']
    
    except KeyError:
        misperrors['error'] = 'No action specified. Please select one from: scrape, get_from_db'
        return misperrors['error']


    # If the user has requested for scraping, proceed as below
    if action_requested == 'scrape':
        
        # Identify the URL so supplied
        try:
            url = _request['url']

        # If none, default to hardcoded sources
        except KeyError:
            log.info('[-] No URL was specified...')
            log.info('[*] Defaulting to harcoded data sources...')
            url = ''
        
        # Identify if the recursive flag has been set (1)
        try:
            recursive = _request['recursive']
            if recursive not in valid_recursive_flags:
                log.info('[-] Invalid recursive value specified. Defaulting to 0.')
                recursive = 0
        
        # If not, set the flag as (0), default behavior would not involve recursion
        except KeyError:
            log.info('[-] No recursive value specified. Defaulting to 0.')
            recursive = 0
        
        # Scrape the URLs
        rc_wc = invoke_web_crawler(url)

        if rc_wc:
            misperrors['error'] = 'Unable to scrape the URLs'
            return misperrors['error']
        

        # Extract IOCs
        try:
            extracted_iocs_dict_initial = invoke_ioc_extract('output/', 1)
        except:
            log.error('[-] Failed to retrieve IOCs from the scraped data...')
            misperrors['error'] = 'Unable to retrieve IOCs from crawled webpages'
            return misperrors['error']
        
        global_response_dict = extracted_iocs_dict_initial

        # Store extracted IOCs in the database
        if extracted_iocs_dict_initial:
            rc_db = invoke_store_iocs_in_db(extracted_iocs_dict_initial, database='local_ioc.db')
            if rc_db:
                log.error('[-] Failed to store the IOCs in the database...')
                # Even if it fails to store, we would still like to alert the user
                global_response_dict['error'] = 'Failed to store the retreived IOCs in the database, '

            # Check if we need to recursively fetch the IoCs
            if recursive:
                # PLACEHOLDER
                article = ''

                # PLACEHOLDER 
                ioc_category = ''

                # PLACEHOLDER, Run the recursive webcrawler
                rc_rec = invoke_web_scraper_recursive(extracted_iocs_dict_initial, article, ioc_category)

                # If not successful, return the response object
                if rc_rec:
                    log.error('[-] Failed to run the recursive submodule...')
                    try:
                        global_response_dict['error'] += 'Failed to run the recursive submodule... '
                    except:
                        global_response_dict['error'] = 'Failed to run the recursive submodule... '
                    response = {'results': [{'types': mispattributes['output'], 'values': global_response_dict}]}
                    return response

                # Try to fetch the IoCs
                try:
                    extracted_iocs_dict = invoke_ioc_extract('outputs/', 1)
                except:
                    log.error('[-] Failed to retrieve IOCs from the recursively scraped data...')
                    try:
                        global_response_dict['error'] += 'Failed to extract IoCs in the recursive submodule, '
                    except:
                        global_response_dict['error'] = 'Failed to extract IoCs in the recursive submodule, '
                    response = {'results': [{'types': mispattributes['output'], 'values': global_response_dict}]}
                    return response

                # If successful and non-empty, store them in the DB
                if extracted_iocs_dict:
                    # Only set the global dict to the newly extracted_iocs_dict if non-empty
                    # Else return the original (w/o recursion) dict
                    global_response_dict = extracted_iocs_dict
                    
                    rc_db = invoke_store_iocs_in_db(extracted_iocs_dict, database='local_ioc.db')
                    if rc_db:
                        log.error('[-] Failed to store the IOCs in the database...')
                        # Even if it fails to store, we would still like to alert the user
                        global_response_dict['error'] = 'Failed to store the retreived IOCs in the database, '

        # Setup the return object, that would be returned back to the user
        response = {'results': [{'types': mispattributes['output'], 'values': global_response_dict}]}
    
    elif action_requested == 'get_from_db':
        
        input_ioc_dict = {}
        
        for _valid_ioc in valid_iocs:
            try:
                _ioc_val = _request[_valid_ioc]
                if _ioc_val:
                    input_ioc_dict[_valid_ioc] = _ioc_val
            except:
                continue

        if not input_ioc_dict:
            log.error('[-] No IoC type or no IoC value specified...')
            misperrors['error'] = 'No IoC type or no IoC value specified...'
            return misperrors
        
        response_dict = invoke_retrieve_from_local_ioc_db(input_ioc_dict, 'local_ioc.db')

        response = {'results': [{'types': mispattributes['output'], 'values': response_dict}]}

    return response
