#!/usr/bin/env python
# coding: utf-8

import sys
import os
import sqlite3
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(name)s:%(levelname)s:%(message)s')
log = logging.getLogger('SQLite_util')



def create_connection(database):
    """
    Create a database connection to the SQLite database specified by database variable
    
    Input: 
    	Database name or path
    
    Output: 
    	Connection object or None
    
    Raises Exception: 
    	Yes
    
    """

    conn = None
    try:
        conn = sqlite3.connect(database)
        return conn
    except Exception as e:
        log.error(f'[-] The following error occured! - {e.args}')
        raise



def create_table(conn, create_table_sql):
    """
    Create a table from the create_table_sql statement
    
    Input: 
    	Connection object, SQL statement
    
    Output: 
    	None
    
    Raises Exception: 
    	Yes
    
    """

    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Exception as e:
        log.error(f'[-] The following error occured! - {e.args}')
        raise



def initialise_db(database):
    """
    Given a database name(or path), initialises the database, creates tables - so specified below,
    (can be tweaked in the future to generate custom tables by adding the query and the
    table name accordingly)

    Input: 
    	Name or path to database
    	(If name is specified, the database will be created in the current directory)
    
    Output: 
    	None
    
    Raises Exception: 
    	Yes

    """
    try:
        # Create table ioc_hashes query
        ioc_hashes_query = '''CREATE TABLE IF NOT EXISTS ioc_hashes
                                (hash_value text,
                                hash_type text,
                                source_parent_url text, 
                                source_parent_name text,
                                confidence_level text,
                                tags text,
                                created_date_epoch integer, 
                                last_updated_date_epoch integer,
                                reference text,
                                remarks text,
                                PRIMARY KEY (hash_value, source_parent_name, reference));'''

        # Create table ioc_urls query
        ioc_ip_addrs_query = '''CREATE TABLE IF NOT EXISTS ioc_ip_addrs
                             (ip_value text, 
                             source_parent_url text,
                             source_parent_name text,
                             confidence_level text,
                             tags text,
                             created_date_epoch integer,
                             last_updated_date_epoch integer,
                             reference text,
                             remarks text,
                             PRIMARY KEY (ip_value, source_parent_name, reference));'''

        # Create table ioc_domains query
        ioc_domains_query = '''CREATE TABLE IF NOT EXISTS ioc_domains
                                 (domain_value text,
                                 source_parent_url text,
                                 source_parent_name text,
                                 confidence_level text,
                                 tags text,
                                 created_date_epoch integer, 
                                 last_updated_date_epoch integer,
                                 reference text,
                                 remarks text,
                                 PRIMARY KEY (domain_value, source_parent_name, reference));'''
        
        ioc_malware_query = '''CREATE TABLE IF NOT EXISTS ioc_malware
                                 (malware_name text,
                                 source_parent_url text,
                                 source_parent_name text,
                                 confidence_level text,
                                 tags text,
                                 created_date_epoch integer, 
                                 last_updated_date_epoch integer,
                                 reference text,
                                 remarks text,
                                 PRIMARY KEY (malware_name, source_parent_name, reference));'''
        
        conn = create_connection(database)
        try:
            create_table(conn, ioc_hashes_query)
            create_table(conn, ioc_ip_addrs_query)
            create_table(conn, ioc_domains_query)
            create_table(conn, ioc_malware_query)
            conn.commit()
            conn.close()
            log.info('[+] Tables created!')
        except Exception as e:
            log.error('[-] Error! Cannot connect to the database.')
            raise

    except Exception as e:
        log.error(f'[-] Table creation unsuccessful! The following error occured: {e.args}')
        raise    



def store_in_table(list_of_json_objects, table_name, database='test.db'):
    """
    Inserts the data from the cleaned up json in the table and database so specified.
    Modifies/Replaces existing data depending on the constraint so set in the queries.
    
    Input: 
    	List of JSON Objects, Table name, Database name
    
    Output: 
    	Return Code (0 - if successful, 1 - if otherwise)
    
    Raises Exception: 
    	No

    """
    
    rc = 1
    
    try:
        conn = create_connection(database)
    except Exception as e:
        log.error(f'[-] Unable to establish connection to the database - {database}')
        log.error(f'[-] {e.args}')
        return rc
    
    cursor = conn.cursor()
    
    insert_query = get_insert_query(table_name)
    if not insert_query:
        log.error(f'Invalid table name specified: {table_name}')
        return rc
    
    try:
        list_of_tuples = get_tuple_list_from_json(list_of_json_objects, table_name)
    except Exception as e:
        log.error('[-] Unable to get tuple list from the input list of json objects')
        log.error(e.args)
        return rc
    
    if not list_of_tuples:
        log.warning(f'[-] Skipping... No data found corresponding to {table_name} in the input json')
        return rc
    
    try:
        cursor.executemany(insert_query, list_of_tuples)
    except Exception as e:
        log.error(f'[-] Unable to add/update data in the {database}:{table_name}')
        log.error(e.args)
        return rc
    
    conn.commit()
    conn.close()
    log.info(f'[*] Total rows added/updated - {cursor.rowcount}. Data successfully stored in {database}:{table_name}')
    rc = 0
    return rc



def get_insert_query(table_name):
    """
    Based on the table_name, returns the corresponding SQL insert query
    
    Input: 
    	Table name
    
    Output: 
    	None or Insert Query
    
    Raises Exception: 
    	No
    
    """
    
    table_insert_query_dict = {
        
        'ioc_hashes':'''
        INSERT OR REPLACE INTO ioc_hashes
        (hash_value,
        hash_type,
        source_parent_url,
        source_parent_name,
        confidence_level,
        tags,
        created_date_epoch, 
        last_updated_date_epoch,
        reference,
        remarks)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hash_value, source_parent_name, reference) DO UPDATE SET
        last_updated_date_epoch = ?;
        ''',
        
        'ioc_ip_addrs':'''
        INSERT OR REPLACE INTO ioc_ip_addrs
        (ip_value, 
        source_parent_url,
        source_parent_name,
        confidence_level,
        tags,
        created_date_epoch,
        last_updated_date_epoch,
        reference,
        remarks)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_value, source_parent_name, reference) DO UPDATE SET
        last_updated_date_epoch = ?;
        ''',
        
        'ioc_domains':'''
        INSERT OR REPLACE INTO ioc_domains
        (domain_value,
        source_parent_url,
        source_parent_name,
        confidence_level,
        tags,
        created_date_epoch, 
        last_updated_date_epoch, 
        reference,
        remarks)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain_value, source_parent_name, reference) DO UPDATE SET
        last_updated_date_epoch = ?;
        ''',
        
        'ioc_malware':'''
        INSERT OR REPLACE INTO ioc_malware
        (malware_name,
        source_parent_url,
        source_parent_name,
        confidence_level,
        tags,
        created_date_epoch,
        last_updated_date_epoch,
        reference,
        remarks)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(malware_name, source_parent_name, reference) DO UPDATE SET
        last_updated_date_epoch = ?;
        '''
    }
    
    try:
        insert_query = table_insert_query_dict[table_name]
    except KeyError as e:
        insert_query = ''
    
    return insert_query



def get_tuple_list_from_json(list_of_json_information_objects, table_name):
    """
    Returns the data to be inserted in SQLite's executemany compatible format (list of tuples)
    
    Input: 
    	JSON Object
    
    Output: 
    	List of tuples
    
    Raises Exception: 
    	Yes
    
    """
    list_of_tuples = []
      
    if table_name == 'ioc_hashes':
        for _obj in list_of_json_information_objects:

            list_hash_types = ['md5', 'sha1', 'sha256']
            for _hash_type in list_hash_types:
                if _obj[_hash_type]:
                    for _hash in _obj[_hash_type]:
                        tuple_to_append = (_hash, 
                                           _hash_type,
                                           _obj['source_parent_url'],
                                           _obj['source_parent_name'],
                                           _obj['confidence_level'],
                                           _obj['tags'],
                                           _obj['created_date_epoch'],
                                           _obj['created_date_epoch'],
                                           _obj['reference'],
                                           _obj['remarks'],
                                           _obj['created_date_epoch'])

                        list_of_tuples.append(tuple_to_append)

    elif table_name == 'ioc_ip_addrs':
        for _obj in list_of_json_information_objects:
            if _obj['ip_address']:
                for _ip_addr in _obj['ip_address']:
                    tuple_to_append = (_ip_addr, 
                                      _obj['source_parent_url'],
                                      _obj['source_parent_name'],
                                       _obj['confidence_level'],
                                       _obj['tags'],
                                       _obj['created_date_epoch'],
                                       _obj['created_date_epoch'],
                                       _obj['reference'],
                                       _obj['remarks'],
                                       _obj['created_date_epoch'])
                    list_of_tuples.append(tuple_to_append)

    elif table_name == 'ioc_domains':
        for _obj in list_of_json_information_objects:
            if _obj['domains']:
                for _domain in _obj['domains']:
                    tuple_to_append = (_domain, 
                                      _obj['source_parent_url'],
                                      _obj['source_parent_name'],
                                      _obj['tags'],  
                                      _obj['confidence_level'],
                                      _obj['created_date_epoch'],
                                      _obj['created_date_epoch'],
                                      _obj['reference'],
                                      _obj['remarks'],
                                      _obj['created_date_epoch'])
                    list_of_tuples.append(tuple_to_append)

    elif table_name == 'ioc_malware':
        for _obj in list_of_json_information_objects:
            if _obj['malware']:
                for _malware in _obj['malware']:
                    tuple_to_append = (_malware,
                                       _obj['source_parent_url'],
                                       _obj['source_parent_name'],
                                       _obj['confidence_level'],
                                       _obj['tags'],
                                       _obj['created_date_epoch'],
                                       _obj['created_date_epoch'],
                                       _obj['reference'],
                                       _obj['remarks'],
                                       _obj['created_date_epoch'])
                    list_of_tuples.append(tuple_to_append)
                    
    return list_of_tuples



def cleanup_input_json(json_object):
    """
    Given the input from the ioc_extract submodule, returns the cleaned up data in a list of json format

    Input: 
        Resulting json from ioc_extract

    Output: 
        List of json objects

    Raises Exception: 
        No
    """

    try:
        output_list_of_dicts = []
        
        if json_object:
        
            for _key, _dict in json_object.items():
                source_parent_name = _key
                
                for _folder_key, _folder_dict in _dict.items():
                        for _sub_folder_key, _sub_folder_dict in _folder_dict.items():
                            temp_dict = {}
                            
                            temp_dict['source_parent_name'] = source_parent_name
                            
                            temp_dict['reference'] = _sub_folder_key
                            
                            temp_dict['md5'] = list(_sub_folder_dict['md5']) if 'md5' in _sub_folder_dict.keys() else None
                            
                            temp_dict['sha1'] = list(_sub_folder_dict['sha1']) if 'sha1' in _sub_folder_dict.keys() else None
                            
                            temp_dict['sha256'] = list(_sub_folder_dict['sha256']) if 'sha256' in _sub_folder_dict.keys() else None
                            
                            if 'ipv4addr' and 'ipv6addr' in _sub_folder_dict.keys():
                                if _sub_folder_dict['ipv4addr']:
                                    temp_dict['ip_address'] = list(_sub_folder_dict['ipv4addr'])
                                if _sub_folder_dict['ipv6addr']:
                                    temp_dict['ip_address'].extend(list(_sub_folder_dict['ipv6addr']))
                            
                            elif 'ipv4addr' in _sub_folder_dict.keys():
                                temp_dict['ip_address'] = list(_sub_folder_dict['ipv4addr']) if _sub_folder_dict['ipv4addr'] else None
                            
                            elif 'ipv6addr' in _sub_folder_dict.keys():
                                temp_dict['ip_address'] = list(_sub_folder_dict['ipv6addr']) if _sub_folder_dict['ipv6addr'] else None
                            
                            else:
                                temp_dict['ip_address'] = None
                            
                            temp_dict['source_parent_url'] = _sub_folder_dict['article_url'] if 'article_url' in _sub_folder_dict.keys() else None
                            
                            try:
                                tags_list = ', '.join(_sub_folder_dict['topic']) if _sub_folder_dict['topic'] else None
                            except KeyError:
                                tags_list = None
                            
                            temp_dict['tags'] = tags_list 
                            
                            temp_dict['created_date_epoch'] = int(datetime.now().timestamp())
                            
                            try: 
                                remarks = _sub_folder_dict['remarks']
                            except KeyError:
                                remarks = None
                            
                            temp_dict['remarks'] = remarks
                            
                            try:
                                confidence_level = _sub_folder_dict['confidence_level']
                            except KeyError:
                                confidence_level = 1
                            
                            temp_dict['confidence_level'] = confidence_level
                            
                            temp_dict['domains'] = None
                            
                            try:
                                malware_list = list(_sub_folder_dict['malware']) if _sub_folder_dict['malware'] else None
                            except KeyError:
                                malware_list = None
                            
                            temp_dict['malware'] = malware_list
                            
                            output_list_of_dicts.append(temp_dict)

    except Exception as e:  
        log.error('[-] Unable to convert the json object to list of tuples')
        log.error(e.args)
        
    return output_list_of_dicts



def store_in_local_ioc_db(extracted_iocs, database='local_ioc.db'):
    """
    CORE function: Stores the data supplied from the ioc_extract submodule into the database so specified

    Input:
        extracted_iocs: JSON object from ioc_extract submodule

    Output:
        rc: 0 if successful

    Raises Exception:
        Yes

    """
    
    rc = 0
    
    valid_tables = ['ioc_hashes', 'ioc_ip_addrs', 'ioc_domains', 'ioc_malware']

    list_of_json_objects = cleanup_input_json(extracted_iocs)
    
    log.info(f'[+] DB initialised - {database}')
    initialise_db(database)

    for table in valid_tables:
        rc = store_in_table(list_of_json_objects, table, database)
  
    log.info(f'[+] Data successfully stored/updated in {database}')
    return rc


def retrieve_from_local_ioc_db(ioc_type, ioc_val, database):
    """
    Given an input dict containing the ioc_type(s) and ioc_value(s), searches the corresponding table
    If found, returns the data in ouput_dict and error set as SUCCESS
    else, returns empty output_list and error set to the corresponding error

    """

    output_list = []
    error = 'SUCCESS'

    table_ioc_mapping = {
            'md5' : ['ioc_hashes', 'hash_value'],
            'sha1' : ['ioc_hashes', 'hash_value'],
            'sha256' : ['ioc_hashes', 'hash_value'],
            'ipv4' : ['ioc_ip_addrs', 'ip_value'],
            'malware_name' : ['ioc_malware', 'malware_name']
        }
    
    
    _table_name = table_ioc_mapping[ioc_type][0]
    _col_name = table_ioc_mapping[ioc_type][1]

    select_query = "SELECT * FROM ? WHERE ? = ?;"
    values = (_table_name, _col_name, ioc_val)

    try:
        conn = create_connection(database)
    except:
        error = f'Unable to establish connection to the database : {database}'
        return output_list, error
    
    try:
        cursor = conn.execute(select_query, values)
    except:
        error = f'Unable to query the {_table_name} to retrieve {_col_name}'
        return output_list, error
    
    rows = cursor.fetchall()

    if not rows:
        error = f'Given {ioc_type} : {ioc_val} not found in the database'
        return output_list, error

    output_list = rows
    conn.close()
    
    return output_list, error
