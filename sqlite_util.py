#!/usr/bin/env python
# coding: utf-8

import sys
import os
import sqlite3
import logging
import json
from datetime import datetime


logging.basicConfig(level=logging.INFO, format='%(name)s:%(levelname)s:%(message)s')
log = logging.getLogger('SQLite_util')


def create_connection(database):
    """
    
    Create a database connection to the SQLite database specified by database variable
    Input: database file name
    Output: Connection object or None
    Raises an exception on error: Yes
    
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
    Input: Connection object, a CREATE TABLE statement
    Output: None
    Raises an exception on error: Yes
    
    """

    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Exception as e:
        log.error(f'[-] The following error occured! - {e.args}')
        raise



def initialise_db(database):
    """
    Given a database name, initialises the database, creates tables - so specified below,
    (can be tweaked in the future to generate custom tables by adding the query and the
    table name accordingly)

    Input: database (path to database)
    Output: None
    Raises an exception on error: Yes

    """
    try:
        # Create table ioc_hashes query
        ioc_hashes_query = '''CREATE TABLE IF NOT EXISTS ioc_hashes
                                (hash_value text,
                                hash_type text,
                                source_parent_url text, 
                                source_parent_name text,
                                threat_actor text,
                                confidence_level text,
                                created_date_epoch integer, 
                                last_updated_date_epoch integer,
                                remarks text,
                                PRIMARY KEY (hash_value, source_parent_name, threat_actor));'''

        # Create table ioc_urls query
        ioc_urls_query = '''CREATE TABLE IF NOT EXISTS ioc_urls
                             (url_value text, 
                             source_parent_url text,
                             source_parent_name text,
                             threat_actor text,
                             confidence_level text,
                             created_date_epoch integer,
                             last_updated_date_epoch integer,
                             remarks text,
                             PRIMARY KEY (url_value, source_parent_name, threat_actor));'''

        # Create table ioc_domains query
        ioc_domains_query = '''CREATE TABLE IF NOT EXISTS ioc_domains
                                 (domain_value text,
                                 ip_address text,
                                 source_parent_url text,
                                 source_parent_name text,
                                 threat_actor text,
                                 confidence_level text,
                                 created_date_epoch integer, 
                                 last_updated_date_epoch integer, 
                                 remarks text,
                                 PRIMARY KEY (domain_value, source_parent_name, threat_actor));'''
        
        conn = create_connection(database)
        try:
            create_table(conn, ioc_hashes_query)
            create_table(conn, ioc_urls_query)
            create_table(conn, ioc_domains_query)
            conn.commit()
            conn.close()
            log.info('[*] Tables created...')
        except Exception as e:
            log.error('[-] Error! Cannot connect to the database.')
            raise

    except Exception as e:
        log.error(f'[-] Table creation unsuccessful! The following error occured: {e.args}')
        raise    


def store_in_table(list_of_json_objects, table_name, database='test.db'):
    """
    Inserts the data from the json in the table and database so specified.
    Modifies/Replaces existing data depending on the constraint so set in the queries.
    
    Input: List of JSON Objects, Table name, Database name
    Output: Return Code (0 - if successful, 1 - if otherwise)
    Raises an exception on error: Yes

    """
    
    rc = 1
    
    valid_tables = ['ioc_hashes', 'ioc_urls', 'ioc_domains']
    
    if table_name not in valid_tables:
        log.error(f'[-] Invalid table name specified: {table_name}')
        return rc
    
    try:
        conn = create_connection(database)
    except Exception as e:
        log.error(f'[-] Unable to establish connection to the database - {database}')
        log.error(f'[-] {e.args}')
        return rc
    
    cursor = conn.cursor()
    
    insert_query = get_insert_query(table_name)
    if not insert_query:
        log.error(f'[-] Invalid table name specified: {table_name}')
        return rc
    
    try:
        list_of_tuples = get_tuple_list_from_json(list_of_json_objects, table_name)
        if not list_of_tuples:
            return rc
    except Exception as e:
        return rc
    
    
    try:
        cursor.executemany(insert_query, list_of_tuples)
    except Exception as e:
        log.error(f'[-] Unable to add/update data in the {database}:{table_name}')
        log.error(e.args)
        return rc
    
    conn.commit()
    conn.close()
    log.info(f'[+] Total rows added/updated - {cursor.rowcount}. Data successfully stored in {database}:{table_name}')
    rc = 0
    return rc


def get_insert_query(table_name):
    """
    Based on the table_name, returns the corresponding SQL insert query
    
    Input: Table name
    Output: None or Insert Query
    Raises an exception on error: No
    
    """
    
    table_insert_query_dict = {
        
        'ioc_hashes':'''
        INSERT OR REPLACE INTO ioc_hashes
        (hash_value,
        hash_type,
        source_parent_url,
        source_parent_name,
        threat_actor,
        confidence_level,
        created_date_epoch, 
        last_updated_date_epoch,
        remarks)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hash_value, source_parent_name, threat_actor) DO UPDATE SET
        last_updated_date_epoch = ?;
        ''',
        
        'ioc_urls':'''
        INSERT OR REPLACE INTO ioc_urls
        (url_value, 
        source_parent_url,
        source_parent_name,
        threat_actor,
        confidence_level,
        created_date_epoch,
        last_updated_date_epoch,
        remarks)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_value, source_parent_name, threat_actor) DO UPDATE SET
        last_updated_date_epoch = ?;
        ''',
        
        'ioc_domains':'''
        INSERT OR REPLACE INTO ioc_domains
        (domain_value,
        ip_address,
        source_parent_url,
        source_parent_name,
        threat_actor,
        confidence_level,
        created_date_epoch, 
        last_updated_date_epoch, 
        remarks text)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain_value, source_parent_name, threat_actor) DO UPDATE SET
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
    
    Input: JSON Object
    Output: List of tuples
    Raises an exception on error: No
    """
    list_of_tuples = []
      
    try:
        if table_name == 'ioc_hashes':
            for _obj in list_of_json_information_objects:
                _obj = json.loads(_obj)
                tuple_to_append = (_obj['hash_value'], 
                                  _obj['hash_type'],
                                  _obj['source_parent_url'],
                                  _obj['source_parent_name'],
                                  _obj['threat_actor'],
                                  _obj['confidence_level'],
                                  _obj['created_date_epoch'],
                                  _obj['created_date_epoch'],
                                  _obj['remarks'],
                                  _obj['created_date_epoch'])
                list_of_tuples.append(tuple_to_append)
        
        elif table_name == 'ioc_urls':
            for _obj in list_of_json_information_objects:
                _obj = json.loads(_obj)
                tuple_to_append = (_obj['url_value'], 
                                  _obj['source_parent_url'],
                                  _obj['source_parent_name'],
                                  _obj['threat_actor'],
                                  _obj['confidence_level'],
                                  _obj['created_date_epoch'],
                                  _obj['created_date_epoch'],
                                  _obj['remarks'],
                                  _obj['created_date_epoch'])
                list_of_tuples.append(tuple_to_append)
        
        elif table_name == 'ioc_domains':
            for _obj in list_of_json_information_objects:
                _obj = json.loads(_obj)
                tuple_to_append = (_obj['domain_value'], 
                                   _obj['ip_address'], 
                                  _obj['source_parent_url'],
                                  _obj['source_parent_name'],
                                  _obj['threat_actor'],
                                  _obj['confidence_level'],
                                  _obj['created_date_epoch'],
                                  _obj['created_date_epoch'],
                                  _obj['remarks'],
                                  _obj['created_date_epoch'])
                list_of_tuples.append(tuple_to_append)
            
        return list_of_tuples
    
    except Exception as e:
        log.error('[-] Unable to convert the list of json information objects to list of tuples')
        log.error(e.args)
        raise