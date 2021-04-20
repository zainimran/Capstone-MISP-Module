import os
import sys
import json
import requests
from util import sqlite_util
import logging

logging.basicConfig(level=logging.INFO, format='%(name)s:%(levelname)s:%(message)s')
log = logging.getLogger('module_core')


misperrors = { 
    'error':'Error'
}

moduleinfo = {
    'version': '0.1', 
    'author': 'CMU Capstone Project - Mattias Rosner, Reginald Savoy, Ryan Chalk, Sachit Malik, Zain Imran',
    'description': '<TODO>',
    'module-type': ['expansion']
}

mispattributes = {
    'input': ['url'],
    'output': ['text'],
}

moduleconfig = [
    'custom_API'
]

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def handler(q=False):
    
    if q is False:
        return False
    
    req = json.loads(q)
    
    """
    <TODO> PLACEHOLDER for CODE
    """

    """
    FLAG: Should it run it or not? - FLAG field in the request
    """

    """
    INVOKE the Web SPIDER
    """

    """
    INVOKE IOC_EXTRACT
    """

    """
    INVOKE SQLite Module
    """

    """
    Send the result back
    """


    list_of_dicts = [{}]

    response = {'results': [{'types': mispattributes['output'], 'values': list_of_dicts}]}
    
    return response