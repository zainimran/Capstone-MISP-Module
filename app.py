import os
import jinja2
import json
from util import sqlite_util
from module_core import handler
from flask import Flask, render_template, request, url_for
from werkzeug.datastructures import ImmutableMultiDict

app = Flask(__name__)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape = True)

@app.route('/form')
def form():
    return render_template('form.html')
 
@app.route('/data/', methods = ['POST', 'GET'])
def data():
    if request.method == 'GET':
        return_msg = "The URL /data is accessed directly. Try going to '/form' to submit form"
        return return_msg
    if request.method == 'POST':
        form_data = request.form
        form_data_dict = form_data.to_dict(flat=True)
        compatible_dict = json.dumps(form_data_dict)

        # Extracted IoCs in the response dict object
        output_from_module = handler(compatible_dict)

        # Format the extracted IoCs
        if form_data_dict['action'] == 'scrape':
            _action = 'scrape'
            try:
                extracted_ioc_dict_in_response = output_from_module['results'][0]['values']
                formatted_response_list_of_dicts = sqlite_util.cleanup_input_json(extracted_ioc_dict_in_response)
                if not formatted_response_list_of_dicts:
                    _error = "No objects in extracted IoCs"
                else:
                    _error = None
            except:
                    _error = "No objects in extracted IoCs"

        else:
            _action = 'get_from_db'
            try:
                extracted_iocs_from_db_in_response = output_from_module['results'][0]['values']
                formatted_response_list_of_dicts = extracted_iocs_from_db_in_response
                _error = extracted_iocs_from_db_in_response['error']
            except:
                _error = "Failed to retrieve IoCs from DB"

        return render_template('data.html', action_str=_action, input_list_of_dicts=formatted_response_list_of_dicts, error = _error)
 
 
app.run(host='localhost', port=5000)