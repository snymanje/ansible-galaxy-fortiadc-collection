#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_waf_http_header_security
short_description: Manage FortiADC Web Application Firewall sensitive data types by RESTful API
description:
  - Manage FortiADC Web Application Firewall profile by RESTful API
version_added: "2.8"
author: ""
options:
"""

EXAMPLES = """
- name:
  hosts: all
  vars:
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Add waf_sensitive_data_type
      fadcos_waf_sensitive_data_type:
        action: add
        name: myurl
        desc: this is a test!!!
        regex: ^(http|https|ftp|ldap|mailto|news|tel|telnet|urn|file|ssh|tftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)?((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4})(\:[0-9]+)?(/[^/][a-zA-Z0-9\.\,\?\'\\/\+&amp;%\$#\=~_\-@]*)*$

    - name: edit waf_sensitive_data_type
      fadcos_waf_sensitive_data_type:
        action: edit
        name: myurl
        desc: it is changed!

    - name: get waf_sensitive_data_type
      fadcos_waf_sensitive_data_type:
        action: get
        name: myurl

    - name: delete waf_sensitive_data_type
      fadcos_waf_sensitive_data_type:
        action: delete
        name: myurl
"""

RETURN = """
"""


def add_waf_http_header_security(module, connection):
    payload = {
        'mkey': module.params['name'],
        'desc': module.params['desc'],
        'regex': module.params['regex'],
        }
    url = '/api/security_waf_sensitive_data_type'
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def get_waf_http_header_security(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_sensitive_data_type'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response

def needs_update(module, data):
    res = False
    for param in module.params: 
        data[param] = module.params[param] 
        res = True
    return res, data

def edit_waf_http_header_security(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_sensitive_data_type?mkey=' + name
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')
    # response["log"] = payload
    # response["url"] = url
    return code, response


def delete_waf_http_header_security(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_sensitive_data_type?mkey=' + name

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'delete'  or action == 'edit') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if (action == 'add' ) and not module.params['regex']:
        err_msg.append('The Regex of sensitive data type need to set.')
        res = False
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append(
            'The vdom is enable in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not accsee the vdom ' +
                       module.params['vdom'])
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        regex=dict(type='str'),
        desc=dict(type='str'),
    )

    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add':
        code, response = add_waf_http_header_security(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_waf_http_header_security(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_http_header_security(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_http_header_security(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_http_header_security(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_http_header_security(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = False
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True
        if result['res']['payload'] == -15 or result['res']['payload'] == -13:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
