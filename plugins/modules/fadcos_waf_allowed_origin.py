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
module: fadcos_waf_allowed_origin
short_description: Manage FortiADC Web Application Firewall allowed origination Signature by RESTful API
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
    - name: Add allowed_origin
      fadcos_waf_allowed_origin:
        action: add
        name: test_aw

    - name: get allowed_origin
      fadcos_waf_allowed_origin:
        action: get
        name: test_aw     

    - name: delete allowed_origin
      fadcos_waf_allowed_origin:
        action: delete
        name: test_aw
"""

RETURN = """
"""


def add_waf_allowed_origin(module, connection):
    payload = {
        'mkey': module.params['name'], 
    }

    url = '/api/security_waf_allowed_origin'
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)
    return code, response


def edit_waf_allowed_origin(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_allowed_origin?mkey=' + name
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')
    return code, response


def get_waf_allowed_origin(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_allowed_origin'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_allowed_origin(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_allowed_origin?mkey=' + name

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False
    for param in module.params: 
        if param != 'name' and module.params[param]:
            data[param] = module.params[param] 
            res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'delete') and not module.params['name']:
        err_msg.append('The name need to set.')
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
        code, response = add_waf_allowed_origin(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_waf_allowed_origin(module, connection)
        result['res'] = response
    elif action == 'delete':
        code, data = get_waf_allowed_origin(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_allowed_origin(module, connection)
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
        if result['res']['payload'] == -15:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
