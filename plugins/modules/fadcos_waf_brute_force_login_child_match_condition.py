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
module: fadcos_waf_brute_force_login_child_match_condition
short_description: Manage FortiADC Web Application Firewall brute force attack detection child match condition by RESTful API
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
    - name: Add brute_force_login_child_match_condition
      fadcos_waf_brute_force_login_child_match_condition:
        action: add
        name: b1
        failed_code: 666
        host_name: qqqq
        host_status: enable
        url: /zzzz/yyy/dd
        limit: 7777

    - name: edit brute_force_login_child_match_condition
      fadcos_waf_brute_force_login_child_match_condition:
        action: edit
        name: b1
        id: 1
        failed_code: 333
        limit: 4444

    - name: get brute_force_login_child_match_condition
      fadcos_waf_brute_force_login_child_match_condition:
        action: get
        name: b1
        id: 1

    - name: delete brute_force_login_child_match_condition
      fadcos_waf_brute_force_login_child_match_condition:
        action: delete
        name: b1
        id: 2
"""

RETURN = """
"""


def add_waf_brute_force_login_child_match_condition(module, connection):
    payload = {
        'failed_code': module.params['failed_code'],
        'host_status': module.params['host_status'],
        'host_name': module.params['host_name'],
        'limit': module.params['limit'],
        'url': module.params['url'],   
        }

    url = '/api/security_waf_brute_force_login_child_match_condition?pkey=' + module.params['name']
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_waf_brute_force_login_child_match_condition(module, payload, connection):
    mkey = module.params['id']
    pkey = module.params['name']
    url = '/api/security_waf_brute_force_login_child_match_condition?pkey=' + pkey + '&mkey=' + mkey
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')
    # response["log"] = payload
    # response["url"] = url
    return code, response


def get_waf_brute_force_login_child_match_condition(module, connection):
    mkey = module.params['id']
    pkey = module.params['name']
    payload = {}
    url = '/api/security_waf_brute_force_login_child_match_condition?pkey=' + pkey
    if mkey:
        url += '&mkey=' + mkey

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_brute_force_login_child_match_condition(module, connection):
    mkey = module.params['id']
    pkey = module.params['name']
    payload = {}
    url = '/api/security_waf_brute_force_login_child_match_condition?pkey=' + pkey + '&mkey=' + mkey

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False
    for param in module.params: 
        if param != 'name' and param != 'id' and module.params[param]:
            d_param = param
            data[d_param] = module.params[param] 
            res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name of HTTP Header Security entry need to set.')
        res = False
    if (action == 'edit' or action == 'delete') and not module.params['id']:
        err_msg.append('The ID of entry to modify need to set.')
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
        id=dict(type='str'),
        host_name=dict(type='str'),
        host_status=dict(type='str'),
        limit=dict(type='str'),
        failed_code=dict(type='str'),
        url=dict(type='str'),
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
        code, response = add_waf_brute_force_login_child_match_condition(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_waf_brute_force_login_child_match_condition(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_brute_force_login_child_match_condition(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_brute_force_login_child_match_condition(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_brute_force_login_child_match_condition(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_brute_force_login_child_match_condition(module, connection)
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
