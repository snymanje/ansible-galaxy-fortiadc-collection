#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/04/06

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: system_snmp_user_child_host
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/system_snmp_user_child_host'

edit_dict = {
}

def update_payload(module):
    payload = {
    'name': module.params['name'],
    'pkey': module.params['snmp_name'],
    'ip': module.params['ip'],
    'mkey': module.params['id'],
    'mkeys': module.params['id_list'],
    'host_type': module.params['host_type'],
    }

    return payload

def get_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '?pkey=' + pkey

    return request_obj(url, payload, connection, 'GET')

def add_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '?pkey=' + pkey

    return request_obj(url, payload, connection, 'POST')

def remove_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '/batch_remove?pkey=' + pkey

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    mkey = payload['mkey']
    url = obj_url + '?pkey=' + pkey + '&mkey=' + mkey

    return request_obj(url, payload, connection, 'PUT')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = False
    action = module.params['action']
    err_msg = ''
    if (action == 'get' or action == 'add' or action == 'remove' or action == 'edit'):
        res = True
    else:
        res = False
        err_msg = action + 'is not supported'

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        ip=dict(type='str'),
        snmp_name=dict(type='str', required=True),
        id=dict(type='str'),
        id_list=dict(type='list'),
        host_type=dict(type='str', default='any'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_msg = param_check(module, connection)
    if not param_pass:
        result['failed'] = True
        result['err_msg'] = param_msg
    elif action == 'get':
        code, response = get_obj(module, connection)
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
    elif action == 'remove':
        code, response = remove_obj(module, connection)
        if 'payload' in response.keys() and response['payload'] and type(response['payload']) is int and response['payload'] < 0:
            response['payload'] = 0
        result['changed'] = True
    elif action == 'edit':
        code, response = edit_obj(module, connection)
        result['changed'] = True
    result['res'] = response

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True
        if result['res']['payload'] == -13 or result['res']['payload'] == -15:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
