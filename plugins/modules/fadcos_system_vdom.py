#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/08/30

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
module: fadcos_system_vdom
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/system_vdom'

edit_dict = {
}

def update_payload(module):
    payload = {
    'name': module.params['name'],
    'mkey': module.params['name'],
    'l4cps': module.params['l4cps'],
    'l7cps': module.params['l7cps'],
    'l7rps': module.params['l7rps'],
    'sslcps': module.params['sslcps'],
    'sslthroughput': module.params['sslthroughput'],
    'concurrentsession': module.params['concurrentsession'],
    'inbound': module.params['inbound'],
    'outbound': module.params['outbound'],
    'vs': module.params['virtual_server'],
    'rs': module.params['real_server'],
    'hc': module.params['health_check'],
    'sp': module.params['source_pool'],
    'ep': module.params['error_page'],
    'lu': module.params['local_user'],
    'ug': module.params['user_group'],
    }

    return payload

def get_obj(module, connection):
    payload = {}
    url = obj_url + '/get_vdom_rlimit?vdom=' + module.params['name'] + '&pkey=' + module.params['name'] 

    return request_obj(url, payload, connection, 'GET')

def edit_obj(module, connection):
    payload = update_payload(module)
    url = obj_url + '?vdom=' + module.params['name'] + '&pkey=' + module.params['name'] + '&mkey=' + module.params['name']

    return request_obj(url, payload, connection, 'PUT')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if action != 'get' and action != 'edit':
        res = False
        err_msg.append('The '+ action + 'is not supported.')

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str', required=True),
        l4cps=dict(type='str', default='0'),
        l7cps=dict(type='str', default='0'),
        l7rps=dict(type='str', default='0'),
        sslcps=dict(type='str', default='0'),
        sslthroughput=dict(type='str', default='0'),
        concurrentsession=dict(type='str', default='0'),
        inbound=dict(type='str', default='0'),
        outbound=dict(type='str', default='0'),
        virtual_server=dict(type='str', default='0'),
        real_server=dict(type='str', default='0'),
        health_check=dict(type='str', default='0'),
        source_pool=dict(type='str', default='0'),
        error_page=dict(type='str', default='0'),
        local_user=dict(type='str', default='0'),
        user_group=dict(type='str', default='0'),
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
        result['res'] = response
    elif action == 'edit':
        code, response = edit_obj(module, connection)
        result['changed'] = True
        result['res'] = response

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True
        if result['res']['payload'] == -289 or result['res']['payload'] == -15:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
