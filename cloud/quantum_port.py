#!/usr/bin/python
#coding: utf-8 -*-

# (c) 2014, Taneli Leppä <taneli@crasman.fi>
# (c) 2013, Benno Joy <benno@ansible.com>
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

try:
    try:
        from neutronclient.neutron import client
    except ImportError:
        from quantumclient.quantum import client
    from keystoneclient.v2_0 import client as ksclient
except ImportError:
    print("failed=True msg='quantumclient (or neutronclient) and keystone client are required'")

DOCUMENTATION = '''
---
module: quantum_port
version_added: "1.9"
short_description: Creates/updates Quantum/Neutron ports
description:
   - Add/update ports in OpenStack.
options:
   login_username:
     description:
        - login username to authenticate to keystone
     required: true
     default: admin
   login_password:
     description:
        - Password of login user
     required: true
     default: 'yes'
   login_tenant_name:
     description:
        - The tenant name of the login user
     required: true
     default: 'yes'
   login_tenant_id:
     description:
        - The tenant ID of the login user
     required: false
   tenant_name:
     description:
        - The name of the tenant for whom the network is created
     required: false
     default: None
   auth_url:
     description:
        - The keystone url for authentication
     required: false
     default: 'http://127.0.0.1:35357/v2.0/'
   state:
     description:
        - Indicate desired state of the resource
     choices: ['present', 'absent']
     default: present
   network_name:
     description:
        - Network name to add port to 
     required: false
     default: None
   name:
     description:
        - Name to be assigned to the port
     required: false
     default: None
   ip_address:
     description:
        - IP address of port (for finding the port)
     required: false
     default: None
   fixed_ip:
     description:
        - Fixed IP address for port
     required: false
     default: None
   security_groups:
     description:
        - Security groups IDs (list)
     required: false
     default: None
   allowed_address_pairs:
     description:
        - Allowed address pairs (useful for eg. VRRP), type list (of { mac_address : '', ip_address : '' })
     required: false
     default: false
   mac_address:
     description:
        - Port MAC address
     required: false
     default: false
   admin_state_up:
     description:
        - Whether the state should be marked as up or down
     required: false
     default: true
requirements: ["quantumclient", "neutronclient", "keystoneclient"]

'''

EXAMPLES = '''
# Create or update port
quantum_port:
  state: present
  auth_url: "url"
  login_username: "user"
  login_password: "password"
  login_tenant_name: "tenant name"
  network_name: "my-network"
  name: "VRRP port"
  security_groups:
    - "1333bbff-d399-40d7-954f-6f5329463610"
  allowed_address_pairs:
    - { 'ip_address' : '10.1.55.79' }
  fixed_ip: "10.1.55.12"
'''

_os_keystone = None
_os_tenant_id = None

def _get_ksclient(module, kwargs):
    try:
        kclient = ksclient.Client(username=kwargs.get('login_username'),
                                 password=kwargs.get('login_password'),
                                 tenant_name=kwargs.get('login_tenant_name'),
                                 auth_url=kwargs.get('auth_url'))
    except Exception, e:
        module.fail_json(msg = "Error authenticating to the keystone: %s" %e.message)
    global _os_keystone
    _os_keystone = kclient
    return kclient


def _get_endpoint(module, ksclient):
    try:
        endpoint = ksclient.service_catalog.url_for(service_type='network', endpoint_type='publicURL')
    except Exception, e:
        module.fail_json(msg = "Error getting network endpoint: %s " %e.message)
    return endpoint

def _get_neutron_client(module, kwargs):
    _ksclient = _get_ksclient(module, kwargs)
    token = _ksclient.auth_token
    endpoint = _get_endpoint(module, _ksclient)
    kwargs = {
            'token': token,
            'endpoint_url': endpoint
    }
    try:
        neutron = client.Client('2.0', **kwargs)
    except Exception, e:
        module.fail_json(msg = " Error in connecting to neutron: %s " %e.message)
    return neutron

def _set_tenant_id(module):
    global _os_tenant_id

    if module.params['tenant_id']:
        _os_tenant_id = module.params['tenant_id']
        return

    if not module.params['tenant_name']:
        tenant_name = module.params['login_tenant_name']
    else:
        tenant_name = module.params['tenant_name']

    for tenant in _os_keystone.tenants.list():
        if tenant.name == tenant_name:
            _os_tenant_id = tenant.id
            break
    if not _os_tenant_id:
        module.fail_json(msg = "The tenant id cannot be found, please check the parameters")

def _get_networks(neutron, module):
    kwargs = {
            'tenant_id': _os_tenant_id
    }
    try:
        networks = neutron.list_networks(**kwargs)
    except Exception, e:
        module.fail_json(msg = "Error in listing neutron networks: %s" % e.message)
    if not networks['networks']:
        return None
    return networks['networks']

def _get_security_groups(neutron, module):
    kwargs = {
            'tenant_id': _os_tenant_id
    }
    try:
        secgroups = neutron.list_security_groups(**kwargs)
    except Exception, e:
        module.fail_json(msg = "Error in listing neutron security groups: %s" % e.message)
    if not secgroups['security_groups']:
        return None
    return secgroups['security_groups']

def _find_port(neutron, module):
    kwargs = {
            'tenant_id': _os_tenant_id
    }
    try:
        ports = neutron.list_ports(**kwargs)
    except Exception, e:
        module.fail_json(msg = "Error in listing neutron ports: %s" % e.message)

    if not ports['ports']:
        return None

    for port in ports['ports']:
        if module.params['name'] and module.params['name'] != '' and port['name'] == module.params['name']:
            return port
        if module.params['ip_address'] and len(port['fixed_ips']) > 0:
            for fip in port['fixed_ips']:
                if fip['ip_address'] == module.params['ip_address']:
                    return port
        if module.params['mac_address'] and port['mac_address'] == module.params['mac_address']:
            return port

    return None

def _get_port(neutron, module, port_id):
    try:
        port = neutron.show_port(port_id)
    except Exception, e:
        module.fail_json(msg = "Error in getting neutron port: %s" % e.message)

    module.fail_json(msg = port)

    return None

def _update_port(neutron, module, old_port):
    neutron.format = 'json'

    security_groups = None
    if module.params['security_groups'] and len(module.params['security_groups']) > 0:
        groups = _get_security_groups(neutron, module)
        if not groups:
            module.fail_json(msg = "Could not find any security groups")

        security_groups = []
        for sgroup in module.params['security_groups']:
            for group in groups:
                if group['name'] == sgroup:
                    security_groups.append(group['id'])
                    break

    port = {
        'name':                      module.params.get('name'),
        'mac_address':               module.params.get('mac_address'),
        'fixed_ips':                 [ { 'ip_address' : module.params.get('fixed_ip') } ],
        'allowed_address_pairs':     module.params.get('allowed_address_pairs'),
        'security_groups':           security_groups,
        'admin_state_up':            module.params.get('admin_state_up'),
    }

    if module.params['mac_address'] is None:
        port.pop('mac_address', None)

    # Neutron adds subnet IDs
    if 'fixed_ips' in old_port:
        for idx, item in enumerate(old_port['fixed_ips']):
            if 'subnet_id' in item:
                old_port['fixed_ips'][idx].pop('subnet_id', None)

    # Compare old port with updated port
    changed = False
    for k in port:
        if k not in old_port:
            changed = True
            break

        if k == 'allowed_address_pairs' and port[k] != None:
            # If the user has not specified mac addresses, don't compare those, since Neutron adds them automatically
            has_mac = False
            for idx, item in enumerate(port[k]):
                if 'mac_address' in item:
                    has_mac = True
                    break
            if not has_mac:
                for idx, item in enumerate(old_port[k]):
                    if 'mac_address' in item:
                        old_port[k][idx].pop('mac_address', None)

        if isinstance(port[k], list) or isinstance(port[k], dict):
            if module.jsonify(port[k]) != module.jsonify(old_port[k]):
                changed = True
                break
        else:
            if port[k] != old_port[k]:
                changed = True
                break
 
    if module.params['allowed_address_pairs'] is None:
        port.pop('allowed_address_pairs', None)
    if module.params['fixed_ip'] is None:
        port.pop('fixed_ips', None)
    if module.params['security_groups'] is None:
        port.pop('security_groups', None)

    if not changed:
        return False

    try:
        updated_port = neutron.update_port(old_port['id'], {'port':port})
    except Exception, e:
        module.fail_json(msg = "Error in updating port: %s" % e.message)

    return updated_port['port']

def _create_port(neutron, module):    
    networks = _get_networks(neutron, module)
    if not networks:
        module.fail_json(msg = "Could not find network: %s" % module.params['network_name'])

    network = None
    for _network in networks:
        if _network['name'] == module.params['network_name']:
            network = _network
            break
    if not network:
        module.fail_json(msg = "Could not find network: %s" % module.params['network_name'])
    
    neutron.format = 'json'

    security_groups = None
    if module.params['security_groups'] and len(module.params['security_groups']) > 0:
        groups = _get_security_groups(neutron, module)
        if not groups:
            module.fail_json(msg = "Could not find any security groups")
        security_groups = []
        for sgroup in module.params['security_groups']:
            for group in groups:
                if group['name'] == sgroup:
                    security_groups.append(group['id'])
                    break

    port = {
        'network_id':                network['id'],
        'name':                      module.params.get('name'),
        'tenant_id':                 _os_tenant_id,
        'mac_address':               module.params.get('mac_address'),
        'fixed_ips':                 [ { 'ip_address' : module.params.get('fixed_ip') } ],
        'allowed_address_pairs':     module.params.get('allowed_address_pairs'),
        'security_groups':           security_groups,
        'admin_state_up':            module.params.get('admin_state_up'),
    }

    if module.params['allowed_address_pairs'] is None:
        port.pop('allowed_address_pairs', None)
    if module.params['fixed_ip'] is None:
        port.pop('fixed_ip', None)
    if module.params['mac_address'] is None:
        port.pop('mac_address', None)
    if module.params['security_groups'] is None:
        port.pop('security_groups', None)

    try:
        new_port = neutron.create_port({'port':port})
    except Exception, e:
        module.fail_json(msg = "Error in creating port: %s" % e.message)
        
    if not new_port['port']:
        module.fail_json(msg = "Error in creating port")

    return new_port['port']

def _delete_port(neutron, module, old_port):
    try:
        neutron.delete_port(old_port['id'])
    except Exception, e:
        module.fail_json(msg = "Error in deleting port: %s" % e.message)
    return True

def main():

    argument_spec = openstack_argument_spec()
    argument_spec.update(dict(
            name                            = dict(default=''),
            tenant_name                     = dict(default=None),
            tenant_id                       = dict(default=None),
            network_name                    = dict(default=None),
            ip_address                      = dict(default=None),
            fixed_ip                        = dict(default=None),
            security_groups                 = dict(default=None, type='list'),
            allowed_address_pairs           = dict(default=None, type='list'),
            mac_address                     = dict(default=None),
            admin_state_up                  = dict(default=True, type='bool'),
            state                           = dict(default='present', choices=['absent', 'present'])
    ))
    module = AnsibleModule(argument_spec=argument_spec)

    neutron = _get_neutron_client(module, module.params)

    _set_tenant_id(module)

    if module.params['state'] == 'present':
        port = _find_port(neutron, module)
        if not port:
            port = _create_port(neutron, module)
            module.exit_json(changed = True, result = "Created", info = port)
        else:
            updated_port = _update_port(neutron, module, port)
            if updated_port == False:
                module.exit_json(changed = False, result = "Not updated", info = port)
            else:
                module.exit_json(changed = True, result = "Updated", info = updated_port)

    if module.params['state'] == 'absent':
        port = _find_port(neutron, module)
        if not port:
            module.exit_json(changed = False, result = "Success")
        else:
            _delete_port(neutron, module, port)
            module.exit_json(changed = True, result = "Deleted")

# this is magic, see lib/ansible/module.params['common.py
from ansible.module_utils.basic import *
from ansible.module_utils.openstack import *
main()

