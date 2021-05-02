import chef
import json
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USERNAME = "pivotal"
CHEF_SERVER = "localhost"
PORT = 4443
KEY = open("test.pem").read()

api = chef.API(CHEF_SERVER, USERNAME, KEY, port=PORT, verify=False)

if 'auser' in api.list_users():
    api.delete_user('auser')

if 'anorg' in api.list_orgs():
    api.delete_org('anorg')


api.create_user('auser', 'A', 'User', 'auser@localhost.localdomain', 'password')
api.update_user('auser', middle_name='Bob')
api.create_user_key('auser', 'akey')
api.get_user_key('auser', 'akey')
api.list_user_keys('auser')
api.delete_user_key('auser', 'akey')
api.get_user('auser')

api.create_org('anorg', 'Example')
api.update_org('anorg', full_name='Example renamed')
api.get_org('anorg')

api.create_org_client('anorg', 'aclient')
api.update_org_client('anorg', 'aclient', name='aclient-renamed')
api.get_org_client('anorg', 'aclient-renamed')
api.delete_org_client('anorg', 'aclient-renamed')

api.create_org_data('anorg', 'abag')
api.create_org_data_item('anorg', 'abag', 'anitem', dict(key1='value1'))
api.update_org_data_item('anorg', 'abag', 'anitem', dict(key2='value2'))
api.replace_org_data_item('anorg', 'abag', 'anitem', dict(key1='value1'))
api.get_org_data_item('anorg', 'abag', 'anitem')
api.delete_org_data_item('anorg', 'abag', 'anitem')
api.get_org_data('anorg', 'abag')
api.delete_org_data('anorg', 'abag')

api.create_org_role('anorg', 'arole')
api.list_org_roles('anorg')
api.update_org_role('anorg', 'arole', run_list=['recipe[acme]'])
api.get_org_role('anorg', 'arole')
api.delete_org_role('anorg', 'arole')

api.create_org_environment('anorg', 'anenv')
api.list_org_environments('anorg')
api.update_org_environment('anorg', 'anenv', cookbook_versions=dict(acme='1.0.0'))
api.get_org_environment('anorg', 'anenv')

api.create_org_node('anorg', 'ahost')
api.list_org_nodes('anorg')
api.get_org_node('anorg', 'ahost')
api.update_org_node('anorg', 'ahost', chef_environment='anenv')
api.delete_org_node('anorg', 'ahost')

api.delete_org_environment('anorg', 'anenv')

api.create_org_client('anorg', 'aclient')
api.list_org_clients('anorg')
api.get_org_client('anorg', 'aclient')
api.update_org_client('anorg', 'aclient', validator=False)
api.create_org_client_key('anorg', 'aclient', 'akey')
api.list_org_client_keys('anorg', 'aclient')
api.get_org_client_key('anorg', 'aclient', 'akey')
api.delete_org_client_key('anorg', 'aclient', 'akey')
api.delete_org_client('anorg', 'aclient')

api.delete_user('auser')
api.delete_org('anorg')
