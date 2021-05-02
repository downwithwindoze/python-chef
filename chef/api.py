import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, urlsplit, urljoin
from datetime import datetime, timezone
import hashlib
import os
import json as libjson
import base64
import types

with open(os.path.join(os.path.dirname(__file__), "init.json")) as f:
    init = libjson.load(f)

class OperationFailed(Exception):
    def __init__(self, operation, path, code, text):
        self.path = path
        self.code = code
        self.message = f"Code {code} {operation} {path}"
        self.text = text

class GetFailed(OperationFailed):
    def __init__(self, *args):
        super().__init__('getting', *args)

class DeleteFailed(OperationFailed):
    def __init__(self, *args):
        super().__init__('deleting', *args)


class ChangeFailed(OperationFailed):
    def __init__(self, operation, json, *args):
        super().__init__(operation, *args)
        self.input = json

class CreateFailed(ChangeFailed):
    def __init__(self, *args):
        super().__init__('creating', *args)
        
class UpdateFailed(ChangeFailed):
    def __init__(self, *args):
        super().__init__('updating', *args)
        
class GetInvalid(Exception):
    pass

class UpdateInvalid(Exception):
    def __init__(self, path, items):
        self.message = f"Updating {path} no valid parameter provided from {', '.join(items)}"
        
class API(requests.Session):
    def __init__(self, server, user, key, port=443, password=None, verify=True, cache=True):
        super().__init__()
        self._key = serialization.load_pem_private_key(key.encode('utf-8'), password=password)
        self._user = user
        self._verify = verify
        self._server = server
        self._port = port
        self._cache = cache
        self._headers = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'X-Ops-Server-API-Version': '1',
            'X-Ops-UserId': self._user,
            'X-Ops-Sign': 'algorithm=sha256;version=1.3;',
            'X-Ops-Timestamp': None,
            'X-Ops-Content-Hash': None,
            'X-Chef-Version': '14.0.0',
            'Host': self._server,
            'Path': None,
            'User-Agent': f"python-chef {init['version']}"
        }
        self._canon = {
            'Method': None,
            'Path': None,
            'X-Ops-Content-Hash': None,
            'X-Ops-Sign': 'version=1.3',
            'X-Ops-Timestamp': None,
            'X-Ops-UserId': self._user,
            'X-Ops-Server-API-Version': '1'
        }
        self._cached = dict()

    @property
    def server(self):
        return self._server

    @property
    def key(self):
        return self._key

    @property
    def user(self):
        return self._user

    @property
    def port(self):
        return self._port

    def get_search_indexes(self, org, **kwargs):
        return list(self.get_path(f'/organizations/{org}/search', **kwargs).keys())
    
    # see https://docs.chef.io/workstation/knife_search/#query-syntax
    def search(self, org, index, start=0, rows=None, query='*', **kwargs):
        if index not in self.search_indexes:
            raise GetInvalid('invalid search index')
        params = dict(start=start, q=query)
        if rows is not None:
            params['rows'] = rows
        return self.get_path(f'/organizations/{org}/search/{index}', params=params, **kwargs)['rows']

    def create_user(self, username, first_name, last_name, email, password, middle_name=None, display_name=None, public_key=None, **kwargs):
        if not display_name:
            display_name = f"{first_name} {middle_name+' ' if middle_name else ''}{last_name}"
        params = dict(username=username, first_name=first_name, last_name=last_name, email=email, password=password, create_key=not public_key, display_name=display_name)
        if middle_name:
            params['middle_name'] = middle_name
        if public_key:
            params['public_key'] = public_key
        return self.create_path('/users', params, **kwargs)

    def get_license(self, **kwargs):
        path = '/license'
        return self.get_path(path, **kwargs)
    @property
    def license(self):
        return self.get_license(cache=False, cached=False)

    def get_stats(self, **kwargs):
        path = '/_stats'
        return self.get_path(path, **kwargs)
    @property
    def stats(self):
        return self.get_stats(cache=False, cached=False)

    def get_status(self, **kwargs):
        path = '/_status'
        return self.get_path(path, **kwargs)
    @property
    def status(self):
        return self.get_status(cache=False, cached=False)

    def get_cookbooks(self, **kwargs):
        path = '/universe'
        return self.get_path(path, **kwargs)
    @property
    def cookbooks(self):
        return self.get_cookbooks(cache=False, cached=False)

    def list_users(self, **kwargs):
        path = '/users'
        return self.get_path(path, **kwargs)
    
    def get_user(self, user, **kwargs):
        path = '/users/%s'%(user,)
        return self.get_path(path, **kwargs)

    def update_user(self, user, **kwargs):
        path = '/users/%s'%(user,)
        kwargs['username'] = kwargs.get('username', user)
        return self.update_path(path, ['username', 'display_name', 'email', 'first_name', 'last_name', 'middle_name'], **kwargs)

    def delete_user(self, user, **kwargs):
        path = '/users/%s'%(user,)
        return self.delete_path(path, **kwargs)

    def list_orgs(self, **kwargs):
        path = '/organizations'
        return self.get_path(path, **kwargs)

    def get_org(self, org, **kwargs):
        path = '/organizations/%s'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org(self, name, full_name, **kwargs):
        path = '/organizations'
        paras = dict()
        paras["name"] = name
        paras["full_name"] = full_name
        return self.create_path(path, paras, **kwargs)

    def update_org(self, org, **kwargs):
        path = '/organizations/%s'%(org,)
        kwargs['name'] = kwargs.get('name', org)
        return self.update_path(path, ['name', 'full_name'], **kwargs)

    def delete_org(self, org, **kwargs):
        path = '/organizations/%s'%(org,)
        return self.delete_path(path, **kwargs)

    def get_org_association_requests(self, org, **kwargs):
        path = '/organizations/%s/association_requests'%(org,)
        return self.get_path(path, **kwargs)

    def create_org_association_request(self, org, **kwargs):
        path = '/organizations/%s/association_requests'%(org,)
        paras = dict()
        return self.create_path(path, paras, **kwargs)

    def list_org_clients(self, org, **kwargs):
        path = '/organizations/%s/clients'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org_client(self, org, name, validator=True, create_key=True, **kwargs):
        path = '/organizations/%s/clients'%(org,)
        paras = dict()
        paras["name"] = name
        paras["clientname"] = name
        paras["validator"] = validator
        paras["create_key"] = create_key
        return self.create_path(path, paras, **kwargs)

    def get_org_client(self, org, client, **kwargs):
        path = '/organizations/%s/clients/%s'%(org,client,)
        return self.get_path(path, **kwargs)

    def update_org_client(self, org, client, **kwargs):
        path = '/organizations/%s/clients/%s'%(org,client,)
        if 'name' in kwargs:
            kwargs['clientname'] = kwargs['name']
        if 'clientname' in kwargs:
            kwargs['name'] = kwargs['clientname']
        return self.update_path(path, ['name', 'clientname', 'validator'], **kwargs)

    def delete_org_client(self, org, client, **kwargs):
        path = '/organizations/%s/clients/%s'%(org,client,)
        return self.delete_path(path, **kwargs)

    def get_org_cookbook_artifact_version(self, org, cookbook_artifact, version, **kwargs):
        path = '/organizations/%s/cookbook_artifacts/%s/%s'%(org,cookbook_artifact,version,)
        return self.get_path(path, **kwargs)

    def list_org_cookbook_artifacts(self, org, **kwargs):
        path = '/organizations/%s/cookbook_artifacts'%(org,)
        return self.get_path(path, **kwargs)
    
    def get_org_cookbook_artifact(self, org, cookbook_artifact, **kwargs):
        path = '/organizations/%s/cookbook_artifacts/%s'%(org,cookbook_artifact,)
        return self.get_path(path, **kwargs)

    def get_org_cookbook_version(self, org, cookbook, version, **kwargs):
        path = '/organizations/%s/cookbooks/%s/%s'%(org,cookbook,version,)
        return self.get_path(path, **kwargs)

    def list_org_cookbooks(self, org, **kwargs):
        path = '/organizations/%s/cookbooks'%(org,)
        return self.get_path(path, **kwargs)
    
    def get_org_cookbook(self, org, cookbook, **kwargs):
        path = '/organizations/%s/cookbooks/%s'%(org,cookbook,)
        return self.get_path(path, **kwargs)

    def delete_org_cookbook(self, org, cookbook, **kwargs):
        path = '/organizations/%s/cookbooks/%s'%(org,cookbook,)
        return self.delete_path(path, **kwargs)

    def get_org_cookbooks_latest(self, org, **kwargs):
        path = '/organizations/%s/cookbooks/_latest'%(org,)
        return self.get_path(path, **kwargs)

    def get_org_cookbooks_recipes(self, org, **kwargs):
        path = '/organizations/%s/cookbooks/_recipes'%(org,)
        return self.get_path(path, **kwargs)

    def list_org_data(self, org, **kwargs):
        path = '/organizations/%s/data'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org_data(self, org, name, **kwargs):
        path = '/organizations/%s/data'%(org,)
        paras = dict()
        paras["name"] = name
        return self.create_path(path, paras, **kwargs)

    def delete_org_data(self, org, data, **kwargs):
        path = '/organizations/%s/data/%s'%(org,data,)
        return self.delete_path(path, **kwargs)

    def get_org_data(self, org, data, **kwargs):
        path = '/organizations/%s/data/%s'%(org,data,)
        return self.get_path(path, **kwargs)
        
    def get_org_data_item(self, org, data, item, **kwargs):
        path = '/organizations/%s/data/%s/%s'%(org,data,item,)
        return self.get_path(path, **kwargs)

    def delete_org_data_item(self, org, data, item, **kwargs):
        path = '/organizations/%s/data/%s/%s'%(org,data,item,)
        return self.delete_path(path, **kwargs)

    def create_org_data_item(self, org, data, name, content, **kwargs):
        path = '/organizations/%s/data/%s'%(org,data,)
        paras = content
        if 'id' not in paras:
            paras['id'] = name
        return self.create_path(path, paras, **kwargs)

    def update_org_data_item(self, org, data, item, content, **kwargs):
        path = '/organizations/%s/data/%s/%s'%(org,data,item,)
        if 'id' not in content:
            content['id'] = item
        kwargs.update(content)
        return self.update_path(path, list(content.keys()), **kwargs)

    def replace_org_data_item(self, org, data, item, content, **kwargs):
        kwargs['replace'] = True
        return self.update_org_data_item(org, data, item, content, **kwargs)
        
    def list_org_environments(self, org, **kwargs):
        path = '/organizations/%s/environments'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org_environment(self, org, name, default_attributes={}, json_class='Chef::Environment', description='', cookbook_versions={}, chef_type='environment', **kwargs):
        path = '/organizations/%s/environments'%(org,)
        paras = dict()
        paras["name"] = name
        paras["default_attributes"] = default_attributes
        paras["json_class"] = json_class
        paras["description"] = description
        paras["cookbook_versions"] = cookbook_versions
        paras["chef_type"] = chef_type
        return self.create_path(path, paras, **kwargs)

    def get_org_environment(self, org, environment, **kwargs):
        path = '/organizations/%s/environments/%s'%(org,environment,)
        return self.get_path(path, **kwargs)

    def delete_org_environment(self, org, environment, **kwargs):
        path = '/organizations/%s/environments/%s'%(org,environment,)
        return self.delete_path(path, **kwargs)

    def update_org_environment(self, org, environment, **kwargs):
        path = '/organizations/%s/environments/%s'%(org,environment,)
        return self.update_path(path, ['name', 'default_attributes', 'description', 'cookbook_versions'], **kwargs)

    def create_org_environment_cookbook_version(self, org, environment, run_list, **kwargs):
        path = '/organizations/%s/environments/%s/cookbook_versions'%(org,environment,)
        paras = dict()
        paras["run_list"] = run_list
        return self.create_path(path, paras, **kwargs)

    def get_org_environment_cookbooks(self, org, environment, **kwargs):
        path = '/organizations/%s/environments/%s/cookbooks'%(org,environment,)
        return self.get_path(path, **kwargs)

    def get_org_environment_nodes(self, org, environment, **kwargs):
        path = '/organizations/%s/environments/%s/nodes'%(org,environment,)
        return self.get_path(path, **kwargs)

    def get_org_environment_recipes(self, org, environment, **kwargs):
        path = '/organizations/%s/environments/%s/recipes'%(org,environment,)
        return self.get_path(path, **kwargs)

    def get_org_environment_role(self, org, environment, role, **kwargs):
        path = '/organizations/%s/environments/%s/roles/%s'%(org,environment,role,)
        return self.get_path(path, **kwargs)

    def get_org_default_environment(self, org, **kwargs):
        path = '/organizations/%s/environments/_default'%(org,)
        return self.get_path(path, **kwargs)

    def list_org_groups(self, org, **kwargs):
        path = '/organizations/%s/groups'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org_group(self, org, name, groupname=None, actors=[], **kwargs):
        path = '/organizations/%s/groups'%(org,)
        paras = dict()
        paras["name"] = name
        paras["groupname"] = (groupname or name)
        paras["actors"] = actors
        return self.create_path(path, paras, **kwargs)

    def get_org_group(self, org, group, **kwargs):
        path = '/organizations/%s/groups/%s'%(org,group,)
        return self.get_path(path, **kwargs)

    def delete_org_group(self, org, group, **kwargs):
        path = '/organizations/%s/groups/%s'%(org,group,)
        return self.delete_path(path, **kwargs)

    def update_org_group(self, org, group, **kwargs):
        path = '/organizations/%s/groups/%s'%(org,group,)
        return self.update_path(path, ['name', 'groupname', 'actors'], **kwargs)

    def list_org_nodes(self, org, **kwargs):
        path = '/organizations/%s/nodes'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org_node(self, org, name, chef_type='node', json_class='Chef::Node', overrides={}, run_list=[], **kwargs):
        path = '/organizations/%s/nodes'%(org,)
        paras = dict()
        paras["name"] = name
        paras["chef_type"] = chef_type
        paras["json_class"] = json_class
        paras["run_list"] = run_list
        return self.create_path(path, paras, **kwargs)

    def get_org_node(self, org, node, **kwargs):
        path = '/organizations/%s/nodes/%s'%(org,node,)
        return self.get_path(path, **kwargs)

    def delete_org_node(self, org, node, **kwargs):
        path = '/organizations/%s/nodes/%s'%(org,node,)
        return self.delete_path(path, **kwargs)

    def exists_org_node(self, org, node, **kwargs):
        path = '/organizations/%s/nodes/%s'%(org,node,)
        return self.exists_path(path, **kwargs)

    def update_org_node(self, org, node, **kwargs):
        path = '/organizations/%s/nodes/%s'%(org,node,)
        return self.update_path(path, ['name', 'chef_type', 'json_class', 'attributes', 'run_list', 'defaults', 'overrides', 'chef_environment'], **kwargs)

    def get_org_policies(self, org, **kwargs):
        path = '/organizations/%s/policies'%(org,)
        return self.get_path(path, **kwargs)

    def get_org_policy_groups(self, org, **kwargs):
        path = '/organizations/%s/policy_groups'%(org,)
        return self.get_path(path, **kwargs)

    def get_org_principals(self, org, **kwargs):
        path = '/organizations/%s/principals'%(org,)
        return self.get_path(path, **kwargs)

    def get_org_required_recipe(self, org, **kwargs):
        path = '/organizations/%s/required_recipe'%(org,)
        return self.get_path(path, **kwargs)

    def list_org_roles(self, org, **kwargs):
        path = '/organizations/%s/roles'%(org,)
        return self.get_path(path, **kwargs)
    
    def create_org_role(self, org, name, default_attributes={}, env_run_lists={}, run_list=[], override_attributes={}, description='', **kwargs):
        path = '/organizations/%s/roles'%(org,)
        paras = dict()
        paras["name"] = name
        paras["default_attributes"] = default_attributes
        paras["env_run_lists"] = env_run_lists
        paras["run_list"] = run_list
        paras["override_attributes"] = override_attributes
        paras["description"] = description
        return self.create_path(path, paras, **kwargs)

    def delete_org_role(self, org, role, **kwargs):
        path = '/organizations/%s/roles/%s'%(org,role,)
        return self.delete_path(path, **kwargs)

    def get_org_role(self, org, role, **kwargs):
        path = '/organizations/%s/roles/%s'%(org,role,)
        return self.get_path(path, **kwargs)

    def update_org_role(self, org, role, **kwargs):
        path = '/organizations/%s/roles/%s'%(org,role,)
        return self.update_path(path, ['name', 'default_attributes', 'description', 'env_run_lists', 'run_list', 'override_attributes'], **kwargs)

    def list_org_role_environments(self, org, role, **kwargs):
        path = '/organizations/%s/roles/%s/environments'%(org,role,)
        return self.get_path(path, **kwargs)
    
    def get_org_role_environment(self, org, role, environment, **kwargs):
        path = '/organizations/%s/roles/%s/environments/%s'%(org,role,environment,)
        return self.get_path(path, **kwargs)

    def list_org_users(self, org, **kwargs):
        path = '/organizations/%s/users'%(org,)
        return self.get_path(path, **kwargs)
    

    def create_org_user(self, org, user, **kwargs):
        path = '/organizations/%s/users'%(org,)
        paras = dict()
        paras["user"] = user
        return self.create_path(path, paras, **kwargs)

    def get_org_user(self, org, user, **kwargs):
        path = '/organizations/%s/users/%s'%(org,user,)
        return self.get_path(path, **kwargs)

    def delete_org_user(self, org, user, **kwargs):
        path = '/organizations/%s/users/%s'%(org,user,)
        return self.delete_path(path, **kwargs)

    def list_user_keys(self, user, **kwargs):
        path = '/users/%s/keys'%(user,)
        return self.get_path(path, **kwargs)
    
    def create_user_key(self, user, name, public_key=None, expiration_date='infinity', **kwargs):
        path = '/users/%s/keys'%(user,)
        paras = dict()
        paras["user"] = user
        paras["name"] = name
        paras["expiration_date"] = expiration_date
        paras["create_key"] = (public_key is None)
        if public_key is not None:
            paras["public_key"] = public_key
        return self.create_path(path, paras, **kwargs)

    def get_user_key(self, user, key, **kwargs):
        path = '/users/%s/keys/%s'%(user,key,)
        return self.get_path(path, **kwargs)

    def delete_user_key(self, user, key, **kwargs):
        path = '/users/%s/keys/%s'%(user,key,)
        return self.delete_path(path, **kwargs)

    def update_user_key(self, user, key, **kwargs):
        path = '/users/%s/keys/%s'%(user,key,)
        return self.update_path(path, ['name', 'public_key', 'expiration_date'], **kwargs)

    def list_org_client_keys(self, org, client, **kwargs):
        path = '/organizations/%s/clients/%s/keys'%(org,client,)
        return self.get_path(path, **kwargs)
    
    def create_org_client_key(self, org, client, name, public_key=None, expiration_date='infinity', **kwargs):
        path = '/organizations/%s/clients/%s/keys'%(org,client,)
        paras = dict()
        paras["name"] = name
        paras["create_key"] = (public_key is None)
        paras["expiration_date"] = expiration_date
        if public_key:
            paras["public_key"] = public_key
        return self.create_path(path, paras, **kwargs)

    def get_org_client_key(self, org, client, key, **kwargs):
        path = '/organizations/%s/clients/%s/keys/%s'%(org,client,key,)
        return self.get_path(path, **kwargs)

    def delete_org_client_key(self, org, client, key, **kwargs):
        path = '/organizations/%s/clients/%s/keys/%s'%(org,client,key,)
        return self.delete_path(path, **kwargs)

    def update_org_client_key(self, org, client, key, **kwargs):
        path = '/organizations/%s/clients/%s/keys/%s'%(org,client,key,)
        return self.update_path(path, ['name', 'public_key', 'expiration_date'], **kwargs)
    
    def get_path(self, path, cached=True, cache=None, **kwargs):
        if cache is None:
            cache = self._cache
        if not cached and path in self._cached:
            del self._cached[path]
        resp = self.get(path, **kwargs)
        data = None
        if resp.status_code != 200:
            raise GetFailed(path, resp.status_code, resp.text)
        else:
            data = resp.json()
        if cache:
            self._cached[path] = data
        return data

    def create_path(self, path, json, **kwargs):
        resp = self.post(path, json=json, **kwargs)
        if resp.status_code != 201:
            raise CreateFailed(json, path, resp.status_code, resp.text)
        return resp.json()

    def update_path(self, path, items, **kwargs):
        params = dict()
        if not kwargs.get('replace', False):
            params = self.get_path(path, cached=False)
        if 'replace' in kwargs:
            del kwargs['replace']
        valid = False
        for item in items:
            if item in kwargs:
                params[item] = kwargs[item]
                del kwargs[item]
                valid = True
        if not valid:
            raise UpdateInvalid(path, items)
        resp = self.put(path, json=params, **kwargs)
        if resp.status_code not in (200,201):
            raise UpdateFailed(params, path, resp.status_code, resp.text)
        if path in self._cached:
            del self._cached[path]
        return resp.json()
    
    def delete_path(self, path, **kwargs):
        resp = self.delete(path, **kwargs)
        if resp.status_code != 200:
            raise DeleteFailed(path, resp.status_code, resp.text)
        if path in self._cached:
            del self._cached[path]
        return resp.json()

    def head_path(self, path, **kwargs):
        resp = self.head(path, **kwargs)
        return resp.status_code == 200
    
    # note that url is used for path within the org in this implementation
    def request(self, method, url, data=None, json=None, headers=None, verify=None, **kwargs):
        url = urljoin(f"https://{self._server}:{self._port}", url)
        urlobj = urlparse(url)
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        body = (data or '') + (libjson.dumps(json) if json else '')
        hashbody = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode()
        authheaders = self._headers.copy()
        authheaders.update({
            'X-Ops-Timestamp': now,
            'X-Ops-Content-Hash': hashbody,
            'Path': urlobj.path
        })
        canon = self._canon.copy()
        canon.update({
            'Method': method.upper(),
            'Path': urlobj.path,
            'X-Ops-Content-Hash': hashbody,
            'X-Ops-Timestamp': now
        })
        canonstr = '\n'.join(f'{key}:{value}' for key, value in canon.items())
        sign = base64.b64encode(self._key.sign(canonstr.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())).decode()
        chunks = [sign[i:i+60] for i in range(0, len(sign), 60)]
        authheaders.update({f'X-Ops-Authorization-{i+1}': s for i,s in enumerate(chunks)})
        authheaders.update(headers or dict())
        if verify is None:
            verify = self._verify
        return super().request(method, url, data=data, headers=authheaders, json=json, verify=verify, **kwargs)


