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
        valid = False
        for item in items:
            if item in kwargs:
                params[item] = kwargs[item]
                del kwargs[item]
                valid = True
        if not valid:
            raise UpdateInvalid(path, items)
        resp = self.put(path, json=params, **kwargs)
        if resp.status_code != 201:
            raise UpdateFailed(json, path, resp.status_code, resp.text)
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



with open(os.path.splitext(__file__)[0]+'.json') as f:
    api = libjson.load(f)

def build_list_method(path, name, config):
    need_args = [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()][:-1]
    make_path = "'"+path+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
def API_method_list_{name}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
    return self.get_path(path, **kwargs)
setattr(API, 'list_{name}', API_method_list_{name})
    '''
    exec(code)
    
def build_single_get_method(path, name, config):
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()][:-1]
    make_path = "'"+path+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
def API_method_get_{name}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
    return self.get_path(path, **kwargs)
setattr(API, 'get_{name}', API_method_get_{name})
    '''
    exec(code)
    

def build_each_get_method(path, name, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()]
    if part:
        need_args.append(part)
    make_path = "'"+path+"/%s"+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
def API_method_get_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
    return self.get_path(path, **kwargs)
setattr(API, 'get_{name}{("_"+part) if part else ""}', API_method_get_{name}{("_"+part) if part else ""})
    '''
    exec(code)
    
def build_create_method(path, name, root, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in root.items()]
    if not part:
        need_args = need_args[:-1]
    make_path = "'"+path+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    require_args = [k for k,v in (config or dict()).items() if v=="require"]
    make_paras = ['paras = dict()']
    for arg in require_args:
        need_args.append(arg)
        make_paras.append(f'paras["{arg}"] = {arg}')
    opt_args = [(k,"'"+v+"'" if isinstance(v, str) else str(v)) for k,v in (config or dict()).items() if v!="require"]
    for k,v in opt_args:
        need_args.append(f'{k}={None if v[1]=="!" else v}')
        make_paras.append(f'paras["{k}"] = ' + (f"({k} or {v[2:-1]})" if v[1]=='!' else f"{k}"))
    make_paras = '\n'.join(['    '+p for p in make_paras])
    code = f'''
def API_method_create_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
{make_paras}
    return self.create_path(path, paras, **kwargs)
setattr(API, 'create_{name}{("_"+part) if part else ""}', API_method_create_{name}{("_"+part) if part else ""})
    '''
    exec(code)    

def build_update_method(path, name, root, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in root.items()]
    if part:
        need_args.append(part)
    make_path = "'"+path+"/%s"+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
def API_method_update_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
    return self.update_path(path, [{', '.join(["'"+c+"'" for c in config])}], **kwargs)
setattr(API, 'update_{name}{("_"+part) if part else ""}', API_method_update_{name}{("_"+part) if part else ""})
    '''
    exec(code)
   

def build_exists_method(path, name, config):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()]
    make_path = "'"+path+"/%s'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
def API_method_exists_{name}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
    return self.exists_path(path, **kwargs)
setattr(API, 'exists_{name}', API_method_exists_{name})
    '''
    exec(code)
    
def build_delete_method(path, name, config, part=None):
    name = name.rstrip('s')
    need_args =  [(v or dict()).get('alias', k).rstrip('s') for k,v in config.items()]
    if part:
        need_args.append(part)
    make_path = "'"+path+"/%s"+("/%s" if part else "")+"'" + (('%('+','.join(need_args)+',)') if need_args else '')
    code = f'''
def API_method_delete_{name}{("_"+part) if part else ""}(self{", " if need_args else ""}{", ".join(need_args)}, **kwargs):
    path = {make_path}
    return self.delete_path(path, **kwargs)
setattr(API, 'delete_{name}{("_"+part) if part else ""}', API_method_delete_{name}{("_"+part) if part else ""})
    '''
    exec(code)
    
    
def build_api_method(root, path, config):
    full_path = '/'+'/%s/'.join([k for k in root.keys()]+[path])
    stem = '_'.join([(v or dict()).get('alias', k).rstrip('s') for k,v in root.items()]+[(config or dict()).get('alias', path)])
    eroot = root.copy()
    eroot[path] = config
    for key, value in config.items():
        if key == 'get':
            build_single_get_method(full_path, stem, eroot)
        elif key == 'list':
            build_list_method(full_path, stem, eroot)
        elif key == 'create':
            build_create_method(full_path, stem, eroot, value)
        elif key == 'each':
            for ekey, evalue in value.items():
                if ekey == 'get':
                    build_each_get_method(full_path, stem, eroot)
                elif ekey == 'update':
                    build_update_method(full_path, stem, eroot, evalue)
                elif ekey == 'exists':
                    build_exists_method(full_path, stem, eroot)
                elif ekey == 'delete':
                    build_delete_method(full_path, stem, eroot)
        elif key == 'parts':
            for pkey, pvalue in value.items():
                for ekey, evalue in pvalue.items():
                    if ekey == 'get':
                        build_each_get_method(full_path, stem, eroot, pkey)
                    elif ekey == 'delete':
                        build_delete_method(full_path, stem, eroot, pkey)
                    elif ekey == 'update':
                        build_update_method(full_path, stem, eroot, evalue, pkey)
                    elif ekey == 'create':
                        build_create_method(full_path, stem, eroot, evalue, pkey)
        elif key == 'contains':
            for ekey, evalue in value.items():
                build_api_method(eroot, ekey, evalue)
    
for path, config in api.items():
    build_api_method({}, path, config)


# support HEAD method for check exists

