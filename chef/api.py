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
        
init = libjson.load(open(os.path.join(os.path.dirname(__file__), "init.json")))

class API(requests.Session):
    def __init__(self, server, org, user, key, port=443, password=None, verify=True, cache=True):
        super().__init__()
        self._key = serialization.load_pem_private_key(key.encode('utf-8'), password=password)
        self._user = user
        self._verify = verify
        self._server = server
        self._port = port
        self._org = org
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

    @property
    def organization(self):
        return self._organization

    @organization.setter
    def organization(self, org):
        self._organization = org

        
    def get_license(self, **kwargs):
        return self.get_path('/license', **kwargs)

    @property
    def license(self):
        return self.get_license(cache=False, cached=False)

    def get_stats(self, **kwargs):
        return self.get_path('/_stats', **kwargs)

    @property
    def stats(self):
        return self.get_stats(cache=False, cached=False)

    def get_status(self, **kwargs):
        return self.get_path('/_status', **kwargs)

    @property
    def status(self):
        return self.get_status(cache=False, cached=False)
    
    def get_organizations(self, **kwargs):
        return self.get_path('/organizations', **kwargs)

    @property
    def organizations(self):
        return self.get_organizations(cached=True)

    def get_organization(self, name, **kwargs):
        return self.get_path(f'/organizations/{name}', cached=True)
    
    def create_organization(self, name, full_name, **kwargs):
        return self.create_path('/organizations', dict(name=name, full_name=full_name), **kwargs)

    def update_organization(self, **kwargs):
        return self.update_path(f'/organizations/{name}', ['name', 'display_name'], **kwargs)
    
    def delete_organization(self, name, **kwargs):
        return self.delete_path(f'/organizations/{name}')
    
    def get_search_indexes(self, **kwargs):
        return list(self.get_path('search', **kwargs).keys())
    
    @property
    def search_indexes(self):
        return self.get_search_indexes(cached=True)

    # see https://docs.chef.io/workstation/knife_search/#query-syntax
    def search(self, index, start=0, rows=None, query='*', **kwargs):
        if index not in self.search_indexes:
            raise GetInvalid('invalid search index')
        params = dict(start=start, q=query)
        if rows is not None:
            params['rows'] = rows
        return self.get_path(f'search/{index}', params=params, **kwargs)['rows']

    def get_cookbooks(self, **kwargs):
        return self.get_path('universe', **kwargs)

    @property
    def cookbooks(self):
        return self.get_cookbooks(cached=True)

    def get_users(self, **kwargs):
        return self.get_path('users', **kwargs)

    @property
    def users(self):
        return self.get_users(cached=True)

    def get_user(self, user, **kwargs):
        return self.get_path(f'/users/{user}', **kwargs)

    def create_user(self, username, first_name, last_name, email, password, middle_name=None, display_name=None, public_key=None, **kwargs):
        if not display_name:
            display_name = f"{first_name} {middle_name+' ' if middle_name else ''}{last_name}"
        params = dict(username=username, first_name=first_name, last_name=last_name, email=email, password=password, create_key=not public_key, display_name=display_name)
        if middle_name:
            params['middle_name'] = middle_name
        if public_key:
            params['public_key'] = public_key
        return self.create_path('/users', params, **kwargs)

    def update_user(self, user, **kwargs):
        return self.update_path(f'/users/{user}', ['username', 'display_name', 'email', 'first_name', 'last_name', 'middle_name'], **kwargs)
        
    def delete_user(self, user, **kwargs):
        return self.delete_path(f'/users/{user}')

    def get_user_keys(self, user, **kwargs):
        return self.get_path(f'/users/{user}/keys', **kwargs)

    def add_user_key(self, user, name, public_key, expiration_date='infinity', **kwargs):
        return self.create_path(f'/users/{user}/keys', params=dict(name=name, public_key=public_key, expiration_date=expiration_date), **kwargs)

    def delete_user_key(self, user, name, **kwargs):
        return self.delete_path(f'/users/{user}/keys/{name}', **kwargs)

    def get_user_key(self, user, name, **kwargs):
        return self.get_path(f'/users/{user}/keys/{name}', **kwargs)

    def update_user_key(self, user, name, **kwargs):
        return self.update_path(f'/users/{user}/keys/{name}', ['name', 'public_key', 'expiration_date'], **kwargs)


    def get_association_requests(self, **kwargs):
        return self.get_path('assoociation_requests', **kwargs)

    @property
    def association_requests(self, **kwargs):
        return self.get_association_requests(cached=True)
    
    def delete_association_request(self, id, **kwargs):
        return self.delete_path(f'association_requests/{id}', **kwargs)

    def create_association_request(self, user, **kwargs):
        return self.create_path('association_requests', dict(user=user), **kwargs)

    def get_clients(self, **kwargs):
        return self.get_path('clients', **kwargs)

    @property
    def clients(self):
        return self.get_clients(cached=True)

    def create_client(self, client, name, clientname=None, validator=True, create_key=True, **kwargs):
        return self.create_path('clients', dict(name=name, clientname=(clientname or name), create_key=create_key, validator=validator), **kwargs)

    def get_client(self, client, **kwargs):
        return self.get_path(f'clients/{client}', **kwargs)

    def delete_client(self, client, **kwargs):
        return self.delete_path(f'clients/{client}', **kwargs)

    def update_client(self, client, **kwargs):
        return self.update_path(f'clients/{client}', ['name', 'validator'], **kwargs)

    def get_client_keys(self, client, **kwargs):
        return self.get_path(f'clients/{client}/keys', **kwargs)

    def add_client_key(self, client, name, public_key, expiration_date='infinity', **kwargs):
        return self.create_path(f'clients/{client}/keys', params=dict(name=name, public_key=public_key, expiration_date=expiration_date), **kwargs)

    def delete_client_key(self, client, name, **kwargs):
        return self.delete_path(f'clients/{client}/keys/{name}', **kwargs)

    def get_client_key(self, client, name, **kwargs):
        return self.get_path(f'clients/{client}/keys/{name}', **kwargs)

    def update_client_key(self, client, name, **kwargs):
        return self.update_path(f'clients/{client}/keys/{name}', ['name', 'public_key', 'expiration_date'], **kwargs)
    

    
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
    
    # note that url is used for path within the org in this implementation
    def request(self, method, url, data=None, json=None, headers=None, verify=None, **vargs):
        url = urljoin(f"https://{self._server}:{self._port}", url if url.startswith('/') else f"/organizations/{self._org}/{url}")
        print(url)
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
        return super().request(method, url, data=data, headers=authheaders, json=json, verify=verify, **vargs)

