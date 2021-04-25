import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
from datetime import datetime, timezone
import hashlib
import os
import json
import base64

init = json.load(open(os.path.join(os.path.dirname(__file__), "init.json")))

class API(requests.Session):
    def __init__(self, user, key, password=None):
        super().__init__()
        self._key = serialization.load_pem_private_key(key.encode('utf-8'), password=password)
        self._user = user
        
    def request(self, method, url, data=None, json=None, headers=None, **vargs):
        urlobj = urlparse(url)
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        body = (data or '') + (json.dumps(json) if json else '')
        hashbody = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode()
        authheaders = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
            'X-Ops-Server-API-Version': '1',
            'X-Ops-UserId': self._user,
            'X-Ops-Sign': 'algorithm=sha256;version=1.3;',
            'X-Ops-Timestamp': now,
            'X-Ops-Content-Hash': hashbody,
            'X-Chef-Version': '14.0.0',
            'Host': urlobj.netloc,
            'Path': urlobj.path,
            'User-Agent': f"python-chef {init['version']}"
        }

        canon={
            'Method': 'GET',
            'Path': urlobj.path,
            'X-Ops-Content-Hash': hashbody,
            'X-Ops-Sign': 'version=1.3',
            'X-Ops-Timestamp': now,
            'X-Ops-UserId': self._user,
            'X-Ops-Server-API-Version': '1'
        }
        canonstr = '\n'.join(f'{key}:{value}' for key, value in canon.items())
        sign = base64.b64encode(self._key.sign(canonstr.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())).decode()
        chunks = [sign[i:i+60] for i in range(0, len(sign), 60)]
        authheaders.update({f'X-Ops-Authorization-{i+1}': s for i,s in enumerate(chunks)})

        authheaders.update(headers or dict())

        return super().request(method, url, data=data, headers=authheaders, json=json, **vargs)
