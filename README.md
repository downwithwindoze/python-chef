# python-chef
A python interface to the chef server api

Designed specifically for chef version >= 12.4 using authentication protocol 1.3.  For older chef versions see https://github.com/coderanger/pychef.

Currently only implements authentication by wrapping a [requests](https://docs.python-requests.org/en/master/) session with an "API" object.
More functionality to follow.

Example:

```
import chef
import json

USERNAME = "my_name"
CHEF_SERVER = "chef.mydomain.com"
ORG = "my_orgname"
KEY = open(os.path.expanduser("~/.chef/private_key.pem")).read()

api = chef.API(USERNAME, KEY)

resp = api.get(f"https://CHEF_SERVER/organizations/ORG/search/node")
print(resp.status_code)
if resp.status_code == 200:
   print(json.dumps(resp.json(), indent=2))
```
