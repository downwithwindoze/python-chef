# python-chef
A python interface to the chef server api

Designed specifically for chef version >= 12.4 using authentication protocol 1.3.  For older chef versions see https://github.com/coderanger/pychef.

Currently only implements authentication by wrapping a [requests](https://docs.python-requests.org/en/master/) session with an "API" object.
More functionality to follow.

It helps to have a chef test server to run against.
[this docker image](https://hub.docker.com/r/cbuisson/chef-server) works for me

```bash
docker pull cbuisson/chef-server
docker run --name test-chef-server -d -p 4443:443 cbuisson/chef-server
docker logs -f test-chef-server   # (wait for server to bootstrap then ^C)
docker exec -it test-chef-server /bin/bash
> chef-server-ctl org-create testorg TestOrg
> chef-server-ctl user-create test Test User test@localhost.localdomain password
> chef-server-ctl org-user-add testorg test --admin
> exit
```
Copy the private key from the `user-create` to say `test.pem`.

Example usage based on above docker test server:

```python
import chef
import json

USERNAME = "test"
CHEF_SERVER = "localhost"
ORG = "testorg"
PORT = 4443
KEY = open("test.pem").read()

api = chef.API(USERNAME, KEY)

resp = api.get(f"https://{CHEF_SERVER}:{PORT}/organizations/{ORG}/search/node", verify=False)

print(resp.status_code)
if resp.status_code == 200:
    print(json.dumps(resp.json(), indent=2))
else:
    print(resp.text)
```
