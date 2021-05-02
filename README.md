# python-chef
A python interface to the chef server api

Designed specifically for chef version >= 12.4 using authentication protocol 1.3.  For older chef versions see https://github.com/coderanger/pychef.

Wraps a [requests](https://docs.python-requests.org/en/master/) session with an "API" object, so expect standard requests session behaviour.
Overriding the `request` method of the session deals with the authentication layer and then functions get, create, update, delete etc functions are added which ultimately call that method.

Feedback is welcome.

It helps to have a chef test server to run against.
[this docker image](https://hub.docker.com/r/cbuisson/chef-server) works for me

```bash
docker pull cbuisson/chef-server
docker run --name test-chef-server -d -p 4443:443 cbuisson/chef-server
docker logs -f test-chef-server   # (wait for server to bootstrap then ^C)
docker exec -it test-chef-server /bin/bash
> chef-server-ctl org-create testorg TestOrg
> chef-server-ctl add-user-key pivotal --key-name admin
> exit
```
Copy the private key from the `user-create` to say `test.pem`.

See `test.py` for example usage based on above docker test server.
