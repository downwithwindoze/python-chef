import sys
if sys.version_info < (3,6,0):
    raise Exception('Minimum Python version is 3.6.0')

import collections
import json
import os

init = json.load(open(os.path.join(os.path.dirname(__file__), "init.json")))

version_info = collections.namedtuple('version_info', ['major', 'minor', 'micro'])(*init['version'].split('.')[:3])
__version__ = '.'.join([str(v) for v in version_info])

author_info = collections.namedtuple('auth_info', ['name', 'email'])(init['author'], init['email'])
__author__ = f'{author_info.name} <{author_info.email}>'

from .api import API, OperationFailed, GetFailed, DeleteFailed, ChangeFailed, CreateFailed, UpdateFailed, GetInvalid, UpdateInvalid

from .server import Server
from .user import User
from .client import Client

