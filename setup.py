#!/usr/bin/env python

import setuptools
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

init = json.load(open(os.path.join(os.path.dirname(__file__), "chef", "init.json")))

setuptools.setup(
    name = "python-chef",
    version = init['version'],
    author_email = init['email'],
    packages = ['chef'],
    zip_safe = True,
    requires = ['requests', 'cryptography'],
    package_data = dict(chef='init.json')
)
    
