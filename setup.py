from setuptools import Extension, setup, find_packages

import sys
import json
import os.path
sys.path.insert(0, os.path.abspath('.'))

with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

with open('minemeld.json') as f:
    _metadata = json.load(f)

_entry_points={}
if 'entry_points' in _metadata:
    for epgroup, epoints in _metadata['entry_points'].iteritems():
        _entry_points[epgroup] = ['{} = {}'.format(k, v) for k, v in epoints.iteritems()]

setup(
    name=_metadata['name'],
    version=_metadata['version'],
    author=_metadata['author'],
    author_email=_metadata['author_email'],
    description=_metadata['description'],
    classifiers=[
        'Framework :: MineMeld',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: Internet'
    ],
    packages=find_packages(),
    provides=find_packages(),
    install_requires=_requirements,
    package_data = {
        '': ['prototypes/*.yml']
    },
    entry_points=_entry_points
)
