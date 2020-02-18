#!/usr/bin/env python3

PROJECT = 'sshame'

VERSION = '0.9'

from setuptools import setup, find_packages

try:
    long_description = open('README.md', 'rt').read()
except IOError:
    long_description = ''

setup(
    name=PROJECT,
    version=VERSION,

    description='SSH public key brute force tool',
    long_description=long_description,
    long_description_content_type="text/markdown",

    author='Hynek Petrak',
    author_email='hynek.petrak@gmail.com',

    url='https://github.com/hynek.petrak/sshame',
    download_url='https://github.com/hynek.petrak/sshame/tarball/master',

    classifiers=['Development Status :: 4 - Beta',
                 'License :: OSI Approved :: MIT License',
                 'Programming Language :: Python :: 3 :: Only',
                 'Intended Audience :: Other Audience',
                 'Environment :: Console',
                 'Operating System :: OS Independent',
                 'Topic :: Security',
                 ],

    platforms=['Any'],

    scripts=[],

    provides=[],
    install_requires=[
        'asyncssh >= 1.15.1',
        'cmd2 >= 0.10.0',
        'colorama',
        'sqlalchemy',
        'scapy',
        'tabulate',
        'pyyaml',
        'pysubnettree'], #TODO: fill

    namespace_packages=[],
    packages=find_packages(),
    include_package_data=True,

    entry_points={
        'console_scripts': [
            'sshame = sshame.main:main'
        ],
        'sshame': [
        #    'load keys = sshame.keys:LoadKeys',
        #    'simple = sshame.simple:Simple',
        #    'two_part = sshame.simple:Simple',
        #    'error = sshame.simple:Error',
        #    'list files = sshame.list:Files',
        #    'files = sshame.list:Files',
        #    'file = sshame.show:File',
        #    'show file = sshame.show:File',
        #    'unicode = sshame.encoding:Encoding',
        #    'hooked = sshame.hook:Hooked',
        ],
        'sshame.hooked': [
        #    'sample-hook = sshame.hook:Hook',
        ],
    },

    zip_safe=False,
)
