# setup.py

from setuptools import setup

with open("README", 'r') as f:
    long_description = f.read()

setup(
   name='sftpy',
   version='1.0.5',
   description='A python SFTP module that supports mget-style filename globby patterns',
   license="LGPLv3",
   long_description='Have you ever longed for mget in a python SFTP module? Leave those kludgy workarounds behind.',
   author='Phenicle',
   author_email='pheniclebeefheart@gmail.com',
   url="https://github.com/phenicle/sftpy",
   packages=['sftpy',],  #same as name
   install_requires=['pexpect', 'cfgpy'], #external packages as dependencies
)
