# -*- coding: utf-8 -*-
""" setup.py """
import os.path
import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand
import subprocess
import shlex
import multiprocessing


class Tox(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import tox
        errno = tox.cmdline(self.test_args)
        sys.exit(errno)


classifiers = [
    "Development Status :: 3 - Alpha",
    "License :: OSI Approved :: ISC License (ISCL)",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 2.6",
    "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.2",
    "Programming Language :: Python :: 3.3",
    "Programming Language :: Python :: 3.4",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Topic :: System",
    "Topic :: System :: Archiving",
    "Topic :: System :: Archiving :: Packaging",
    "Topic :: System :: Software Distribution",
]


long_description = (
    open("README.rst").read() +
    open(os.path.join("docs", "HISTORY.rst")).read() +
    open(os.path.join("docs", "TODO.rst")).read())

requires = ['setuptools',
            'python_gnupg',
            'python_debian',
            'chardet']


def check_debian_packages():
    command = 'dpkg -l gnupg dput lintian'
    with open(os.devnull, 'w') as devnull:
        if subprocess.call(shlex.split(command), stdout=devnull) == 0:
            return True
        else:
            sys.exit(1)
check_debian_packages()

setup(name='pydebsign',
      version='0.1.1',
      description='yet another library of debsign',
      long_description=long_description,
      author='Kouhei Maeda',
      author_email='mkouhei@palmtb.net',
      url='https://github.com/mkouhei/pydebsign',
      license='ISC License',
      classifiers=classifiers,
      packages=['pydebsign'],
      data_files=[],
      install_requires=requires,
      include_package_data=True,
      tests_require=['tox'],
      cmdclass={'test': Tox},)
