#!/usr/bin/env python
"""
Installs the ofsolver tool and library
"""

import sys
import os
from os import path
import stat
from platform import architecture
import tarfile
try:
    from urllib import urlretrieve
except ImportError:
    from urllib.request import urlretrieve
import distutils.cmd
from setuptools import setup

LIB_NAME = "ofsolver"
MINISAT_ZMQ_URL = "https://github.com/wandsdn/minisat-zmq/releases/download/v0.1/minisat-zmq-amd64"
MINISAT_ZMQ_BIN = path.join(LIB_NAME, "minisat-zmq")
MUSER2_URL = "https://wand.net.nz/~rsanger/files/muser2-20120821.tgz"
MUSER2_BIN = path.join(LIB_NAME, "muser2-20120821", "linux_2.6_x86-64", "muser2-static")
MUSER2_TAR = path.join(LIB_NAME, "muser2-20120821.tgz")

with open('README.md') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()


def download_minisatzmq():
    """ Download a standalone minisat-zmq binary """
    if architecture() == ("64bit", "ELF"):
        # If not already downloaded
        if not have_minisatzmq():
            print("Downloading minisat-zmq")
            urlretrieve(MINISAT_ZMQ_URL, MINISAT_ZMQ_BIN)
            stat_ = os.stat(MINISAT_ZMQ_BIN)
            os.chmod(MINISAT_ZMQ_BIN,
                     stat_.st_mode | stat.S_IXUSR | stat.S_IXOTH | stat.S_IXGRP)
        else:
            print("Found existing copy of minisat-zmq")
    else:
        print("Warning: unable to automatically download minisat-zmq for your system\n"
              "See https://github.com/wandsdn/minisat-zmq/ for how build\n"
              "Then either place in the ./" + LIB_NAME + "directory or install to the system path")


def download_muser2():
    """ Download a standalone muser2 binary """
    if not have_muser2():
        print("Downloading muser2")
        urlretrieve(MUSER2_URL, MUSER2_TAR)
        with tarfile.open(MUSER2_TAR, 'r:gz') as tar:
            tar.extractall(path=LIB_NAME)
    else:
        print("Found existing copy of muser2")


def have_minisatzmq():
    """ Check for local minisat-zmq binary """
    return path.exists(MINISAT_ZMQ_BIN)


def have_muser2():
    """ Check for local muser2 binary """
    return path.exists(LIB_NAME + "/muser2-20120821/linux_2.6_x86-64/muser2-static")


class DownloadCommand(distutils.cmd.Command):
    """ Download local copies of required binaries """
    no_minisat_zmq = False
    no_muser2 = False
    description = 'download minisat-zmq and muser2 binaries locally'
    user_options = [('no-minisat-zmq', None, "don't download minisat-zmq"),
                    ('no-muser2', None, "don't download muser2")]

    def initialize_options(self): pass

    def finalize_options(self): pass

    def run(self):
        if not self.no_minisat_zmq:
            download_minisatzmq()
        if not self.no_muser2:
            download_muser2()

if "download" not in sys.argv:
    if not have_minisatzmq():
        print(
            "Note: minisat-zmq not found locally, use ./setup.py download\n"
            "This can be ignored if you have installed minisat-zmq to system path\n"
            "See https://github.com/wandsdn/minisat-zmq for details.\n")
    if not have_muser2():
        print(
            "Note: muser2 not found locally, use ./setup.py download.\n"
            "This can be ignored if you have installed muser2 to system path.\n"
            "Without muser2 ofsolver --print-failure will not work.\n")

setup(
    name='ofsolver',
    version='1.0.0',
    description=('A python tool to fit OpenFlow rulesets to new pipelines.'),
    long_description=README,
    author='Richard Sanger',
    author_email='rsanger@wand.net.nz',
    url='https://github.com/wandsdn/ofsolver',
    license=LICENSE,
    packages=[LIB_NAME, LIB_NAME + ".util"],
    include_package_data=True,
    cmdclass={"download": DownloadCommand},
    install_requires=[
        "ofequivalence",
        "ttp-tools",
        "ryu",
        "tqdm",
        "six",
        "parameterized",
        "pyzmq",
        "deap",
        "satispy"
        ],
    entry_points={
        "console_scripts": [
            "ofsolver=ofsolver.ofsolver:main"
            ]
        }
    )
