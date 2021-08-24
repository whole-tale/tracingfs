tracingfs
#########

|GitHub Project| |nsf-badge|

Description
===========

A naive passthrough fuse filesystem (based on an original `example <https://www.stavros.io/posts/python-fuse-filesystem/>`_) with additional capability of logging operations remotely to logstash

Installation
============

.. code-block:: shell

    pip install -r requirements.txt

Usage
=====

.. code-block:: shell

    python passthrough.py $HOME /tmp/home
    ./run_stash.sh  # starts logstash container, may take a while

Perform some file operations in `/tmp/home` in a separate terminal.

Cleanup
=======

.. code-block:: shell
  
    fusermount -u /tmp/home && rmdir /tmp/home
    docker stop -t 0 logstash  # or CTRL-C in shell runningn logstash container


Acknowledgements
================

This material is based upon work supported by the National Science Foundation under Grant No. OAC-1541450.

.. |GitHub Project| image:: https://img.shields.io/badge/GitHub--blue?style=social&logo=GitHub
   :target: https://github.com/whole-tale/tracingfs

.. |nsf-badge| image:: https://img.shields.io/badge/NSF-154150-blue.svg
    :target: https://www.nsf.gov/awardsearch/showAward?AWD_ID=1541450
    :alt: NSF Grant Badge

