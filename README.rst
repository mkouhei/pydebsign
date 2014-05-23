===============================================
 pydebsign is a yet another library of debsign
===============================================

Motivation
==========

`debsign` is a command of devscripts that sign a Debian .changes and .dsc file pare using GPG,
the command cannot use in environment witout TTY, for example invokeking by CI.

I had tried to use debsign from `subprocess` module of Python as follow,
but entering passphrase prompt is always returned.
It was the same in the case of using gnupg-agent and keyring.::

  >>> import subprocess
  >>> import shlex
  >>> command = '/usr/bin/debsign -k %s %s' % (`keyid`, `.changes`)'
  >>> process = subprocess.Popen(shlex.split(command),
  ...                            stdin=subprocess.PIPE,
  ...                            stdout=subprocess.PIPE,
  ...                            stderr=subprocess.PIPE)
  >>> stdout, stderr = process.communicate('%s\n%s\n') % (`passphrase`, `passphrase`)

So, I decided to make a python library to do the same behavior debsign.


Goal
====

* It is enable to sign `.changes` and `.dsc` files with GPG without the input of interactive passphrase.
* It can also be used by a user can not login shell on the CI, such as Jenkins.
