# -*- coding: utf-8 -*-
""" pydebsign.debsign
debsign process as follows;
---
1. Signing .dsc file with GPG key.
2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
3. Rewrite of above values at .changes.
4. Siging .changes file with GPG key.
---
optional:
   How to verify signed files: `dput -o .changes` command.
"""
import re
import os.path
import hashlib
import subprocess
import shlex
import gnupg
import deb822


class Debsign(object):
    """ debsign class """
    def __init__(self, changes_path, passphrase=None):
        self.changes_path = changes_path
        self.dsc_path = ''
        if passphrase:
            self.passphrase = passphrase
            use_agent = False
        else:
            use_agent = True
        self.gpg = gnupg.GPG(use_agent=use_agent)

    def is_signed(self, file_path):
        """ check file is signed with GPG key,
        Returns: `bool` True is signed, False is unsigned.
        :param file_path: expecting .dsc file or .changes file.
        """
        with open(file_path, 'rb') as fileobj:
            if self.gpg.verify(fileobj.read()).status is None:
                return False
            else:
                return True

    def parse_changes(self):
        """ parse .changes and retrieve efile size and file name list.
        Returns: file List of list with file size and checksums.
        """
        with open(self.changes_path, 'rb') as fileobj:
            changes = deb822.Changes(fileobj)
        return [changes['Files'],
                changes['Checksums-Sha1'],
                changes['Checksums-Sha256']]

    def retrieve_dsc_path(self, file_list):
        """ retrieve dsc file path from file list.
        Returns: dsc file path
        :param file_list: expecting file list as return of parse_changes().
        """
        pattern = re.compile(r'.dsc\Z')
        return [_file.get('name') for _file in file_list
                if pattern.search(_file.get('name'))][0]

    def signing_changes(self):
        """ sign .changes file with GPG key,
        invoke siging_dsc() when not yet to sign .dsc file.
        ---
        Returns: `bool` True is successful, False is failure.
        """
        with open(self.changes_path, 'rb') as fileobj:
            data = fileobj.read()
        signed_data = self.gpg.sign(data, passphrase=self.passphrase)
        with open(self.changes_path, 'w') as fileobj:
            fileobj.write(signed_data.data)
        return True

    def signing_dsc(self):
        """ sign .dscs file with GPG key,
        invoke rewrite_changes() when this method is succeeded.
        ---
        Returns: `bool` True is successful, False is failure.
        """
        with open(self.dsc_path, 'rb') as fileobj:
            data = fileobj.read()
        signed_data = self.gpg.sign(data, passphrase=self.passphrase)
        with open(self.dsc_path, 'w') as fileobj:
            fileobj.write(signed_data.data)
        return True

    def rewrite_changes(self, filesize, checksums):
        """ rewrite file size and hash fingerprint of .dsc file.
        invoke retrieve_checksums() and retreive_filesize().
        this method is invoked by siging_dsc().
        ---
        Returns: status code
        :param filesize: expecting `int` .dsc file size
        :param checksums: expecting `tuple` of md5, sha1, sha256 hexdigest
        """
        pass

    def retrieve_checksums(self, file_path):
        """ retrieve md5, sha1, sha256 checksums.
        Returns: tupul of md5, sha1, sha256 hexdigest.
        :param file_path: expecting .dsc file path.
        """
        with open(file_path, 'rb') as fileobj:
            data = fileobj.read()
        return (hashlib.md5(data).hexdigest(),
                hashlib.sha1(data).hexdigest(),
                hashlib.sha256(data).hexdigest())

    def verify_filesize(self, dsc_filesize, file_list):
        """ verify file size with file list retrieved from changes.
        Returns: `bool` True is valid, False is invalid.
        :param dsc_filesize: `int` file size of .dsc
        :param file_list: expecting file list as return of parse_changes().
        """
        pattern = re.compile(r'.dsc\Z')
        return dsc_filesize == [int(_file.get('size')) for _file in file_list
                                if pattern.search(_file.get('name'))][0]

    def verify_checksums(self, dsc_checksums, file_list):
        """ verify checksums (and size) with file list retrieved from changes.
        Returns: `bool` True is valid, False is invalid.
        :param file_list: expecting file list as return of parse_changes().
        """
        pattern = re.compile(r'.dsc\Z')
        return dsc_checksums[0] == [_file.get('md5sum')
                                    for _file in file_list[0]
                                    if pattern.search(_file.get('name'))][0]

    def verify_signature(self, file_path):
        """ verify signature of file with GPG key.
        Returns: `bool` True is valid, False is invalid
        :param file_path: expecting .dsc file path or .changes file path
        """
        with open(file_path) as fileobj:
            return self.gpg.verify(fileobj.read()).valid

    def verify_with_dput(self):
        """ verify .changes and .dsc files with `dput` command,
        and automatically inclide a lintian run any moure.
        Returns: `bool` True is valid, False is invalid.
        """
        command = 'dput -ol %s' % self.changes_path
        args = shlex.split(command)
        return subprocess.call(args)

    def verification(self, dsc_filesize, dsc_checksums, file_list):
        """ verification of signed files.
        Returns: `bool` True is valid, False is invalid.
        :param dsc_filesize: `int` file size retreived from .changes
        :param dsc_checksums: `tuple` .dsc checksums retrieved from .changes
        :param file_list: `list` file list retrieve .changes
        """
        self.verify_filesize(dsc_filesize, file_list)
        self.verify_checksums(dsc_checksums, file_list)
        self.verify_signature(self.dsc_path)
        self.verify_signature(self.changes_path)
        self.verify_with_dput()
        return True


def debsign_process(changes_path, passphrase):
    """ debsign process sequence """
    dbsg = Debsign(changes_path, passphrase)

    file_list = dbsg.parse_changes()
    dbsg.dsc_path = dbsg.retrieve_dsc_path(file_list[0])

    if dbsg.is_signed(changes_path):
        dsc_checksums = dbsg.retrieve_checksums(dbsg.dsc_path)
        dsc_filesize = os.path.getsize(dbsg.dsc_path)
        dbsg.verification(dsc_filesize, dsc_checksums, file_list)

    if dbsg.is_signed(dbsg.dsc_path) is False:
        dbsg.signing_dsc()
        dsc_checksums = dbsg.retrieve_checksums(dbsg.dsc_path)
        dsc_filesize = os.path.getsize(dbsg.dsc_path)
        dbsg.rewrite_changes(dsc_filesize, dsc_checksums)

    dbsg.signing_changes()
    signed_file_list = dbsg.parse_changes()

    dbsg.verification(dsc_filesize, dsc_checksums, signed_file_list)
    return True
