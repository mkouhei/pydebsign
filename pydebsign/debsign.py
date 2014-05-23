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
import hashlib
import gnupg
import deb822


class Debsign(object):
    """ debsign class """
    def __init__(self):
        self.gpg = gnupg.GPG()

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

    def parse_changes(self, changes_path):
        """ parse .changes and retrieve efile size and file name list.
        Returns: file list with file size and checksums.
        :param changes_path: .changes file path
        """
        with open(changes_path, 'rb') as fileobj:
            changes = deb822.Changes(fileobj)
        return [_file for _file in changes['Files']]

    def retrieve_dsc_path(self, file_list):
        """ retrieve dsc file path from file list.
        Returns: dsc file path
        :param file_list: expecting file list as return of parse_changes().
        """
        pass

    def signing_changes(self, changes_path):
        """ sign .changes file with GPG key,
        invoke siging_dsc() when not yet to sign .dsc file.
        ---
        Returns: status code
        :param changes_path: .changes file path
        """
        pass

    def signing_dsc(self, dsc_path):
        """ sign .dscs file with GPG key,
        invoke rewrite_changes() when this method is succeeded.
        ---
        Returns: status code
        :param dsc_path: .dsc file path
        """
        pass

    def rewrite_changes(self, changes_path, filesize, checksums):
        """ rewrite file size and hash fingerprint of .dsc file.
        invoke retrieve_checksums() and retreive_filesize().
        this method is invoked by siging_dsc().
        ---
        Returns: status code
        :param changes_path: .changes file path
        :param filesize: expecting `int` .dsc file size
        :param checksums: expecting `tuple` of md5, sha1, sha256 hexdigest
        """
        pass

    def retrieve_checksums(self, file_path):
        """ retrieve md5, sha1, sha256 checksums.
        Returns: tupul of md5, sha1, sha256 hexdigest.
        :param file_path: expecting .dsc file path.
        """
        pass

    def retrieve_filesize(self, file_path):
        """ retrieve file size.
        Returns: `int` file size.
        :param file_path: expecting .dsc file path.
        """
        pass

    def verify_filesize(self, dsc_filesize, file_list):
        """ verify file size with file list retrieved from changes.
        Returns: `bool` True is valid, False is invalid.
        :param file_list: expecting file list as return of parse_changes().
        """
        pass

    def verify_checksums(self, dsc_checksums, file_list):
        """ verify checksums (and size) with file list retrieved from changes.
        Returns: `bool` True is valid, False is invalid.
        :param file_list: expecting file list as return of parse_changes().
        """
        pass

    def verify_signature(self, file_path):
        """ verify signature of file with GPG key.
        Returns: `bool` True is valid, False is invalid
        :param file_path: expecting .dsc file path or .changes file path
        """
        with open(file_path) as fileobj:
            return self.gpg.verify(fileobj.read()).valid

    def verify_with_dput(self, changes_path):
        """ verify .changes and .dsc files with `dput` command.
        Returns: `bool` True is valid, False is invalid.
        :param changes_path: expecting .changes file path
        """
        pass

    def verification(self, changes_path, dsc_path,
                     dsc_filesize, dsc_checksums, file_list):
        """ verification of signed files.
        Returns: `bool` True is valid, False is invalid.
        :param changes_path: .changes file path
        :param dsc_path: .dsc file path
        :param dsc_filesize: `int` file size retreived from .changes
        :param dsc_checksums: `tuple` .dsc checksums retrieved from .changes
        :param file_list: `list` file list retrieve .changes
        """
        self.verify_filesize(dsc_filesize, file_list)
        self.verify_checksums(dsc_checksums, file_list)
        self.verify_signature(dsc_path)
        self.verify_signature(changes_path)
        self.verify_with_dput(changes_path)
        return True


def debsign_process(changes_path):
    """ debsign process sequence """
    dbsg = Debsign()

    file_list = dbsg.parse_changes(changes_path)
    dsc_path = dbsg.retrieve_dsc_path(file_list)

    if dbsg.is_signed(changes_path):
        dsc_checksums = dbsg.retrieve_checksums(dsc_path)
        dsc_filesize = dbsg.retrieve_filesize(dsc_path)
        dbsg.verification(changes_path,
                          dsc_path,
                          dsc_filesize,
                          dsc_checksums,
                          file_list)

    if dbsg.is_signed(dsc_path) is False:
        dbsg.signing_dsc(dsc_path)
        dsc_checksums = dbsg.retrieve_checksums(dsc_path)
        dsc_filesize = dbsg.retrieve_filesize(dsc_path)
        dbsg.rewrite_changes(changes_path, dsc_filesize, dsc_checksums)

    dbsg.signing_changes(changes_path)
    signed_file_list = dbsg.parse_changes(changes_path)

    dbsg.verification(changes_path,
                      dsc_path,
                      dsc_filesize,
                      dsc_checksums,
                      signed_file_list)
    return True
