# -*- coding: utf-8 -*-
""" pydebsing.tests.test_pydebsign """

import unittest
import shutil
import os
import sys
from pydebsign import debsign


class PydebsignTests(unittest.TestCase):
    """ Unit test of pydebsign """

    def setUp(self):
        shutil.copytree('pydebsign/tests/test_data', '_build')
        self.gnupghome = os.path.abspath('misc/dummy_gpg')
        self.keyid = '5A046C53'
        self.passphrase = 'password'
        self.changes_path = '_build/shello_0.1-1_amd64.changes'

    def tearDown(self):
        shutil.rmtree('_build')

    def test_normal_case(self):
        """ signing .changes and verifying process is as follows;
        1. Signing .dsc file with GPG key.
        2. Retrieve size and md5, sha1, sha256 finger print from signed .dsc.
        3. Rewrite of above values at .changes.
        4. Signing .changes file with GPG key.
        5. Verify checksums from .changes and retreived checksums
        6. Verify signature of .dsc and .changes
        7. Verify .changes file with `dput -o .changes` command.
        """
        self.assertTrue(
            debsign.debsign_process(self.changes_path,
                                    passphrase=self.passphrase,
                                    keyid=self.keyid,
                                    gnupghome=self.gnupghome,
                                    lintian=False))

    def test_invalid_passphrase(self):
        """ trying debsign with invalid passphrase """
        self.assertFalse(
            debsign.debsign_process(self.changes_path,
                                    passphrase='dummy',
                                    gnupghome=self.gnupghome,
                                    lintian=False))

    def test_signed_dsc(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .dsc file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Compare 2 and 3 values.
        5. Signing .changes file with GPG key.
        6. Verify checksums from .changes and retreived checksums
        7. Verify signature of .dsc and .changes
        8. Verify .changes file with `dput -o .changes` command.
        """
        dbsg = debsign.Debsign(self.changes_path,
                               passphrase='password',
                               keyid=self.keyid,
                               gnupghome=self.gnupghome)
        dbsg.initialize()
        dbsg.signing_dsc()
        self.assertTrue(debsign.debsign_process(self.changes_path,
                                                passphrase='password',
                                                gnupghome=self.gnupghome,
                                                lintian=False))

    def test_invalid_dsc(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .dsc file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Compare 2 and 3 values.
        5. Signing .changes file with GPG key.
        6. Fail to verify checksums from .changes and retreived checksums
        """
        dbsg = debsign.Debsign(self.changes_path,
                               passphrase='password',
                               keyid=self.keyid,
                               gnupghome=self.gnupghome)
        dbsg.initialize()
        dbsg.signing_dsc()
        shutil.copyfile('%s.invalid' % dbsg.dsc_path, dbsg.dsc_path)
        self.assertRaises(ValueError,
                          debsign.debsign_process,
                          self.changes_path,
                          passphrase='password',
                          gnupghome=self.gnupghome,
                          lintian=False)

    def test_signed_changes(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .changes file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Verify checksums from .changes and retreived checksums
        """
        dbsg = debsign.Debsign(self.changes_path,
                               passphrase='password',
                               keyid=self.keyid,
                               gnupghome=self.gnupghome)
        dbsg.initialize()
        shutil.copyfile('%s.signed' % self.changes_path, self.changes_path)
        shutil.copyfile('%s.signed' % dbsg.dsc_path, dbsg.dsc_path)
        self.assertTrue(debsign.debsign_process(self.changes_path,
                                                passphrase='password',
                                                gnupghome=self.gnupghome,
                                                lintian=False))

    def test_invalid_signed_changes(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .changes file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Fail to verify checksums from .changes and retreived checksums
        """
        shutil.copyfile('%s.signed' % self.changes_path, self.changes_path)
        self.assertRaises(ValueError,
                          debsign.debsign_process,
                          self.changes_path,
                          passphrase='password',
                          gnupghome=self.gnupghome,
                          lintian=False)

    def test_check_encode(self):
        """ unit test of check_encode() """
        _str = '012345689abcdefghijklmnopqrstuvwxwzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        _byte = b'\xc3\x84\xc3\x8b\xc3\x8f\xc3\x96\xc3\x9c\xc3'
        _byte2 = b'\xa4\xc3\xab\xc3\xaf\xc3\xb6\xc3\xbc\xc3\xbf'

        self.assertFalse(debsign.check_encode(_str))

        if sys.version_info < (3, 0):
            self.assertFalse(debsign.check_encode(_byte))
            self.assertFalse(debsign.check_encode(_byte2))
        else:
            self.assertTrue(debsign.check_encode(_byte))
            self.assertTrue(debsign.check_encode(_byte2))
