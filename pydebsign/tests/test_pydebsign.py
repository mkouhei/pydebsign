# -*- coding: utf-8 -*-
""" pydebsing.tests.test_pydebsign """

import unittest
import shutil
from pydebsign import debsign


class PydebsignTests(unittest.TestCase):
    """ Unit test of pydebsign """

    def setUp(self):
        shutil.copytree('pydebsign/tests/test_data', '_build')
        self.keyrings = ['misc/dummy_gpg/secring.gpg',
                         'misc/dummy_gpg/pubring.gpg']
        self.keyid = '5BAFE1FA'
        self.passphrase = 'password'

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
            debsign.debsign_process('_build/shello_0.1-1_amd64.changes',
                                    passphrase=self.passphrase,
                                    keyrings=self.keyrings,
                                    keyid=self.keyid))

    def test_invalid_passphrase(self):
        """ trying debsign with invalid passphrase """
        self.assertFalse(
            debsign.debsign_process('_build/shello_0.1-1_amd64.changes',
                                    passphrase='dummy',
                                    keyrings=self.keyrings))

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
        pass

    def test_invalid_dsc(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .dsc file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Compare 2 and 3 values.
        5. Signing .changes file with GPG key.
        6. Fail to verify checksums from .changes and retreived checksums
        """
        pass

    def test_signed_changes(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .changes file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Verify checksums from .changes and retreived checksums
        """
        pass

    def test_invalid_signed_changes(self):
        """ signing .changes and verifying process is as follows;
        1. Already signed .changes file with GPG key.
        2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
        3. Retrieve size and checksums of .dsc from .changes
        4. Fail to verify checksums from .changes and retreived checksums
        """
        pass
