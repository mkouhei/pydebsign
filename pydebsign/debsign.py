# -*- coding: utf-8 -*-
"""
pydebsign.debsign
-----------------

debsign process as follows;

1. Signing .dsc file with GPG key.
2. Retrieve size and md5, sha1, sha256 checksums from signed .dsc.
3. Rewrite of above values at .changes.
4. Siging .changes file with GPG key.

optional:
How to verify signed files ``dput -o .changes`` command.

----
"""
import re
import os.path
import hashlib
import subprocess
import codecs
import shlex
import gnupg
import deb822


class Debsign(object):
    """The :class:`Debsign <Debsign>` object."""
    def __init__(self, changes_path, passphrase=None, keyid=None,
                 gnupghome=None, verbose=False,
                 lintian=True, dput_host='local'):
        #: changes file path: .changes file path
        self.changes_path = os.path.abspath(changes_path)

        #: dsc file path
        self.dsc_path = ''

        if passphrase:
            #: passphrase of GPG secret key, using gpg-agent
            #: when this is None. But cannot use execuceded gpg-agent
            #: by another shell session.
            self.passphrase = passphrase
            use_agent = False
        else:
            self.passphrase = None
            use_agent = True
        #: keyid id for the key which will be used to do the signing
        self.keyid = keyid

        if gnupghome:
            os.environ['GNUPGHOME'] = os.path.abspath(gnupghome)
            self.gpg = gnupg.GPG(gnupghome=gnupghome,
                                 use_agent=use_agent,
                                 verbose=verbose)
        else:
            self.gpg = gnupg.GPG(use_agent=use_agent, verbose=verbose)
        #: lintian mode (default: ``True``);
        #: True is running lintian by dput
        self.lintian = lintian
        if check_dput_host(dput_host) is False:
            raise KeyError('%s is not defined '
                           'in /etc/dput.cf or ~/.dput.cf' % dput_host)
        #: :data:`str`: specify host identifier for dput
        #: ``local`` is defined in ``/etc/dput.cf`` in default;
        #: cf. you know to print ``dput -H``.
        self.dput_host = dput_host

    def initialize(self):
        """
        initialize common propeties
        """
        base_path = os.path.dirname(os.path.abspath(self.changes_path))
        file_list = self.parse_changes()
        self.dsc_path = os.path.join(base_path,
                                     self.retrieve_dsc_path(file_list[0]))

    def is_signed(self, file_path):
        """
        checking signed file with GPG key

        :rtype: bool
        :return: ``True`` is signed, ``False`` is unsigned.
        :param str file_path: expecting .dsc file or .changes file.
        """
        with open(file_path, 'rb') as fileobj:
            data = fileobj.read()
            if check_encode(data):
                # for Python 3
                data = data.decode('utf-8')

            if data.find('-----BEGIN PGP SIGNED MESSAGE-----') == 0:
                # signed data why found gpg header
                if self.gpg.verify(data).timestamp is None:
                    # invalid signed data
                    raise ValueError('invalid signed data')
                else:
                    # valid signed data
                    return True
            else:
                # not signed data
                return False

    def parse_changes(self):
        """
        parse .changes and retrieve efile size and file name list.

        :rtype: list
        :return: file list with file size and checksums.
        """
        with open(self.changes_path, 'rb') as fileobj:
            changes = deb822.Changes(fileobj)
        return [changes['Files'],
                changes['Checksums-Sha1'],
                changes['Checksums-Sha256']]

    @staticmethod
    def retrieve_dsc_path(file_list):
        """
        retrieve dsc file path from file list.

        :rtype: str
        :return: dsc file path
        :param list file_list: file list as return of parse_changes().
        """
        pattern = re.compile(r'.dsc\Z')
        return [_file.get('name') for _file in file_list
                if pattern.search(_file.get('name'))][0]

    def signing_changes(self):
        """
        signing .changes file with GPG key,
        invoke siging_dsc() when not yet to sign .dsc file.

        :rtype: bool
        :return: ``True`` is successful, ``False`` is failure.
        """
        with open(self.changes_path, 'rb') as fileobj:
            data = fileobj.read()
        signed_data = self.gpg.sign(data, passphrase=self.passphrase,
                                    keyid=self.keyid)
        if signed_data.fingerprint is None and signed_data.type is None:
            return False

        with open(self.changes_path, 'w') as fileobj:
            if check_encode(signed_data.data):
                fileobj.write(signed_data.data.decode('utf-8'))
            else:
                fileobj.write(signed_data.data)
        return True

    def signing_dsc(self):
        """
        signing .dscs file with GPG key,
        invoke rewrite_changes() when this method is succeeded.

        :rtype: bool
        :return: ``True`` is successful, ``False`` is failure.
        """
        with open(self.dsc_path, 'rb') as fileobj:
            data = fileobj.read()
        signed_data = self.gpg.sign(data, passphrase=self.passphrase,
                                    keyid=self.keyid)
        if signed_data.fingerprint is None and signed_data.type is None:
            return False

        with open(self.dsc_path, 'w') as fileobj:
            if check_encode(signed_data.data):
                fileobj.write(signed_data.data.decode('utf-8'))
            else:
                fileobj.write(signed_data.data)
        return True

    def rewrite_changes(self, filesize, checksums):
        """
        rewrite file size and hash fingerprint of .dsc file.
        invoke retrieve_checksums() and retreive_filesize().
        this method is invoked by siging_dsc().

        :rtype: bool
        :return: status code
        :param int filesize: .dsc file size
        :param tuple checksums: md5sum, sha1, sha256 hexdigest
        """
        with open(self.changes_path, 'rb') as fileobj:
            changes = deb822.Changes(fileobj)
        # md5sum
        rewrite_data(changes, ('Files', 'md5sum'), filesize, checksums[0])
        # sha1
        rewrite_data(changes, ('Checksums-Sha1', 'sha1'),
                     filesize, checksums[1])
        # sha1
        rewrite_data(changes, ('Checksums-Sha256', 'sha256'),
                     filesize, checksums[2])
        with codecs.open(self.changes_path, 'w', 'utf-8') as fileobj:
            if check_encode(changes.dump()):
                fileobj.write(changes.dump().decode('utf-8'))
            else:
                fileobj.write(changes.dump())
        return True

    @staticmethod
    def retrieve_checksums(file_path):
        """
        retrieve md5, sha1, sha256 checksums.

        :rtype: tuple
        :return: md5, sha1, sha256 hexdigest.

        :param str file_path: expecting .dsc file path.
        """
        with open(file_path, 'rb') as fileobj:
            data = fileobj.read()
        return (hashlib.md5(data).hexdigest(),
                hashlib.sha1(data).hexdigest(),
                hashlib.sha256(data).hexdigest())

    @staticmethod
    def retrieve_filesize(file_path):
        """
        retrieve file size.

        :rtype: int
        :return: fils size

        :param str file_path: absolute file path
        """
        return os.path.getsize(file_path)

    @staticmethod
    def verify_filesize(dsc_filesize, file_list):
        """
        verify file size with file list retrieved from changes.

        :rtype: bool
        :return: ``True`` is valid, ``False`` is invalid.

        :param int dsc_filesize: file size of .dsc
        :param list file_list: file list as return of parse_changes().
        """
        pattern = re.compile(r'.dsc\Z')
        return dsc_filesize == [int(_file.get('size'))
                                for _file in file_list[0]
                                if pattern.search(_file.get('name'))][0]

    @staticmethod
    def verify_checksums(dsc_checksums, file_list):
        """
        verify checksums (and size) with file list retrieved from changes.

        :rtype: bool
        :return: ``True`` is valid, ``False`` is invalid.

        :param list file_list: file list as return of parse_changes().
        """
        pattern = re.compile(r'.dsc\Z')

        if dsc_checksums[0] != [_file.get('md5sum')
                                for _file in file_list[0]
                                if pattern.search(_file.get('name'))][0]:
            return False
        if dsc_checksums[1] != [_file.get('sha1')
                                for _file in file_list[1]
                                if pattern.search(_file.get('name'))][0]:
            return False
        if dsc_checksums[2] != [_file.get('sha256')
                                for _file in file_list[2]
                                if pattern.search(_file.get('name'))][0]:
            return False
        return True

    def verify_signature(self, file_path):
        """verify signature of file with GPG key.

        :rtype: bool
        :return: ``True`` is valid, ``False`` is invalid

        :param str file_path: expecting .dsc file path or .changes file path
        """
        with open(file_path) as fileobj:
            return self.gpg.verify(fileobj.read()).valid

    def verify_with_dput(self):
        """verify .changes and .dsc files with ``dput`` command,
        and automatically inclide a lintian run any moure.

        :rtype: bool
        :return: ``True`` is valid, ``False`` is invalid.
        """
        if self.lintian:
            command = '/usr/bin/dput -ol %s %s' % (self.dput_host,
                                                   self.changes_path)
        else:
            command = '/usr/bin/dput -o %s %s' % (self.dput_host,
                                                  self.changes_path)
        args = shlex.split(command)
        return subprocess.call(args)

    def verification(self, dsc_filesize, dsc_checksums, file_list):
        """
        verification of signed files.

        :rtype: bool
        :return: ``True`` is valid, ``False`` is invalid.

        :param int dsc_filesize: file size retreived from .changes
        :param tuple dsc_checksums: .dsc checksums retrieved from .changes
        :param list file_list: file list retrieve .changes
        """
        if self.verify_filesize(dsc_filesize, file_list) is False:
            raise ValueError('difference file size of .dsc')

        if self.verify_checksums(dsc_checksums, file_list) is False:
            raise ValueError('invalid checksums of .dsc')

        if self.verify_signature(self.dsc_path) is False:
            raise ValueError('invalid signature of .dsc')

        if self.verify_signature(self.changes_path) is False:
            raise ValueError('invalid signature of .changes')

        if self.verify_with_dput() != 0:
            raise ValueError('invalid checking with dput')

        return True


def debsign_process(changes_path, passphrase=None, keyid=None,
                    gnupghome=None, lintian=True, dput_host='local'):
    """
    debsign process sequence

    :rtype: bool
    :return: ``True`` is valid, ``False`` is invalid.

    :param str changes_path: .changes file path
    :param str passphrase: passphrase of GPG secret key, using gpg-agent

        when this is None. But cannot use execuceded gpg-agent
        by another shell session.

    :param str keyid: id for the key which will be used to do the signing
    :param str gnupghome: path of .gnupg existed directory
    :param bool verbose: ``True`` is verbose message of gnupg
    :param bool lintian: ``True`` is running lintian by dput
    :param str dput_host: specify host identifier for dput ``local``

        is defined in ``/etc/dput.cf`` in default
        cf. you know to print ``dput -H``.
    """
    dbsg = Debsign(changes_path, passphrase=passphrase,
                   keyid=keyid, gnupghome=gnupghome,
                   lintian=lintian, dput_host=dput_host)
    dbsg.initialize()
    file_list = dbsg.parse_changes()

    if dbsg.is_signed(changes_path):
        dsc_checksums = dbsg.retrieve_checksums(dbsg.dsc_path)
        dsc_filesize = dbsg.retrieve_filesize(dbsg.dsc_path)
        return dbsg.verification(dsc_filesize, dsc_checksums, file_list)

    if dbsg.is_signed(dbsg.dsc_path) is False:
        if dbsg.signing_dsc() is False:
            return False
    dsc_checksums = dbsg.retrieve_checksums(dbsg.dsc_path)
    dsc_filesize = dbsg.retrieve_filesize(dbsg.dsc_path)
    dbsg.rewrite_changes(dsc_filesize, dsc_checksums)

    if dbsg.signing_changes() is False:
        return False
    signed_file_list = dbsg.parse_changes()
    return dbsg.verification(dsc_filesize, dsc_checksums, signed_file_list)


def rewrite_data(changes_obj, hash_type, filesize, hashdigest):
    """rewrite .changes object with new file size and hashdigest.

    :param `Deb822Dict` changes_obj: :class:`Deb822Dict` object
    :param tuple hash_type: hash type of .changes
    :param int filesize: expecting .dsc file size
    :param str hashdigest: expecting .dsc hash digest
    """
    pattern = re.compile(r'.dsc\Z')
    line = [line for line in changes_obj[hash_type[0]]
            if pattern.search(line.get('name'))][0]
    line_index = changes_obj[hash_type[0]].index(line)
    changes_obj[hash_type[0]][line_index]['size'] = str(filesize)
    changes_obj[hash_type[0]][line_index][hash_type[1]] = hashdigest


def check_encode(data):
    """
    Check data encode

    :rtype: bool
    :return: ``True`` is Python3, ``False`` is Python2

    :param str|bytes data: expecting str (Python2) or bytes (Python3)
    """
    return (isinstance(data, bytes) and
            isinstance(data, str) is False)


def check_dput_host(dput_host):
    """
    Check spcified host is defined in dput.cf

    :rtype: bool
    :return: ``True`` is dput_host is defined

    :param str dput_host: dput host
    """
    command = '/usr/bin/dput -H'
    args = shlex.split(command)
    response = subprocess.check_output(args).decode('utf-8')
    return dput_host in [host.split(' => ')[0]
                         for host in response.split('\n')
                         if len(host.split(' => ')) > 1]
