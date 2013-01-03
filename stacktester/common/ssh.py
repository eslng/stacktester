
import time
import socket
import warnings
import binascii

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import paramiko
    from paramiko import SSHException


class Client(object):

    def __init__(self, host, username, password, pkey=None, timeout=300):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.private_key = pkey

    def _get_ssh_connection(self):
        """Returns an ssh connection to the specified host"""
        _timeout = True
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy())
        _start_time = time.time()

        while not self._is_timed_out(self.timeout, _start_time):
            try:
                ssh.connect(self.host, username=self.username,
                    password=self.password, pkey=self.private_key,
                    look_for_keys=False, timeout=self.timeout)
                _timeout = False
                break
            except socket.error:
                continue
            except paramiko.AuthenticationException:
                time.sleep(15)
                continue
        if _timeout:
            raise socket.error("SSH connect timed out")
        return ssh

    def _is_timed_out(self, timeout, start_time):
        return (time.time() - timeout) > start_time

    def connect_until_closed(self):
        """Connect to the server and wait until connection is lost"""
        try:
            ssh = self._get_ssh_connection()
            _transport = ssh.get_transport()
            _start_time = time.time()
            _timed_out = self._is_timed_out(self.timeout, _start_time)
            while _transport.is_active() and not _timed_out:
                time.sleep(5)
                _timed_out = self._is_timed_out(self.timeout, _start_time)
            ssh.close()
        except (EOFError, paramiko.AuthenticationException, socket.error):
            return

    def exec_command(self, cmd):
        """Execute the specified command on the server.

        :returns: data read from standard output of the command

        """
        ssh = self._get_ssh_connection()
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read()
        ssh.close()
        return output

    def test_connection_auth(self):
        """ Returns true if ssh can connect to server"""
        try:
            connection = self._get_ssh_connection()
            connection.close()
        except paramiko.AuthenticationException:
            return False

        return True


def generate_key(ktype='dsa', bits=1024):
    """Generates a keypair"""
    key_table = {'dsa': paramiko.DSSKey,
                 'rsa': paramiko.RSAKey,
                }
    if ktype == 'dsa' and bits > 1024:
        raise SSHException('DSA keys must be 1024 bits')
    if not key_table.has_key(ktype):
        raise SSHException("Unknown %s algorithm to generate keys pair"
                    % ktype)
    private_key = key_table[ktype].generate(bits)
    pub_key = '%s %s' % (private_key.get_name(), private_key.get_base64())
    fp_hash = binascii.hexlify(private_key.get_fingerprint())
    fingerprint = ":".join([fp_hash[i:2+i] \
            for i in range(0, len(fp_hash), 2)])
    return private_key, pub_key, fingerprint

