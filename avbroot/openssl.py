import binascii
import contextlib
import getpass
import os
import subprocess
import unittest.mock

# This module calls the openssl binary because AOSP's avbtool.py already does
# that and the operations are simple enough to not require pulling in a
# library.


@contextlib.contextmanager
def _passphrase_fd(passphrase):
    '''
    If the specified passphrase is not None, yield the readable end of a pipe
    that produces the passphrase encoded as UTF-8, followed by a newline. The
    read end of the pipe is marked as inheritable. Both ends of the pipe are
    closed after leaving the context.
    '''

    if passphrase is None:
        yield None
        return

    # For simplicity, we don't write to the pipe on a thread, so pick a maximum
    # length that doesn't exceed any OS's pipe buffer size, while still being
    # usable for just about every use case.
    if len(passphrase) >= 4096:
        raise ValueError('Passphrase is too long')

    pipe_r, pipe_w = os.pipe()
    write_closed = False

    try:
        os.set_inheritable(pipe_r, True)

        os.write(pipe_w, passphrase.encode('UTF-8'))
        os.write(pipe_w, b'\n')
        os.close(pipe_w)
        write_closed = True

        yield pipe_r
    finally:
        os.close(pipe_r)
        if not write_closed:
            os.close(pipe_w)


class _PopenPassphraseWrapper:
    '''
    Wrapper around subprocess.Popen() that adds arguments for passing in the
    private key passphrase via a pipe
    '''

    def __init__(self, passphrase):
        self.orig_popen = subprocess.Popen
        self.passphrase = passphrase

    def __call__(self, cmd, *args, **kwargs):
        if cmd and os.path.basename(cmd[0]) == 'openssl':
            with _passphrase_fd(self.passphrase) as fd:
                kwargs['close_fds'] = False

                new_cmd = cmd[:]
                if fd is not None:
                    new_cmd.append('-passin')
                    new_cmd.append(f'fd:{fd}')

                return self.orig_popen(new_cmd, *args, **kwargs)

            # The pipe is closed at this point in this process, but the child
            # already inherited the fd and the passphrase is sitting the pipe
            # buffer
        else:
            return self.orig_popen(cmd, *args, **kwargs)


def inject_passphrase(passphrase):
    '''
    While this context is active, patch subprocess calls to openssl so that
    the passphrase is specified via an injected -passin argument, if it is not
    None. The passphrase is passed to the command via a pipe file descriptor.
    '''

    return unittest.mock.patch(
        'subprocess.Popen', side_effect=_PopenPassphraseWrapper(passphrase))


def _guess_format(path):
    '''
    Simple heuristic to determine the encoding of a key. This is needed because
    openssl 1.1 doesn't support autodetection.
    '''

    with open(path, 'rb') as f:
        for line in f:
            if line.startswith(b'-----BEGIN '):
                return 'PEM'

    return 'DER'


def _get_modulus(path, passphrase, is_x509):
    '''
    Get the RSA modulus of the given file, which can be a private key or
    certificate.
    '''

    with inject_passphrase(passphrase):
        output = subprocess.check_output([
            'openssl',
            'x509' if is_x509 else 'rsa',
            '-in', path,
            '-inform', _guess_format(path),
            '-noout',
            '-modulus',
        ])

    prefix, delim, suffix = output.strip().partition(b'=')
    if not delim or prefix != b'Modulus':
        raise Exception(f'Unexpected modulus output: {repr(output)}')

    return binascii.unhexlify(suffix)


def max_signature_size(pkey, passphrase):
    '''
    Get the maximum size of a signature signed by the specified RSA key. This
    is equal to the modulus size.
    '''

    return len(_get_modulus(pkey, passphrase, False))


def sign_data(pkey, passphrase, data):
    '''
    Sign <data> with <pkey>.
    '''

    with inject_passphrase(passphrase):
        return subprocess.check_output(
            [
                'openssl', 'pkeyutl',
                '-sign',
                '-inkey', pkey,
                '-keyform', _guess_format(pkey),
                '-pkeyopt', 'digest:sha256',
            ],
            input=data,
        )


def cert_matches_key(cert, pkey, passphrase):
    '''
    Check that the x509 certificate matches the RSA private key.
    '''

    return _get_modulus(cert, None, True) \
        == _get_modulus(pkey, passphrase, False)


def _is_encrypted(pkey):
    '''
    Check if a private key is encrypted.
    '''

    with open(pkey, 'rb') as f:
        for line in f:
            if b'-----BEGIN ENCRYPTED PRIVATE KEY-----' == line.strip():
                return True

    return False


def prompt_passphrase(pkey):
    '''
    Prompt and return passphrase if the private key is encrypted.
    '''

    if not _is_encrypted(pkey):
        return None

    passphrase = getpass.getpass(f'Passphrase for {pkey}: ')

    # Verify that it is correct
    with inject_passphrase(passphrase):
        subprocess.check_output(['openssl', 'pkey', '-in', pkey, '-noout'])

    return passphrase
