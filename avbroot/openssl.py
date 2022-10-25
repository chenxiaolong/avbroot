import binascii
import subprocess

# This module calls the openssl binary because AOSP's avbtool.py already does
# that and the operations are simple enough to not require pulling in a library.


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


def _get_modulus(path, is_x509):
    '''
    Get the RSA modulus of the given file, which can be a private key or
    certificate.
    '''

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


def max_signature_size(pkey):
    '''
    Get the maximum size of a signature signed by the specified RSA key. This is
    equal to the modulus size.
    '''

    return len(_get_modulus(pkey, False))


def sign_data(pkey, data):
    '''
    Sign <data> with <pkey>.
    '''

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


def cert_matches_key(cert, pkey):
    '''
    Check that the x509 certificate matches the RSA private key.
    '''

    return _get_modulus(cert, True) == _get_modulus(pkey, False)


def decrypt_key(input_path, output_path, out_form='PEM'):
    '''
    Copy PKCS8 private key, decrypting it if needed.
    '''

    subprocess.check_output([
        'openssl', 'pkcs8',
        '-in', input_path,
        '-out', output_path,
        '-topk8',
        '-outform', out_form,
        '-nocrypt',
    ])
