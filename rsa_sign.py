import os
import sys
import json
import base64

from OpenSSL import crypto
import config


def main(args):
    if len(args) != 2:
        raise ValueError('Input should be one string')

    print signed_identifier(args[1])


def signed_identifier(message):
    """Returns json with the original message, signature, and public key
    based on RSA encryption. Creates keys and saves private key if file
    does not exist otherwise retrieves existing files.

    :param <str> message: must be less than 250 chars
    """

    if len(message) > 250:
        raise ValueError('Input can only be up to 250 characters')
    elif not isinstance(message, basestring):
        raise TypeError('Input must be string type')

    if os.path.exists(config.PRIVATE_FILE):
        identifier = _retrieve_identifiers(message, config.PRIVATE_FILE)
    else:
        identifier = _create_identifiers(message, config.PRIVATE_FILE)

    return json.dumps(identifier)


def _create_identifiers(message, filename):
    """Creates a new key-pair object, signature, and persists
    private key to file system.

    :param <str> message: must be less than 250 chars
    """
    key_pair = _create_key_pair_object()
    signature = base64.b64encode(_create_signature(key_pair, message))
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
    _create_file(filename, private_key)
    return _format_response(message, signature, key_pair)


def _retrieve_identifiers(message, filename):
    """Retrieves key-pair based on existing private key
    stored in file system. Creates new signature based
    on received message.

    :param <str> message: must be less than 250 chars
    """
    key_pair = _retrieve_key_pair(filename)
    signature = _create_signature(key_pair, message)
    return _format_response(message, signature, key_pair)


def _retrieve_key_pair(filename):
    """Returns key-pair object based on private key stored in filesystem"""

    private_key = open(filename, 'r').read()
    key_pair = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
    return key_pair


def _create_file(filename, data):
    """Creates new file and writes data.

    :param <str> filename: name of file to create
    :param <str> data: text to write into file
    """

    new_file = open(filename, 'w')
    new_file.write(data)
    new_file.close()


def _create_key_pair_object():
    """Creates and returns new key-pair object and generates
    keys based on RSA encryption and specified bits
    """

    key_pair_object = crypto.PKey()
    key_pair_object.generate_key(crypto.TYPE_RSA, config.BITS)
    return key_pair_object


def _create_certificate(key_pair):
    """Creates and returns a certificate set with public key.

    :param <PKey object> key_pair: key_pair object
    """

    certificate = crypto.X509()
    certificate.set_pubkey(key_pair)
    return certificate


def _create_signature(key_pair, message):
    """Creates and returns a signature based on
    key-pair object and supplied message using SHA256

    :param <PKey object> key_pair: key_pair object
    :param <str> message: must be less than 250 chars
    """
    signature = crypto.sign(key_pair, message, config.DIGEST)
    return signature


def _format_response(message, signature, key_pair):
    """Formats and returns parameters in required format.

    :param <str> message: must be less than 250 chars
    :param <str> signature: signature based on message and private key
    :param <PKey object> key_pair: key_pair object
    """

    signature_base_64 = base64.b64encode(signature)
    pubkey = crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair)
    response = {
        'message': message,
        'signature': signature_base_64,
        'pubkey': pubkey
    }
    return response

if __name__ == '__main__':
    main(sys.argv)
