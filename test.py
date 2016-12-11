import os
import unittest
import rsa_sign
import json
from OpenSSL import crypto

class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # setup for create_identifier
        cls.create_identifier_filename = 'test_create.pem'

        # setup for retrieve tests
        cls.retrieve_file = 'test_private.pem'
        cls.retrieve_identifier_message = 'testing retrieve identifiers'
        rsa_sign._create_identifiers(
            cls.retrieve_identifier_message,
            cls.retrieve_file
        )

        # for testing create_file
        cls.create_filename = 'new_file'

    def setUp(self):
        self.key_pair = rsa_sign._create_key_pair_object()

    def test_signed_identifier(self):
        message = 'this is a test'
        result = json.loads(rsa_sign.signed_identifier(message))

        self.assertRaises(TypeError, rsa_sign.signed_identifier, 123)
        self.assertRaises(ValueError, rsa_sign.signed_identifier, 'A'*251)
        self.assertEqual(result['message'], message)
        self.assertTrue('pubkey' in result)
        self.assertTrue('signature' in result)
        self.assertEqual(result['pubkey'][0:21], '-----BEGIN PUBLIC KEY')

    def test_create_identifiers(self):
        message = 'testing create identifiers'
        self.assertFalse(
            os.path.exists(self.create_identifier_filename)
        )
        rsa_sign._create_identifiers(
            message, self.create_identifier_filename
        )
        self.assertTrue(os.path.exists(self.create_identifier_filename))

    def test_retrieve_identifiers(self):
        self.assertTrue(os.path.exists(self.retrieve_file))
        response = rsa_sign._retrieve_identifiers(
            self.retrieve_identifier_message,
            self.retrieve_file
        )
        self.assertTrue(isinstance(response, dict))

    def test_retrieve_key_pair(self):
        key_pair = rsa_sign._retrieve_key_pair(self.retrieve_file)
        self.assertTrue(isinstance(key_pair, crypto.PKey))
        self.assertEqual(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)[0:22],
            '-----BEGIN PRIVATE KEY'
        )

    def test_create_file(self):
        message = "test create file"
        self.assertFalse(os.path.exists(self.create_filename))
        rsa_sign._create_file(self.create_filename, message)
        self.assertTrue(os.path.exists(self.create_filename))
        saved_message = open(self.create_filename).read()
        self.assertEqual(saved_message, message)

    def test_create_key_pair(self):
        key_pair = rsa_sign._create_key_pair_object()
        self.assertTrue(isinstance(key_pair, crypto.PKey))
        self.assertTrue(key_pair.check())


    def test_create_certificate(self):
        cert = rsa_sign._create_certificate(self.key_pair)
        self.assertTrue(isinstance(cert, crypto.X509))

    def test_create_signature(self):
        message = 'testing create signature'
        signature = rsa_sign._create_signature(self.key_pair, message)
        self.assertTrue(isinstance(signature, basestring))

    def test_format_response(self):
        message = 'test format response'
        signature = rsa_sign._create_signature(self.key_pair, message)
        response = rsa_sign._format_response(message, signature, self.key_pair)
        self.assertTrue('message' in response)
        self.assertTrue('signature' in response)
        self.assertTrue('pubkey' in response)

    def test_signature_verification(self):
        message = 'signature verification test'
        signature = rsa_sign._create_signature(self.key_pair, message)
        cert = rsa_sign._create_certificate(self.key_pair)

        try:
            crypto.verify(cert, signature, message, 'sha256')
            self.assertTrue(True)
        except Exception as e:
            self.assertTrue(False)

        try:
            message2 = 'signature verification test different'
            crypto.verify(cert, signature, message2, 'sha256')
            self.assertTrue(False)
        except Exception as e:
            self.assertTrue(True)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.create_identifier_filename)
        os.remove(cls.retrieve_file)
        os.remove(cls.create_filename)

if __name__ == '__main__':
    unittest.main()
