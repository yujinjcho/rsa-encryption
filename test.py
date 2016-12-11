import unittest
import rsa_sign
import json
from OpenSSL import crypto

class Test(unittest.TestCase):

    def test_create_key_pair(self):
        key_pair = rsa_sign._create_key_pair_object()
        self.assertTrue(isinstance(key_pair, crypto.PKey))
        self.assertTrue(key_pair.check())

    def test_create_signature(self):
        key_pair = rsa_sign._create_key_pair_object()
        message = 'testing create signature'
        signature = rsa_sign._create_signature(key_pair, message)
        self.assertTrue(isinstance(signature, basestring))

    def test_create_certificate(self):
        key_pair = rsa_sign._create_key_pair_object()
        cert = rsa_sign._create_certificate(key_pair)
        self.assertTrue(isinstance(cert, crypto.X509))

    def test_signed_identifier(self):
        message = 'this is a test'
        result = json.loads(rsa_sign.signed_identifier(message))

        self.assertRaises(TypeError, rsa_sign.signed_identifier, 123)
        self.assertRaises(ValueError, rsa_sign.signed_identifier, 'A'*251)
        self.assertEqual(result['message'], message)
        self.assertTrue('pubkey' in result)
        self.assertTrue('signature' in result)
        self.assertEqual(result['pubkey'][0:21], '-----BEGIN PUBLIC KEY')

    def test_signature_verification(self):
        message = 'signature verification test'
        key_pair = rsa_sign._create_key_pair_object()
        signature = rsa_sign._create_signature(key_pair, message)
        cert = rsa_sign._create_certificate(key_pair)

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

if __name__ == '__main__':
    unittest.main()
