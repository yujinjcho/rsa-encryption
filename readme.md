# Code Challenge
* Given a string input of up to 250 characters, return a JSON response compliant to the schema defined below.
* You are responsible for generating a public/private RSA or ECDSA keypair and persisting the keypair on the filesystem
* Subsequent invocations of your application should read from the same files
* Document your code, at a minimum defining parameter types and return values for any public methods
* Include Unit Test(s) with instructions on how a Continuous Integration system can execute your test(s)
* You may only use first order libraries, you may not use any third party libraries or packages.  For example, you may use the OpenSSL library, but you may not use any libraries built on top of OpenSSL.

```
{
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "Signed Identifier",
    "description": "Schema for a signed identifier",
    "type": "object",
    "required": [ "message", "signature", "pubkey" ],
    "properties": {
        "message": {
            "type": "string",
            "description": "original string provided as the input to your app"
        },
        "signature": {
            "type": "string",
            "description": "RFC 4648 compliant Base64 encoded cryptographic signature of the input, calculated using the private key and the SHA256 digest of the input"
        },
        "pubkey": {
            "type": "string",
            "description": "Base64 encoded string (PEM format) of the public key generated from the private key used to create the digital signature"
        }
    }
}
```

# Example

```
>python rsa_sign "theAnswerIs42"
```

Returns:
```
{ 
    "message":"theAnswerIs42",
    "signature":"MGUCMCDwlFyVdD620p0hRLtABoJTR7UNgwj8g2r0ipNbWPi4Us57YfxtSQJ3dAkHslyBbwIxAKorQmpWl9QdlBUtACcZm4kEXfL37lJ+gZ/hANcTyuiTgmwcEC0FvEXY35u2bKFwhA==",
    "pubkey":"-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI5/0zKsIzou9hL3ZdjkvBeVZFKpDwxTb\nfiDVjHpJdu3+qOuaKYgsLLiO9TFfupMYHLa20IqgbJSIv/wjxANH68aewV1q2Wn6\nvLA3yg2mOTa/OHAZEiEf7bVEbnAov+6D\n-----END PUBLIC KEY-----\n"
}
```
