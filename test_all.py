import os
import tempfile
import unittest

from charm.toolbox.pairinggroup import PairingGroup

from filecrypt import decrypt_file, encrypt_file
from ibe_bf import MSG_LEN, BonehFranklinIBE
from rsa_baseline import rsa_decrypt_file, rsa_encrypt_file, rsa_keygen

ALICE = "alice@nmsu.edu"
BOB = "bob@nmsu.edu"


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ibe = BonehFranklinIBE(PairingGroup("SS512"))
        cls.pk, cls.mk = cls.ibe.setup()

    def roundtrip(self, encrypt, decrypt):
        data = os.urandom(100000)
        with tempfile.TemporaryDirectory() as d:
            src, enc, out = (os.path.join(d, n) for n in ("src", "enc", "out"))
            with open(src, "wb") as f:
                f.write(data)
            encrypt(src, enc)
            decrypt(enc, out)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), data)

    def test_roundtrip(self):
        sk = self.ibe.extract(self.mk, ALICE)
        msg = os.urandom(MSG_LEN)
        ct = self.ibe.encrypt(self.pk, ALICE, msg)
        self.assertEqual(self.ibe.decrypt(self.pk, sk, ct), msg)

    def test_wrong_identity(self):
        sk_bob = self.ibe.extract(self.mk, BOB)
        ct = self.ibe.encrypt(self.pk, ALICE, os.urandom(MSG_LEN))
        self.assertIsNone(self.ibe.decrypt(self.pk, sk_bob, ct))

    def test_tampered_ciphertext(self):
        sk = self.ibe.extract(self.mk, ALICE)
        ct = self.ibe.encrypt(self.pk, ALICE, os.urandom(MSG_LEN))
        other = self.ibe.encrypt(self.pk, ALICE, os.urandom(MSG_LEN))
        ct["U"] = other["U"]
        self.assertIsNone(self.ibe.decrypt(self.pk, sk, ct))

    def test_ibe_file(self):
        sk = self.ibe.extract(self.mk, ALICE)
        self.roundtrip(
            lambda i, o: encrypt_file(self.ibe, self.pk, ALICE, i, o),
            lambda i, o: decrypt_file(self.ibe, self.pk, sk, i, o),
        )

    def test_ibe_file_wrong_key(self):
        sk_bob = self.ibe.extract(self.mk, BOB)
        with tempfile.TemporaryDirectory() as d:
            src, enc, out = (os.path.join(d, n) for n in ("src", "enc", "out"))
            with open(src, "wb") as f:
                f.write(b"secret")
            encrypt_file(self.ibe, self.pk, ALICE, src, enc)
            with self.assertRaises(ValueError):
                decrypt_file(self.ibe, self.pk, sk_bob, enc, out)

    def test_rsa_file(self):
        pub, priv = rsa_keygen(2048)
        self.roundtrip(
            lambda i, o: rsa_encrypt_file(pub, i, o),
            lambda i, o: rsa_decrypt_file(priv, i, o),
        )
