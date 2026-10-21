from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.IBEnc import IBEnc


class BonehFranklinIBE(IBEnc):
    def __init__(self, group):
        IBEnc.__init__(self)
        self.group = group

    def setup(self):
        raise NotImplementedError

    def extract(self, mk, identity):
        raise NotImplementedError

    def encrypt(self, pk, identity, msg):
        """Returns {'U': ..., 'V': ..., 'W': ...}."""
        raise NotImplementedError

    def decrypt(self, pk, sk, ct):
        """Returns msg, or None if the check on U fails."""
        raise NotImplementedError

    def H2(self, gt_elem, n):
        raise NotImplementedError

    def H3(self, sigma, msg):
        raise NotImplementedError

    def H4(self, sigma, n):
        raise NotImplementedError
