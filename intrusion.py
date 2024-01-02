from ref_architecture import *

class Intrusion:
    def __init__(self, src: Asset, dst: Asset, ar: AttackResult, im, tara:list):
        self.source         = src
        self.destination    = dst
        self.attack_result  = ar
        self.impact         = im

        self._w_S           = tara[0]
        self._S             = tara[1]
        self._w_F           = tara[2]
        self._F             = tara[3]
        self._w_O           = tara[4]
        self._O             = tara[5]
        self._w_P           = tara[6]
        self._P             = tara[7]
        self._w_E           = tara[8]
        self._E             = tara[9]
