from ref_architecture import *

class Response:
    def __init__(self, act: Countermeasure, prec, appl: Asset, stop, cos:list, ben:list):
        self.action         = act
        self.precondition   = prec
        self.applyAt        = appl
        self.stopCondition  = stop
        self.cost           = 0
        self.benefit        = 0

        self._w_A           = cos[0]
        self._A             = cos[1]
        self._w_Perf        = cos[2]
        self._Perf          = cos[3]

        self._w_S           = ben[0]
        self._S             = ben[1]
        self._w_F           = ben[2]
        self._F             = ben[3]
        self._w_O           = ben[4]
        self._O             = ben[5]
        self._w_P           = ben[6]
        self._P             = ben[7]