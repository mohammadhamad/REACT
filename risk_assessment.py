from intrusion import Intrusion
from ref_architecture import *
import typing
import xml.etree.ElementTree as ET

class HEAVENS:
    def __init__(self, w_S, S, w_F, F, w_O, O, w_P, P):
        self._S = S
        self._F = F
        self._O = O
        self._P = P

        self._w_S = w_S
        self._w_F = w_F
        self._w_O = w_O
        self._w_P = w_P

class RiskEvaluation:
    def __init__(self, v_state: DynamicSystemState):

        # Fill dictionaries with the TARA parameters from the TARA xml files
        self._init_TARA_Falsify_Alter_Information = {}
        tree = ET.parse("dynamic_updated_Parameters/TARA_Falsify_Alter_Information.xml")
        root = tree.getroot()
        for asset in root:
            self._init_TARA_Falsify_Alter_Information[Asset[str(asset[0].text).split('.')[-1]]] = \
                [int(asset[1][0].text), int(asset[1][1].text), int(asset[1][2].text), int(asset[1][3].text),
                int(asset[1][4].text), int(asset[1][5].text), int(asset[1][6].text), int(asset[1][7].text)]
        
        self._init_TARA_Falsify_Alter_Timing = {}
        tree = ET.parse("dynamic_updated_Parameters/TARA_Falsify_Alter_Timing.xml")
        root = tree.getroot()
        for asset in root:
            self._init_TARA_Falsify_Alter_Timing[Asset[str(asset[0].text).split('.')[-1]]] = \
                [int(asset[1][0].text), int(asset[1][1].text), int(asset[1][2].text), int(asset[1][3].text),
                int(asset[1][4].text), int(asset[1][5].text), int(asset[1][6].text), int(asset[1][7].text)]

        self._init_TARA_Information_Disclosure = {}
        tree = ET.parse("dynamic_updated_Parameters/TARA_Information_Disclosure.xml")
        root = tree.getroot()
        for asset in root:
            self._init_TARA_Information_Disclosure[Asset[str(asset[0].text).split('.')[-1]]] = \
                [int(asset[1][0].text), int(asset[1][1].text), int(asset[1][2].text), int(asset[1][3].text),
                int(asset[1][4].text), int(asset[1][5].text), int(asset[1][6].text), int(asset[1][7].text)]
        
        self._init_TARA_Falsify_Alter_Behavior = {}
        tree = ET.parse("dynamic_updated_Parameters/TARA_Falsify_Alter_Behavior.xml")
        root = tree.getroot()
        for asset in root:
            self._init_TARA_Falsify_Alter_Behavior[Asset[str(asset[0].text).split('.')[-1]]] = \
                [int(asset[1][0].text), int(asset[1][1].text), int(asset[1][2].text), int(asset[1][3].text),
                int(asset[1][4].text), int(asset[1][5].text), int(asset[1][6].text), int(asset[1][7].text)]

        self._init_TARA_Denial_Of_Service = {}
        tree = ET.parse("dynamic_updated_Parameters/TARA_Denial_Of_Service.xml")
        root = tree.getroot()
        for asset in root:
            self._init_TARA_Denial_Of_Service[Asset[str(asset[0].text).split('.')[-1]]] = \
                [int(asset[1][0].text), int(asset[1][1].text), int(asset[1][2].text), int(asset[1][3].text),
                int(asset[1][4].text), int(asset[1][5].text), int(asset[1][6].text), int(asset[1][7].text)]
        self.vehicle_state = v_state

    def __TARA_Falsify_Alter_Information(self, asset: Asset):
        return self._init_TARA_Falsify_Alter_Information.get(asset)

    def __TARA_Falsify_Alter_Timing(self, asset: Asset):
        return self._init_TARA_Falsify_Alter_Timing.get(asset)

    def __TARA_Information_Disclosure(self, asset: Asset):
        return self._init_TARA_Information_Disclosure.get(asset)

    def __TARA_Falsify_Alter_Behavior(self, asset: Asset):
        return self._init_TARA_Falsify_Alter_Behavior.get(asset)

    def __TARA_Denial_Of_Service(self, asset: Asset):
        return self._init_TARA_Denial_Of_Service.get(asset)

    # Helper function to calculate TARA, using the HEAVENS method
    def __calc_TARA(self, HEAVENS_dict: typing.Dict[Asset, list]):
        return HEAVENS_dict[0] * HEAVENS_dict[1] + \
            HEAVENS_dict[2] * HEAVENS_dict[3] + \
            HEAVENS_dict[4] * HEAVENS_dict[5] + \
            HEAVENS_dict[6] * HEAVENS_dict[7]

    # Return the risk of an intrusion, considering the velocity
    def __calc_TARA_Environmental(self, intrusion: Intrusion, vehicle_state: DynamicSystemState):
        intrusion._w_E = 1
        if vehicle_state.VehicleSpeed < 30:
            intrusion._E = 0
        elif vehicle_state.VehicleSpeed < 50:
            intrusion._E = 1
        elif vehicle_state.VehicleSpeed < 75:
            intrusion._E = 10
        else:
            intrusion._E = 100
        return intrusion._w_E * intrusion._E

    # Calculate the static part of the TARA (=Apply HEAVENS)
    def __TARA(self, intrusion: Intrusion):
        asset = intrusion.destination
        attack_result = intrusion.attack_result
        attack_result_TARA = {
            AttackResult.Falsify_Alter_Information: self.__TARA_Falsify_Alter_Information,
            AttackResult.Falsify_Alter_Timing: self.__TARA_Falsify_Alter_Timing,
            AttackResult.Information_Disclosure: self.__TARA_Information_Disclosure,
            AttackResult.Falsify_Alter_Behavior: self.__TARA_Falsify_Alter_Behavior,
            AttackResult.Denial_Of_Service: self.__TARA_Denial_Of_Service
        }

        # Fill the individual HEAVENS parameters of the intrusion object
        intrusion._w_S = attack_result_TARA[attack_result](asset)[0]
        intrusion._S = attack_result_TARA[attack_result](asset)[1]
        intrusion._w_F = attack_result_TARA[attack_result](asset)[2]
        intrusion._F = attack_result_TARA[attack_result](asset)[3]
        intrusion._w_O = attack_result_TARA[attack_result](asset)[4]
        intrusion._O = attack_result_TARA[attack_result](asset)[5]
        intrusion._w_P = attack_result_TARA[attack_result](asset)[6]
        intrusion._P = attack_result_TARA[attack_result](asset)[7]

        return self.__calc_TARA(attack_result_TARA[attack_result](asset))

    # Public function to evaluate the risk, using static and dynamic methods
    def RiskEvaluation(self, intrusion: Intrusion, vehicle_state: DynamicSystemState):
        
        # Read the vehicle speed from XML.
        tree = ET.parse('dynamic_state.xml')
        root = tree.getroot()
        
        vehicle_state.VehicleSpeed = float(root[0].text)

        return self.__TARA(intrusion) + self.__calc_TARA_Environmental(intrusion, vehicle_state)
