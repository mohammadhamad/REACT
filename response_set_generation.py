from intrusion import Intrusion
from ref_architecture import *
from response import Response
from risk_assessment import HEAVENS
import xml.etree.ElementTree as ET

class ResponseSet:
    def __init__(self):
        self.responseSet = []

    # Helper function to calculate the cost of a response
    def __calculateCost(self, w_A, A, w_P, P):
        return w_A * A + w_P * P

    # Helper function to calculate the benefit of a response
    def __calculateBenefit(self, heavens_param:HEAVENS):
        return heavens_param._w_S * heavens_param._S + \
            heavens_param._w_F * heavens_param._F + \
            heavens_param._w_O * heavens_param._O + \
            heavens_param._w_P * heavens_param._P

    # Converts a single XML element into a Response object and interprets dynamic values
    def __elemToResponse(self, element: ET.Element, intrusion: Intrusion):
        action = list(element)[0].text
        precondition = list(element)[1].text
        applyAt = list(element)[2].text
        stopCondition = list(element)[3].text
        w_A = list(list(element)[4])[0].text
        A = list(list(element)[4])[1].text
        w_Perf = list(list(element)[4])[2].text
        Perf = list(list(element)[4])[3].text
        w_S = list(list(element)[5])[0].text
        S = list(list(element)[5])[1].text
        w_F = list(list(element)[5])[2].text
        F = list(list(element)[5])[3].text
        w_O = list(list(element)[5])[4].text
        O = list(list(element)[5])[5].text
        w_P = list(list(element)[5])[6].text
        P = list(list(element)[5])[7].text
        
        applyAt_interpreted = eval(applyAt) if not "Asset" in applyAt else applyAt

        #print(action, precondition, applyAt_interpreted, stopCondition, "[", w_A, A, w_Perf, Perf, "], [", w_S, S, w_F, F, w_O, O, w_P, P, "]")

        return Response(Countermeasure[str(action).split('.')[-1]], precondition, Asset[str(applyAt_interpreted).split('.')[-1]], \
            int(stopCondition), [float(w_A), int(A), float(w_Perf), int(Perf)], \
            [float(w_S), int(S), float(w_F), int(F), float(w_O), int(O), float(w_P), int(P)])

    def __ResponseSet_Generic(self, intrusion: Intrusion):
        tree = ET.parse('dynamic_updated_Parameters/responseSet_Generic.xml')
        root = tree.getroot()
        for child_response in root:
            self.responseSet.append(self.__elemToResponse(child_response, intrusion))

    def __ResponseSet_Falsify_Alter_Information(self, intrusion: Intrusion):
        self.__ResponseSet_Generic(intrusion)

        tree = ET.parse('dynamic_updated_Parameters/responseSet_Falsify_Alter_Information.xml')
        root = tree.getroot()
        for child_response in root:
            self.responseSet.append(self.__elemToResponse(child_response, intrusion))

    def __ResponseSet_Falsify_Alter_Timing(self, intrusion: Intrusion):
        self.__ResponseSet_Generic(intrusion)

        tree = ET.parse('dynamic_updated_Parameters/responseSet_Falsify_Alter_Timing.xml')
        root = tree.getroot()
        for child_response in root:
            self.responseSet.append(self.__elemToResponse(child_response, intrusion))

    def __ResponseSet_Information_Disclosure(self, intrusion: Intrusion):
        self.__ResponseSet_Generic(intrusion)

        tree = ET.parse('dynamic_updated_Parameters/responseSet_Information_Disclosure.xml')
        root = tree.getroot()
        for child_response in root:
            self.responseSet.append(self.__elemToResponse(child_response, intrusion))

    def __ResponseSet_Falsify_Alter_Behavior(self, intrusion: Intrusion):
        self.__ResponseSet_Generic(intrusion)

        tree = ET.parse('dynamic_updated_Parameters/responseSet_Falsify_Alter_Behavior.xml')
        root = tree.getroot()
        for child_response in root:
            self.responseSet.append(self.__elemToResponse(child_response, intrusion))
    
    def __ResponseSet_Denial_Of_Service(self, intrusion: Intrusion):
        self.__ResponseSet_Generic(intrusion)

        tree = ET.parse('dynamic_updated_Parameters/responseSet_Denial_Of_Service.xml')
        root = tree.getroot()
        for child_response in root:
            self.responseSet.append(self.__elemToResponse(child_response, intrusion))
    
    # Public function, to return the response set, based on the detected intrusion
    def createResponseSet(self, intrusion: Intrusion, dataset = None):

        # If no specific dataset is selected -> Standard use case and fill complete response set
        if dataset is None:
            attackResult = intrusion.attack_result
            attack_result_responseSet = {
                AttackResult.Falsify_Alter_Information: self.__ResponseSet_Falsify_Alter_Information,
                AttackResult.Falsify_Alter_Timing: self.__ResponseSet_Falsify_Alter_Timing,
                AttackResult.Information_Disclosure: self.__ResponseSet_Information_Disclosure,
                AttackResult.Falsify_Alter_Behavior: self.__ResponseSet_Falsify_Alter_Behavior,
                AttackResult.Denial_Of_Service: self.__ResponseSet_Denial_Of_Service
            }
            attack_result_responseSet[attackResult](intrusion)

        # If a "dataset" is not None, only Generic dataset will be loaded
        else:
            self.__ResponseSet_Generic(intrusion)

        # Calculate cost and benefit for the special action "No Action", where the cost = intrusion.impact
        for res in self.responseSet:
            if res.action == Countermeasure.No_Action:
                res.cost = intrusion.impact
                res.benefit = self.__calculateBenefit(HEAVENS(res._w_S, res._S, res._w_F, res._F, res._w_O, res._O, res._w_P, res._P))
            else:
                res.cost = self.__calculateCost(res._w_A, res._A, res._w_Perf, res._Perf)
                res.benefit = self.__calculateBenefit(HEAVENS(res._w_S, res._S, res._w_F, res._F, res._w_O, res._O, res._w_P, res._P))
        return self.responseSet