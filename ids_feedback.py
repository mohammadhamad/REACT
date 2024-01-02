from ref_architecture import *
from intrusion import *
from response import *
from response_set_generation import ResponseSet
from risk_assessment import RiskEvaluation
import xml.etree.ElementTree as ET
from random import uniform

class IDSFeedback:
    @staticmethod
    def _reduceHEAVENS_single(param):
        if param == 100:
            return 10
        elif param == 10:
            return 1
        elif param == 1:
            return 0
        elif param == 0:
            return 0

    @staticmethod
    def _reduceHEAVENS(S, F, O, P):
        new_S = IDSFeedback._reduceHEAVENS_single(S)
        new_F = IDSFeedback._reduceHEAVENS_single(F)
        new_O = IDSFeedback._reduceHEAVENS_single(O)
        new_P = IDSFeedback._reduceHEAVENS_single(P)
        return new_S, new_F, new_O, new_P

    @staticmethod
    def _shuffleWeightsValues(w_S, w_F, w_O, w_P):
        r = round(uniform(0.8, 1.2), 2)
        return r * w_S, r * w_F, r * w_O, r * w_P

    @staticmethod
    def _readResponse(intrusion: Intrusion, response: Response, root_path, param="SFOP"):
        _S = 0
        _F = 0
        _O = 0
        _P = 0
        UseSFOP = True if param == "SFOP" else False
        Found = False
        attackResult = intrusion.attack_result
        attack_result_responseSet = {
            AttackResult.Falsify_Alter_Information: "responseSet_Falsify_Alter_Information.xml",
            AttackResult.Falsify_Alter_Timing: "responseSet_Falsify_Alter_Timing.xml",
            AttackResult.Information_Disclosure: "responseSet_Information_Disclosure.xml",
            AttackResult.Falsify_Alter_Behavior: "responseSet_Falsify_Alter_Behavior.xml",
            AttackResult.Denial_Of_Service: "responseSet_Denial_Of_Service.xml"
        }
        tree = ET.parse(root_path + attack_result_responseSet[attackResult])
        root = tree.getroot()
        for child_response in root:
            applyAt = child_response[2].text
            applyAt_interpreted = eval(applyAt) if not "Asset" in applyAt else applyAt
            #print(child_response[0].text, applyAt_interpreted, "\t", str(response.action), str(response.applyAt))
            if child_response[0].text == str(response.action) and str(applyAt_interpreted) == str(response.applyAt):
                Found = True
                _S = int(child_response[5][1].text) if UseSFOP else float(child_response[5][0].text)
                _F = int(child_response[5][3].text) if UseSFOP else float(child_response[5][2].text)
                _O = int(child_response[5][5].text) if UseSFOP else float(child_response[5][4].text)
                _P = int(child_response[5][7].text) if UseSFOP else float(child_response[5][6].text)
        if not Found:
            tree = ET.parse(root_path + "responseSet_Generic.xml")
            root = tree.getroot()
            for child_response in root:
                applyAt = child_response[2].text
                applyAt_interpreted = eval(applyAt) if not "Asset" in applyAt else applyAt
                #print(child_response[0].text, applyAt_interpreted, "\t", str(response.action), str(response.applyAt))
                if child_response[0].text == str(response.action) and str(applyAt_interpreted) == str(response.applyAt):
                    _S = int(child_response[5][1].text) if UseSFOP else float(child_response[5][0].text)
                    _F = int(child_response[5][3].text) if UseSFOP else float(child_response[5][2].text)
                    _O = int(child_response[5][5].text) if UseSFOP else float(child_response[5][4].text)
                    _P = int(child_response[5][7].text) if UseSFOP else float(child_response[5][6].text)
        #print(_S, _F, _O, _P)
        return _S, _F, _O, _P

    @staticmethod
    def _writeResponse(intrusion: Intrusion, response: Response, root_path, _S, _F, _O, _P, param="SFOP"):
        Found = False
        UseSFOP = True if param == "SFOP" else False
        attackResult = intrusion.attack_result
        attack_result_responseSet = {
            AttackResult.Falsify_Alter_Information: "responseSet_Falsify_Alter_Information.xml",
            AttackResult.Falsify_Alter_Timing: "responseSet_Falsify_Alter_Timing.xml",
            AttackResult.Information_Disclosure: "responseSet_Information_Disclosure.xml",
            AttackResult.Falsify_Alter_Behavior: "responseSet_Falsify_Alter_Behavior.xml",
            AttackResult.Denial_Of_Service: "responseSet_Denial_Of_Service.xml"
        }
        tree = ET.parse(root_path + attack_result_responseSet[attackResult])
        root = tree.getroot()
        for child_response in root:
            applyAt = child_response[2].text
            applyAt_interpreted = eval(applyAt) if not "Asset" in applyAt else applyAt
            #print(child_response[0].text, applyAt_interpreted, "\t", str(response.action), str(response.applyAt))
            if child_response[0].text == str(response.action) and str(applyAt_interpreted) == str(response.applyAt):
                Found = True
                child_response[5][1 if UseSFOP else 0].text = str(_S)
                child_response[5][3 if UseSFOP else 2].text = str(_F)
                child_response[5][5 if UseSFOP else 4].text = str(_O)
                child_response[5][7 if UseSFOP else 6].text = str(_P)
                tree.write(root_path + attack_result_responseSet[attackResult])
        if not Found:
            tree = ET.parse(root_path + "responseSet_Generic.xml")
            root = tree.getroot()
            for child_response in root:
                applyAt = child_response[2].text
                applyAt_interpreted = eval(applyAt) if not "Asset" in applyAt else applyAt
                #print(child_response[0].text, applyAt_interpreted, "\t", str(response.action), str(response.applyAt))
                if child_response[0].text == str(response.action) and str(applyAt_interpreted) == str(response.applyAt):
                    child_response[5][1 if UseSFOP else 0].text = str(_S)
                    child_response[5][3 if UseSFOP else 2].text = str(_F)
                    child_response[5][5 if UseSFOP else 4].text = str(_O)
                    child_response[5][7 if UseSFOP else 6].text = str(_P)
                    tree.write(root_path + "responseSet_Generic.xml")

    @staticmethod
    def _reduceParameters(intrusion: Intrusion, response: Response):
        old_S, old_F, old_O, old_P = IDSFeedback._readResponse(intrusion, response, "dynamic_updated_Parameters/")
        new_S, new_F, new_O, new_P = IDSFeedback._reduceHEAVENS(old_S, old_F, old_O, old_P)
        #print(new_S, new_F, new_O, new_P)
        IDSFeedback._writeResponse(intrusion, response, "dynamic_updated_Parameters/", new_S, new_F, new_O, new_P)

    @staticmethod
    def _restoreParameters(intrusion: Intrusion, response: Response):
        orig_S, orig_F, orig_O, orig_P = IDSFeedback._readResponse(intrusion, response, "initial_Parameters/")
        IDSFeedback._writeResponse(intrusion, response, "dynamic_updated_Parameters/", orig_S, orig_F, orig_O, orig_P)

    @staticmethod
    def _shuffleWeights(intrusion: Intrusion, response: Response):
        w_S, w_F, w_O, w_P = IDSFeedback._readResponse(intrusion, response, "initial_Parameters/", "w")
        w_S, w_F, w_O, w_P = IDSFeedback._shuffleWeightsValues(w_S, w_F, w_O, w_P)
        IDSFeedback._writeResponse(intrusion, response, "dynamic_updated_Parameters/", w_S, w_F, w_O, w_P, "w")

    @staticmethod
    def _manualCheck():
        prec_met = input("Was the response successful? (y or n): ")
        if prec_met == 'Y' or prec_met == 'y':
            return True
        else:
            return False

    @staticmethod
    def idsFeedback(intrusion: Intrusion, response: Response, dataset=None):

        # If dataset != None then automatically the success-case gets selected (for the follow-up actions)
        # If it is None, the if-else-condition will be executed based on the manual check
        if dataset != None or IDSFeedback._manualCheck():
            IDSFeedback._restoreParameters(intrusion, response)
            IDSFeedback._shuffleWeights(intrusion, response)
            return True
        else:
            IDSFeedback._reduceParameters(intrusion, response)
            return False