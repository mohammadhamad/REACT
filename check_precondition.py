from ref_architecture import *
from intrusion import *
from response import *

class PreconditionCheck:

    # Private helper function to print intrusion and response data
    @staticmethod
    def _printData(intrusion: Intrusion, response: Response):
        print("Intrusion:\n==========")
        print('\tSource =', intrusion.source.name, '\n\tDestination =', intrusion.destination.name, '\n\tAttack =', \
            intrusion.attack_result.name, '\n\tImpact =', intrusion.impact)
        print("Response:\n=========")
        print('\tPerform', response.action.name, 'at', response.applyAt.name, 'with cost', response.cost, 'and benefit', response.benefit)

    # Helper function to manually ask the user, if the precondition is fulfilled
    @staticmethod
    def _manualCheck():
        prec_met = input("Are preconditions met? (y or n): ")
        if prec_met == 'Y' or prec_met == 'y':
            return True
        else:
            return False

    # Helper function to check the precondition automatically
    def _semiautomaticCheck(intrusion: Intrusion, response: Response):
        if response.precondition == None or response.precondition == "None":
            return PreconditionCheck._manualCheck()
        else:
            print("Automatic Precondition Check:\n=============================")
            print("\tResult:", eval(response.precondition), "\n\n")
            return eval(response.precondition)

    # Public function to check the precondition semi-automatically
    @staticmethod
    def checkPrecondition(intrusion: Intrusion, response: Response):
        PreconditionCheck._printData(intrusion, response)
        return PreconditionCheck._semiautomaticCheck(intrusion, response)