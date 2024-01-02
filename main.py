from re import I
from unicodedata import name
from ref_architecture import *
from intrusion import *
from response import *
from risk_assessment import *
from response_set_generation import *
from ids_dummy import *
from optimal_response_selection import *
from check_precondition import *
from ids_feedback import *

AUTOMATIC_USAGE = True

def main():
    # Counter, which intrusion of system_state.xml should be used
    intrusion_no = 0
    main_response_mitigates = False

    # Create an (dummy)-IDS
    ids = IDS()

    if AUTOMATIC_USAGE:
        # Create an empty object and read the velocity later
        v1 = DynamicSystemState()
    else:
        # Ask the user for the vehicle speed
        v1 = DynamicSystemState(float(input("Vehicle Speed in km/h: ")))

    # Create a TARA object (=read all TARA XMLs) and consider the vehicle speed (either manual from above or from XML)
    tara1 = RiskEvaluation(v1)

    # Repeat until XML is over, or user provides no more data
    while(True):
        if AUTOMATIC_USAGE:
            # Read the n-th intrusion data from the XML file
            i_rand = ids.getDetectedIntrusionXml(intrusion_no)
        else:
            # Ask the user to input the data
            i_rand = ids.getDetectedIntrusionManualGUI()

            # Uncomment, to generate a random attack (only for testing purposes)
            # i_rand = ids.getDetectedIntrusionDummy()

        # If no intrusion was selected, stop the program correctly
        if i_rand == None:
            exit()

        # Make a risk evaluation of the detected intrusion, under consideration of the dynamic vehicle state
        i_rand.impact = tara1.RiskEvaluation(i_rand, v1)

        # Create an response set object (rsg) and fill the actual list of responses (rs)
        rsg = ResponseSet()
        rs = rsg.createResponseSet(i_rand)

        # Create a response_selection object
        response_selection = OptimalResponse()
    
        # Repeat, until precondition is fulfilled
        while(True):

            # Get the optimal response (res) and its index in the response set. If no method is mentioned, the user will be asked
            res, index = response_selection.getOptimalResponse(tara1, rs, i_rand, v1, "LP_max_benefit")
            if res != None:
                # Check the precondition (semi-automatically)
                if PreconditionCheck.checkPrecondition(i_rand, res):
                    # Adapt parameters of the XML files, depending on the precondition check
                    main_response_mitigates = IDSFeedback.idsFeedback(i_rand, res)
                    break
                else:
                    # If precondition is not fulfilled, delete the response from the response set
                    del rs[index]
            else:
                break

        if main_response_mitigates:
            print("\n\nFollow up actions:")

            # Define, how many responses for each attack result should follow up
            loop_repeats = {
                AttackResult.Falsify_Alter_Information: 2,
                AttackResult.Falsify_Alter_Timing: 2,
                AttackResult.Information_Disclosure: 3,
                AttackResult.Falsify_Alter_Behavior: 4,
                AttackResult.Denial_Of_Service: 4,
            }

            # Create an response set object (generic_rsg) and fill the actual list of generic-only responses (generic_rs)
            generic_rsg = ResponseSet()
            generic_rs = generic_rsg.createResponseSet(i_rand, "generic")

            # Create a response selection object
            response_selection_generic = OptimalResponse()

            # Repeat as often as defined in the dictionary a few lines above
            for i in range(loop_repeats[i_rand.attack_result]):

                # Identify the best result
                res, index = response_selection_generic.getOptimalResponse(tara1, generic_rs, i_rand, v1, "LP_min_cost")

                if res != None:
                    # No precondition check is necessary, since only generic Responses are selected

                    # Print the action, and adapt Feedback "always successful" to get fluctuations in the result
                    print("Action no.", i+1, ":", res.action, "at", res.applyAt)
                    IDSFeedback.idsFeedback(i_rand, res, "generic")
                    del generic_rs[index]
                else:
                    break

        # Use next intrusion from the XML file if intrusion was mitigated
        intrusion_no = intrusion_no + 1 if main_response_mitigates else intrusion_no
            


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass