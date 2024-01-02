from ref_architecture import *
from risk_assessment import *
from functools import reduce
from operator import add, itemgetter
from pulp import *

# pip install pulp
# sudo apt-get install glpk-utils

AMOUNT_OF_CRITERIA = 6
SMALL_NUMBER = 0.01
RHO = 3

class OptimalResponse:

    # Return the optimal response, using the adapted SAW method
    def _saw(this, riskEval: RiskEvaluation, responseSet: list, intrusion: Intrusion, vehicleState: DynamicSystemState):

         # weighted_resp[response no][criteria] with criteria = normalized elements of [A, Perf, S, F, O, P]
        weighted_resp = [[0]*AMOUNT_OF_CRITERIA for i in range(len(responseSet))]

        # Find the maximum S, F, O and P of the current response set
        max_S = 0
        max_F = 0
        max_O = 0
        max_P = 0
        for i in range(len(responseSet)):
            max_S = (responseSet[i]._S * responseSet[i]._w_S) if (responseSet[i]._S * responseSet[i]._w_S) > max_S else max_S
            max_F = (responseSet[i]._F * responseSet[i]._w_F) if (responseSet[i]._F * responseSet[i]._w_F) > max_F else max_F
            max_O = (responseSet[i]._O * responseSet[i]._w_O) if (responseSet[i]._O * responseSet[i]._w_O) > max_O else max_O
            max_P = (responseSet[i]._P * responseSet[i]._w_P) if (responseSet[i]._P * responseSet[i]._w_P) > max_P else max_P

        for i in range(len(responseSet)):

            # Assign normalized values for cost on availability
            if(responseSet[i]._A == 0):
                weighted_resp[i][0] = 1
            else:
                weighted_resp[i][0] = SMALL_NUMBER / (responseSet[i]._A * responseSet[i]._w_A)

            # Assign normalized values for cost on performance
            if(responseSet[i]._Perf == 0):
                weighted_resp[i][1] = 1
            else:
                weighted_resp[i][1] = SMALL_NUMBER / (responseSet[i]._Perf * responseSet[i]._w_Perf)

            # Assign normalized values for benefit of safety
            weighted_resp[i][2] = (responseSet[i]._w_S * responseSet[i]._S)/(max_S)

            # Assign normalized values for benefit of financial
            weighted_resp[i][3] = (responseSet[i]._w_F * responseSet[i]._F)/(max_F)

            # Assign normalized values for benefit of operational
            weighted_resp[i][4] = (responseSet[i]._w_O * responseSet[i]._O)/(max_O)

            # Assign normalized values for benefit of privacy
            weighted_resp[i][5] = (responseSet[i]._w_P * responseSet[i]._P)/(max_P)
        
        preference_value = [None] * len(responseSet)
        for i in range(len(responseSet)):
            # Calculate the preference value, according to the standard SAW method
            preference_value[i] = reduce(add, [weighted_resp[i][0], weighted_resp[i][1], weighted_resp[i][2], \
                weighted_resp[i][3], weighted_resp[i][4], weighted_resp[i][5]])

        # Create 5 dummy intrusions, each with the same assets, but a different intrusion result. Needed, to get TARA
        # Parameters for other intrusion results. This is necessary to apply the adapted SAW method
        dummy_intr1 = Intrusion(intrusion.source, intrusion.destination, AttackResult.Falsify_Alter_Information, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        tara1 = riskEval
        dummy_intr1.impact = tara1.RiskEvaluation(dummy_intr1, vehicleState)
        dummy_intr2 = Intrusion(intrusion.source, intrusion.destination, AttackResult.Falsify_Alter_Timing, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        tara2 = riskEval
        dummy_intr2.impact = tara2.RiskEvaluation(dummy_intr2, vehicleState)
        dummy_intr3 = Intrusion(intrusion.source, intrusion.destination, AttackResult.Information_Disclosure, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        tara3 = riskEval
        dummy_intr3.impact = tara3.RiskEvaluation(dummy_intr3, vehicleState)
        dummy_intr4 = Intrusion(intrusion.source, intrusion.destination, AttackResult.Falsify_Alter_Behavior, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        tara4 = riskEval
        dummy_intr4.impact = tara4.RiskEvaluation(dummy_intr4, vehicleState)
        dummy_intr5 = Intrusion(intrusion.source, intrusion.destination, AttackResult.Denial_Of_Service, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        tara5 = riskEval
        dummy_intr5.impact = tara5.RiskEvaluation(dummy_intr5, vehicleState)

        # Calculate weighted intrusion sum of S. Array parameters [0] = w_S; Array parameters [1] = S
        weighted_intr_sum_S = tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[0] * \
            tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[1] + \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[0] * \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[1] + \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[0] * \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[1] + \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[0] * \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[1] + \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[0] * \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[1]
        # Calculate weighted intrusion sum of F. Array parameters [2] = w_F; Array parameters [3] = F
        weighted_intr_sum_F = tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[2] * \
            tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[3] + \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[2] * \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[3] + \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[2] * \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[3] + \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[2] * \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[3] + \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[2] * \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[3]
        # Calculate weighted intrusion sum of O. Array parameters [4] = w_O; Array parameters [5] = O
        weighted_intr_sum_O = tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[4] * \
            tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[5] + \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[4] * \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[5] + \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[4] * \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[5] + \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[4] * \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[5] + \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[4] * \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[5]
        # Calculate weighted intrusion sum of P. Array parameters [6] = w_F; Array parameters [7] = P
        weighted_intr_sum_P = tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[6] * \
            tara1._init_TARA_Falsify_Alter_Information.get(intrusion.destination)[7] + \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[6] * \
            tara2._init_TARA_Falsify_Alter_Timing.get(intrusion.destination)[7] + \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[6] * \
            tara3._init_TARA_Information_Disclosure.get(intrusion.destination)[7] + \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[6] * \
            tara4._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination)[7] + \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[6] * \
            tara5._init_TARA_Denial_Of_Service.get(intrusion.destination)[7]

        tara_to_use = {
            AttackResult.Falsify_Alter_Information: riskEval._init_TARA_Falsify_Alter_Information.get(intrusion.destination),
            AttackResult.Falsify_Alter_Timing: riskEval._init_TARA_Falsify_Alter_Timing.get(intrusion.destination),
            AttackResult.Information_Disclosure: riskEval._init_TARA_Information_Disclosure.get(intrusion.destination),
            AttackResult.Falsify_Alter_Behavior: riskEval._init_TARA_Falsify_Alter_Behavior.get(intrusion.destination),
            AttackResult.Denial_Of_Service: riskEval._init_TARA_Denial_Of_Service.get(intrusion.destination),
        }
        
        # Calculate the weighted intrusion as a sum of: Current w_{S, F, O, P} * {S, F, O, P} divided by weighted intrusion sum {S, F, O, P}
        weighted_intr = tara_to_use[intrusion.attack_result][0] * tara_to_use[intrusion.attack_result][1] / weighted_intr_sum_S \
            if weighted_intr_sum_S != 0 else 0
        weighted_intr += tara_to_use[intrusion.attack_result][2] * tara_to_use[intrusion.attack_result][3] / weighted_intr_sum_F \
            if weighted_intr_sum_F != 0 else 0
        weighted_intr += tara_to_use[intrusion.attack_result][4] * tara_to_use[intrusion.attack_result][5] / weighted_intr_sum_O \
            if weighted_intr_sum_O != 0 else 0
        weighted_intr += tara_to_use[intrusion.attack_result][6] * tara_to_use[intrusion.attack_result][7] / weighted_intr_sum_P \
            if weighted_intr_sum_P != 0 else 0

        # TODO: Something like: RHO += vehicleSpeed
        argmax_value = 0
        argmax_found = False

        # Find maximum value of the preference, under consideration of the constraint weighted_intr * RHO
        for i in range(len(responseSet)):
            if preference_value[i] < (weighted_intr * RHO):
                argmax_value = i if argmax_value == 0 else argmax_value
                if preference_value[i] >= preference_value[argmax_value]:
                    argmax_value = i
                    argmax_found = True
        
        # Return the response, or None, if no reponse is applicable
        if argmax_found:
            return responseSet[argmax_value], argmax_value
        else:
            return None, None

    # Return the optimal response, using the LP method with minimum cost objective
    def _lp_min_cost(this, riskEval: RiskEvaluation, responseSet: list, intrusion: Intrusion, vehicleState: DynamicSystemState):
        f = []      # Objective function parameters
        A = []      # Contains parameters for first constraint (= cost values)
        b = []      # Contains later the Impact of the intrusion
        beq = []    # Contains later a one of the second constraint
        result = []

        # Fill the two lists with costs of the response
        for resp in responseSet:
            f.append(resp.cost)
            A.append(resp.cost)

        b.append(intrusion.impact)
        beq.append(1)

        # Create the LP-Model and define the solution variables as x_0, x_1, ... x_n. This contains later the optimal response
        model = LpProblem(name="LP_Min_Cost", sense=LpMinimize)
        x_vars = {i:LpVariable(cat=LpBinary, name="x_{0}".format(i)) for i in range(len(responseSet))}

        # Set the first constraint: sum of A_i * x_i <= b
        cos1 = LpConstraint(e=lpSum(A[i]*x_vars[i] for i in range(len(responseSet))), sense=LpConstraintLE, rhs=b[0], name="constraint_0")
        model.addConstraint(cos1)

        # Set the second constraint: sum of x must be one
        cos2 = LpConstraint(e=lpSum(x_vars[i] for i in range(len(responseSet))), sense=LpConstraintEQ, rhs=beq[0], name="constraint_1")
        model.addConstraint(cos2)

        # Define the objective function: sum of f_i * x_i must be minimized (see minimization argument in the model initialization)
        objective = lpSum(x_vars[i] * f[i] for i in range(len(f)))
        model.setObjective(objective)

        # Solve the model, using GLPK and don't show debug messages
        status = model.solve(solver=GLPK(msg=False))
        
        for x in x_vars.values():
            result.append(x.value())

        # Find the argmax of the result
        argmax, max_val = max(enumerate(result), key=itemgetter(1))

        # If the optimization was successful return the reponse, else, return None
        if model.status == 1:
            return responseSet[argmax], argmax
        else:
            return None, None

    # Return the optimal response, using the LP method with maximum benefit objective
    def _lp_max_benefit(this, riskEval: RiskEvaluation, responseSet: list, intrusion: Intrusion, vehicleState: DynamicSystemState):
        f = []      # Objective function parameters
        A = []      # Contains parameters for first constraint (= cost values)
        b = []      # Contains later the Impact of the intrusion
        beq = []    # Contains later a one of the second constraint
        result = []

        # Fill the two lists with costs and benefit of the response
        for resp in responseSet:
            f.append(resp.benefit)
            A.append(resp.cost)

        b.append(intrusion.impact)
        beq.append(1)

        # Create the LP-Model and define the solution variables as x_0, x_1, ... x_n. This contains later the optimal response
        model = LpProblem(name="LP_Max_Benefit", sense=LpMaximize)
        x_vars = {i:LpVariable(cat=LpBinary, name="x_{0}".format(i)) for i in range(len(responseSet))}

        # Set the first constraint: sum of A_i * x_i <= b
        cos1 = LpConstraint(e=lpSum(A[i]*x_vars[i] for i in range(len(responseSet))), sense=LpConstraintLE, rhs=b[0], name="constraint_1")
        model.addConstraint(cos1)

        # Set the second constraint: sum of x must be one
        cos2 = LpConstraint(e=lpSum(x_vars[i] for i in range(len(responseSet))), sense=LpConstraintEQ, rhs=beq[0], name="constraint_2")
        model.addConstraint(cos2)

        # Define the objective function: sum of f_i * x_i must be maximized (see maximize argument in the model initialization)
        objective = lpSum(x_vars[i] * f[i] for i in range(len(f)))
        model.setObjective(objective)

        # Solve the model, using GLPK and don't show debug messages
        status = model.solve(solver=GLPK(msg=False))
        
        for x in x_vars.values():
            result.append(x.value())

        # Find the argmax of the result
        argmax, max_val = max(enumerate(result), key=itemgetter(1))

        # If the optimization was successful return the reponse, else, return None
        if model.status == 1:
            return responseSet[argmax], argmax
        else:
            return None, None

    # Return the optimal response, using the mentioned method. If none is mentioned, the user will be asked
    def getOptimalResponse(this, riskEval: RiskEvaluation, responseSet: list, intrusion: Intrusion, vehicleState: DynamicSystemState, method=None):
        if method == None:
            while True:
                selection = input("Which method shall be used?\n1: SAW\n2: Linear Programming (min cost)\n3: Linear Programming (max benefit)\n")
                if selection != '' and int(selection) > 0 and int(selection) < 4:
                    method = 'SAW' if int(selection) == 1 else method
                    method = 'LP_min_cost' if int(selection) == 2 else method
                    method = 'LP_max_benefit' if int(selection) == 3 else method
                    break
        if method == 'SAW':
            return this._saw(riskEval, responseSet, intrusion, vehicleState)
        if method == 'LP_min_cost':
            return this._lp_min_cost(riskEval, responseSet, intrusion, vehicleState)
        if method == 'LP_max_benefit':
            return this._lp_max_benefit(riskEval, responseSet, intrusion, vehicleState)