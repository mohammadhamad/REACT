# https://realpython.com/linear-programming-python/
# https://realpython.com/linear-programming-python/#using-pulp --> Example2
from scipy.optimize import linprog
from gekko import GEKKO
from pulp import *
import random
from response_set_generation import *

def __elemToResponse2(element: ET.Element):
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
        
        #applyAt_interpreted = eval(applyAt) if not "Asset" in applyAt else applyAt

        print(action, precondition, applyAt, stopCondition, "[", w_A, A, w_Perf, Perf, "], [", w_S, S, w_F, F, w_O, O, w_P, P, "]")

        #return Response(Countermeasure[str(action).split('.')[-1]], precondition, Asset[str(applyAt_interpreted).split('.')[-1]], \
        #    int(stopCondition), [float(w_A), int(A), float(w_Perf), int(Perf)], \
        #    [float(w_S), int(S), float(w_F), int(F), float(w_O), int(O), float(w_P), int(P)])

def main():
    """
    f = [-1, -2]
    A = [[ 2,  1],  
         [-4,  5],
         [ 1, -2]]
    b = [20,
         10,
          2]
    Aeq = [[-1, 5]]
    beq = [15]

    bnd = [(0, float("inf")),
           (0, float("inf"))]

    opt = linprog(c=f, A_ub=A, b_ub=b,
                  A_eq=Aeq, b_eq=beq, bounds=bnd,
                  method="revised simplex")

    print(opt.fun)
    print(opt.x)
    

    f = [101,101,11,11,101,11,101,200,200,2,11,20,0,0,1,1,0,10,2,101,20,20,101,110]
    A = [[101,101,11,11,101,11,101,200,200,2,11,20,0,0,1,1,0,10,2,101,20,20,101,110]]
    b = [4]
    Aeq = [[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]]
    beq = [1]
    bnd = [(0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),
           (0, 1),]
    opt = linprog(c=f, A_ub=A, b_ub=b,
                  A_eq=Aeq, b_eq=beq, bounds=bnd,
                  method="revised simplex")

    print(opt.fun)
    print(opt.x)
    print(opt.message)
    print(opt.status)
"""
    """
    m = GEKKO(remote=False)
    c = [0,1]
    A = [[-1,1],[3,2],[2,3]]
    b = [1,12,12]
    z = m.Array(m.Var,2,integer=True,lb=0)
    m.qobj(c,x=z,otype='max')
    m.axb(A,b,x=z,etype='<=')
    m.options.SOLVER = 1
    m.solve()
    print('Objective: ', -m.options.OBJFCNVAL)
    print('x: ', z[0].value[0])
    print('y: ', z[1].value[0])
    """
    """
    # Create the model
    model = LpProblem(name="small-problem", sense=LpMaximize)

    # Initialize the decision variables: x is integer, y is continuous
    x = LpVariable(name="x", lowBound=0, cat="Integer")
    y = LpVariable(name="y", lowBound=0)

    # Add the constraints to the model
    model += (2 * x + y <= 20, "red_constraint")
    model += (4 * x - 5 * y >= -10, "blue_constraint")
    model += (-x + 2 * y >= -2, "yellow_constraint")
    model += (-x + 5 * y == 15, "green_constraint")

    # Add the objective function to the model
    model += lpSum([x, 2 * y])

    # Solve the problem
    status = model.solve(solver=GLPK(msg=False))

    print(model.objective.value(), x.value(), y.value())
    """

    """
    A = [101,101,11,11,101,11,101,200,200,2,11,20,0,0,1,1,0,10,2,101,20,20,101,110]
    f = [101,101,11,11,101,11,101,200,200,2,11,20,0,0,1,1,0,10,2,101,20,20,101,110]
    b = [4]
    beq = [1]

    model = LpProblem(name="small-problem", sense=LpMinimize)
    x_vars = {i:LpVariable(cat=LpBinary, name="x_{0}".format(i)) for i in range(len(f))}

    cos1 = LpConstraint(e=lpSum(A[i]*x_vars[i] for i in range(len(f))), sense=LpConstraintLE, rhs=b[0], name="constraint_0")
    model.addConstraint(cos1)

    cos2 = LpConstraint(e=lpSum(x_vars[i] for i in range(len(f))), sense=LpConstraintEQ, rhs=beq[0], name="constraint_1")
    model.addConstraint(cos2)

    objective = lpSum(x_vars[i] * f[i] for i in range(len(f)))
    model.setObjective(objective)

    status = model.solve(solver=GLPK(msg=False))
    print(model.objective.value())
    for x in x_vars.values():
        print(x.name, x.value())
    """

    import xml.etree.ElementTree as ET

    #tree = ET.parse('responseSet_Generic.xml')
    #root = tree.getroot()
    #for child_response in root:
    #    print("===", list(list(child_response)[4])[0].text)
    #    for child_item in child_response:
    #        print(child_item.tag, "\t", child_item.text)
    #        if child_item.tag == "cost":
    #            for childchild in child_item:
    #                print(childchild.tag, "\t", childchild.text)
    #        if child_item.tag == "benefit":
    #            for childchild in child_item:
    #                print(childchild.tag, "\t", childchild.text)

    #tree = ET.parse('dynamic_updated_Parameters/test.xml')
    #root = tree.getroot()
    #for child_response in root:
    #    __elemToResponse2(child_response)
    #    if child_response[0].text == "Countermeasure.Introduce_Honeypot" and child_response[2].text == "Asset.Central_Vehicle_Gateway":
    #        print(child_response[0].text, child_response[2].text)
    #        child_response[0].text = "test.dummy"
    #        tree.write('dynamic_updated_Parameters/test.xml')

    #i_rand = Intrusion(Asset.OBD_II, Asset.DoIP, AttackResult.Denial_Of_Service, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    #rsg = ResponseSet()
    #rsg.createResponseSet(i_rand)
    #rsg.__ResponseSet_Generic(i_rand)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass