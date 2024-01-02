Dynamic IRS for connected and autonomous vehicles
=========================================
## Contributors
The main author of this code is Michael Kühr.  This code was written  to demonstrate the research paper "REACT: Dynamic Intrusion Response System for Connected and Autonomous Vehicles." 

## System requirements
The following software is required in advance to use this IRS:

1. [Python](https://www.python.org/downloads/), Version 3.8.10 or higher. Install via `apt-get install python3`
2. [PuLP](https://coin-or.github.io/pulp/index.html), Version 2.6.0 or higher. Install via `pip install pulp`
3. [GLPK](https://www.gnu.org/software/glpk/), Version 4.65-2 or higher. Install via `apt-get install glpk-utils`

## Configuration

Since this software represents only an IRS, some data needs to be provided manually, which is normally provided by an IDS.

All the relevant data is stored inside [system_state.xml](./system_state.xml). It can be edited using any text editor. Since this IRS can not only handle a single intrusion but also cover stepping-stone attacks, multiple `state`s can be included, each representing one intrusion to solve. For each `state`, the following information is required:

* `infected_asset`: This represents the asset that is infected by a computer virus/hacker. It can be any asset from the enum `Asset` of [ref_architecture.py](./ref_architecture.py). Please refer to the standardized syntax: `Asset.<your asset>`, where `<your asset>` can be replaced by any `Asset`.
* `affected_asset`: This represents the asset that is under attack / which is the victim of an intrusion. It can be any asset from the enum `Asset` of [ref_architecture.py](./ref_architecture.py). Please refer to the standardized syntax: `Asset.<your asset>`, where `<your asset>` can be replaced by any `Asset`.
* `intrusion_result`: This represents the "detected" intrusion result. It can be any intrusion result from the enum `AttackResult` of [ref_architecture.py](./ref_architecture.py). Please refer to the standardized syntax: `AttackResult.<your intrusion result>`, where `<your intrusion result>` can be replaced by any `AttackResult`.

Additionally, the current vehicle velocity is required. In a real-world setup, this is gathered via sensors, but in this prototype, it will be read using the [dynamic_state.xml](./dynamic_state.xml) file. This contains the following elements:

* `dynamic_parameters/velocity`: The current velocity of the vehicle. It can be any float or integer value

## Execution
After installing all [system requirements](#system-requirements) and [configuring](#configuration) your project, it can be simply executed via:

```
python3 main.py
```

**Note:** Since a real IDS is missing, some manual user-input is necessary in order to provide information. The tool will ask for that information in case it is necessary.

## For developers only
This section briefly describes all available files in this root directory. The configuration files are separately described in their respective sub-folder.

**Please note:** This section is only meant to be used by developers, _not users!_

### main.py
Main IRS program, calling call methods inside classes, to run the IRS functionality

## response.py and intrusion.py
Two files to described [responses](./response.py) and [intrusions](./intrusion.py) as classes

### ref_architecture.py
Contains mainly Enums to provide all the data structures

### ids_dummy.py
Since no real IDS is available, [this script](./ids_dummy.py) gives all the information, which is normally provided by an IRS. Overview of public methods:

* `getDetectedIntrusionDummy`: Return random assets and attack results (only for testing purposes)
* `getDetectedIntrusionManual`: The user must enter all assets and attack results via the terminal
* `getDetectedIntrusionManualGUI`: The user can provide all assets and attack results via a GUI
* `getDetectedIntrusionXml`: Uses the [system_state.xml](./system_state.xml) file to read out the assets and attack results. By providing and index, the n-th intrusion (= `state`) will be read.

### risk_assessment.py
[This script](./risk_assessment.py) performs a threat analysis and risk assessment of the detected intrusion under consideration of the dynamic vehicle parameters (currently only velocity). It has only one public method, `RiskEvaluation`, which is used to evaluate the risk of a detected intrusion. By providing and index, the n-th intrusion (= `state`) will be read.

### response_set_generation.py
[This script](./response_set_generation.py) identifies all possible responses that can be applied in the detected scenario. It has only one public method, `createResponseSet`, which returns the list of applicable [responses](./response.py).

### optimal_response_selection.py
The actual identification of the optimal response will be handled [here](./optimal_response_selection.py). Its only public method, `getOptimalResponse`, has the optional parameter `method`, which is a string identifying the method to calculate the best response. If it is not provided, the user will be asked to select the method manually.

### check_precondition.py
After identifying the optimal response, its precondition will be checked in [this script](./check_precondition.py). It has one public method, `checkPrecondition`, which tries to check the preconditions automatically, but might rely on user inputs.

### ids_feedback.py
Depending on the success of an applied response, the response-specific parameters need to be adapted. This will happen [here](./ids_feedback.py). Its public method, `idsFeedback`, will ask the user to provide the success of the response as a yes/no question. The IDS normally senses this information, but it needs to be emulated here. This script will adapt the XML-files in the folder [dynamic_updated_Parameters](./dynamic_updated_Parameters/)
