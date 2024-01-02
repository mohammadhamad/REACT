Dynamically updated configuration files
===================================

## Description
These files contain all the response and TARA metrics that are used for the evaluation of the optimal response. The naming convention of all files can be found below:

```plain
<use case>_<intrusion result>.xml
```

Overview of use cases:
* `responseSet`: These files contain all the metrics and parameters with respect to the responses as well as an overview of general responses, sorted into individual files for all intrusion results (plus one generic, including responses, which can always be applied)
* `TARA`: These files contain all the metrics and parameters with respect to the threat analysis and risk assessment. For each intrusion result there is an individual file, containing parameters for all available assets

Overview of intrusion results:
* `Denial_Of_Service`
* `Falsify_Alter_Behavior`
* `Falsify_Alter_Information`
* `Falsify_Alter_Timing`
* `Information_Disclosure`
* (only for the response Set) `Generic`

**Please note**

Parameters of the `responseSet` can be dynamically changed. If you plan to make changes here, please follow this procedure:

1. Change the parameters inside [initial_Parameters](../initial_Parameters/)
2. Copy the changes into the files in this folder

While it is essential to follow this procedure for the `responseSet`, it is not mandatory, but strictly recommended for `TARA` files

## Description of responseSet files
Each `responseSet`-file can contain multiple elements of the type `response`. Each response has the structure, depicted in the example below:

```xml
<response>
	<action>Countermeasure.Introduce_Access_Control</action>
	<precondition>None</precondition>
	<applyAt>intrusion.destination</applyAt>
	<stopCondition>0</stopCondition>
	<cost>
		<w_A>1</w_A>
		<A>10</A>
		<w_Perf>1</w_Perf>
		<Perf>1</Perf>
	</cost>
	<benefit>
		<w_S>1</w_S>
		<S>10</S>
		<w_F>1</w_F>
		<F>1</F>
		<w_O>1</w_O>
		<O>10</O>
		<w_P>1</w_P>
		<P>100</P>
	</benefit>
</response>
```

**Please note:** To successfully parse the XML file, it is important, that the order of the individual elements inside a `response` stays as depicted!

The following enumeration described individual elements of such a `response`:
* `<action>`: The countermeasure to do. This can be one of the elements of the `Countermeasure` enum from [ref_architecture.py](../ref_architecture.py). Please follow the Python enum-notation: `Countermeasure.<actual action>`
* `<precondition>`: The precondition which needs to be fulfilled, to execute the response. The following options are possible:
  * `None`: The precondition needs to be checked later automatically
  * Any Python interpret-able code: Since this precondition can be evaluated automatically, standard python syntax can be used here. As this is evaluated during runtime, variables can be used. Due to the embedding into existing source code, the following variables are available: `intrusion` (a object of the type [intrusion](../intrusion.py)) and `response` (a object of the type [response](../response.py)). This allows to use flexible boolean structures, like:
  ```python
  (intrusion.destination == Asset.DoIP) and (intrusion.source != Asset.OBD_II)
  ```
* `<applyAt>`: The place, where the response should be applied. Similar to the precondition, this is evaluated during runtime and needs to be an object of the enum-type [Asset](../ref_architecture.py). Possible dynamic assets are: `intrusion.source` or `intrusion.destination`, which will be evaluated automatically, or any constant Enum object from the [Asset-Enum](../ref_architecture.py) in its correct python formulation (example: `Asset.Central_Vehicle_Gateway`)
* `<stopCondition>`: The time, after which the response will be stopped. Since this is only a prototype implementation, this content is currently not evaluated
* `<cost>`: Cost of a response with respect to the availability `A` or the performance `Perf` as well as the respective weights `w_A` and `w_Perf`
* `<benefit>`: Positive impact of a response on HEAVENS parameters (`S, F, O, P`) and the respective weights (`w_S, w_F, w_O, w_P`).

## Description of TARA files
Each `TARA`-file can contain multiple elements of the type `RiskAssessnebt`. Each risk assessment has the structure, depicted in the example below:

```xml
<RiskAssessment>
	<Asset>Asset.OBD_II</Asset>
	<impact>
		<w_S>1</w_S>
		<S>1</S>
		<w_F>0</w_F>
		<F>0</F>
		<w_O>1</w_O>
		<O>100</O>
		<w_P>0</w_P>
		<P>0</P>
	</impact>
</RiskAssessment>
```

**Please note:** To successfully parse the XML file, it is important, that the order of the individual elements inside a `RiskAssessment` stays as depicted!

The following enumeration described individual elements of such a `RiskAssessment`:
* `<Asset>`: Any constant Enum object from the [Asset-Enum](../ref_architecture.py) in its correct python formulation (example: `Asset.Central_Vehicle_Gateway`)
* `<impact>`: Impact of a intrusion on the given asset according to HEAVENS with its parameters (`S, F, O, P`) and the respective weights (`w_S, w_F, w_O, w_P`).
