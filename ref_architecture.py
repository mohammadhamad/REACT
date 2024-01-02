from enum import Enum
from dataclasses import dataclass

# Enum, containing all possible Assets
class Asset(Enum):
    OBD_II                      = 1
    DoIP                        = 2
    GPS                         = 3
    Cellular_module             = 4
    DSRC_for_IoV                = 5
    EV_charging_infrastructure  = 6
    Digital_toll_collection     = 7
    Engine_control              = 8
    Transmission_control        = 9
    Battery_management          = 10
    Combustion_control          = 11
    Light_control               = 12
    Wiper_control               = 13
    Key_control                 = 14
    Climate_control             = 15
    Door_Trunk_control          = 16
    Steering_control            = 17
    Acceleration_control        = 18
    Brake_control               = 19
    Airbag_control              = 20
    Instrument_cluster          = 21
    TPMS_receiver               = 22
    Front_camera                = 23
    Surround_camera             = 24
    Radar                       = 25
    LiDAR                       = 26
    Ultrasonic                  = 27
    WiFi_hotspot                = 28
    USB_port                    = 29
    Video_screens               = 30
    Bluetooth                   = 31
    Speech_recognition          = 32
    UKW_DAB                     = 33
    Diagnostic_Gateway          = 34
    External_Gateway            = 35
    Powertrain_Gateway          = 36
    Body_Comfort_Gateway        = 37
    Chassis_Gateway             = 38
    ADAS_Gateway                = 39
    Infotainment_Gateway        = 40
    Central_Vehicle_Gateway     = 41

# Enum, containing all AttackResults
class AttackResult(Enum):
    Falsify_Alter_Information   = 1
    Falsify_Alter_Timing        = 2
    Information_Disclosure      = 3
    Falsify_Alter_Behavior      = 4
    Denial_Of_Service           = 5

# Enum, containing all the possible countermeasures
class Countermeasure(Enum):
    Isolation                           = 1
    Limit_Communication                 = 2
    Drop_Packets                        = 3
    Trace_Communication                 = 4
    Additional_Logging                  = 5
    Block_Network_Traffic               = 6
    Kill_Asset                          = 7
    Use_Redundant_Source                = 8
    Reduce_Trust_Level                  = 9
    Perform_Security_Auditing           = 10
    Increase_Monitor_Level              = 11
    Correction_Timing                   = 12
    Correction_Protocol                 = 13
    Correction_Behavior                 = 14
    Issue_Authentication_Challenge      = 15
    Request_Perform_SW_Update           = 16
    Introduce_Access_Control            = 17
    Additional_Authentication           = 18
    Introduce_Honeypot                  = 19
    Notify_SoC_Administrator            = 20
    Restart_Asset                       = 21
    Change_Settings                     = 22
    Modify_Firewall                     = 23
    Redirect_Traffic                    = 24
    Split_Merge_Functions               = 25
    Reinitialization                    = 26
    Adapt_IDS_Parameters                = 27
    Limit_Resources                     = 28
    Introduce_VLAN                      = 29
    Go_Into_Safe_Mode                   = 30
    Warn_Other_ECU                      = 31
    Delete_Infected_Memory              = 32
    Create_Backup                       = 33
    No_Action                           = 34

# Data class, describing the dynamic system state
@dataclass
class DynamicSystemState:
    VehicleSpeed: float = 0.0