from os import system
from ref_architecture import *
from intrusion import *
import random
import xml.etree.ElementTree as ET

class IDS:
    
    # return a random intrusion (random assets and random intrusion result)
    def getDetectedIntrusionDummy(self):
        assets = list(Asset)
        infected_asset = random.choice(assets)
        affected_asset = random.choice(assets)

        attack_results = list(AttackResult)
        attack_result = random.choice(attack_results)

        return Intrusion(infected_asset, affected_asset, attack_result, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    # return the intrusion, entered via terminal by the user
    def getDetectedIntrusionManual(self):
        choice = input("Infected asset: ")
        if choice == '':
            return None
        infected_asset = Asset[choice]

        choice = input("Affected asset: ")
        if choice == '':
            return None
        affected_asset = Asset[choice]

        choice = input("Attack result: ")
        if choice == '':
            return None
        attack_result = AttackResult[choice]

        return Intrusion(infected_asset, affected_asset, attack_result, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    # Private helper function to read to the GUI selected intrusion data
    def _getGUIElements(self):

        # Read the data, if it is not empty
        if(self.selection_infected_asset.get() != '') or (self.selection_affected_asset.get() != '') or (self.selection_attack_result.get() != ''):
            infected_asset = Asset[str(self.selection_infected_asset.get()).split('.')[-1]]
            affeced_asset = Asset[str(self.selection_affected_asset.get()).split('.')[-1]]
            attack_result = AttackResult[str(self.selection_attack_result.get()).split('.')[-1]]
            self.intrusion = Intrusion(infected_asset, affeced_asset, attack_result, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            self.tk.destroy()
        else:
            self.intrusion = None
            self.tk.destroy()
    
    # Private helper function to stop the program
    def _endProgram(self):
        self.intrusion = None # -> By setting this to None, the program will end
        self.tk.destroy()

    # return the intrusion, entered via GUI by the user
    def getDetectedIntrusionManualGUI(self):
        import tkinter

        assets = list(Asset)
        attack_results = list(AttackResult)

        self.tk = tkinter.Tk(className="Set IDS Parameter")
        self.tk.geometry("640x480")

        self.selection_infected_asset = tkinter.StringVar()
        self.selection_affected_asset = tkinter.StringVar()
        self.selection_attack_result = tkinter.StringVar()

        label_infected_asset = tkinter.Label(master=self.tk, text="Infected Asset")
        label_infected_asset.place(x=10, y=10)

        label_affected_asset = tkinter.Label(master=self.tk, text="Affected Asset")
        label_affected_asset.place(x=10, y=60)

        label_attack_result = tkinter.Label(master=self.tk, text="Attack Result")
        label_attack_result.place(x=10, y=110)

        drop_infected_asset = tkinter.OptionMenu(self.tk, self.selection_infected_asset, *assets)
        drop_infected_asset.place(x=200, y=10)

        drop_affected_asset = tkinter.OptionMenu(self.tk, self.selection_affected_asset, *assets)
        drop_affected_asset.place(x=200, y=60)

        drop_attack_result = tkinter.OptionMenu(self.tk, self.selection_attack_result, *attack_results)
        drop_attack_result.place(x=200, y=110)

        button = tkinter.Button(master=self.tk,text="End",command=self._endProgram)
        button.pack(side="bottom")

        button = tkinter.Button(master=self.tk,text="OK",command=self._getGUIElements)
        button.pack(side="bottom")

        self.tk.mainloop()

        return self.intrusion
    
    # return the index-th intrusion out of the system_state.xml file
    def getDetectedIntrusionXml(self, index=0):
        tree = ET.parse('system_state.xml')
        root = tree.getroot()
        if index > (len(root) - 1):
            return None
        else:
            infected_asset = Asset[root[index][0].text.split('.')[-1]]
            affeced_asset = Asset[root[index][1].text.split('.')[-1]]
            attack_result = AttackResult[root[index][2].text.split('.')[-1]]
            #print(infected_asset, affeced_asset, attack_result)
            return Intrusion(infected_asset, affeced_asset, attack_result, 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])