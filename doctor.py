import BroControl.plugin
from BroControl import config

class Doctor(BroControl.plugin.Plugin):
    def __init__(self):
        super(Doctor, self).__init__(apiversion=1)

    def name(self):
        return "doctor"

    def pluginVersion(self):
        return 1

    def init(self):
        self.message("Doctor plugin is initialized")
        return True

    def commands(self):
        return [("", "", "Troubleshoot Bro installation")]

    def cmd_custom(self, cmd, args, cmdout):
        self.message("WEEEEE")
