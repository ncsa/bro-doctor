import BroControl.plugin
from BroControl import config

import os
import glob

def find_recent_log_directories(base_dir, days=7):
    dirs = os.listdir(base_dir)
    dirs.sort()
    #Fix in 983 years
    return [d for d in dirs if d.startswith("20")][:days]

def find_recent_log_files(base_dir, glob_pattern,  days=7):
    dirs = os.listdir(base_dir)
    dirs.sort()
    #Fix in 983 years
    dirs = [d for d in dirs if d.startswith("20")][:days]
    matches = []
    for d in dirs:
        matches.extend(glob.glob(os.path.join(d, glob_pattern)))
    return matches
        

GOBACK = 7 # days

class Doctor(BroControl.plugin.Plugin):
    def __init__(self):
        super(Doctor, self).__init__(apiversion=1)

    def name(self):
        return "doctor"

    def pluginVersion(self):
        return 1

    def init(self):
        self.message("Doctor plugin is initialized")

        self.log_directory = self.getGlobalOption("logdir")
        return True

    def commands(self):
        return [("bro", "", "Troubleshoot Bro installation")]

    def check_reporter(self):
        """"Check for recent reporter.log entries"""
        files = find_recent_log_files(self.log_directory, "reporter.*", days=GOBACK)
        if not files:
            self.message("No reporter logs in the past {} days".format(GOBACK) )
            return True

    def check_capture_loss(self):
        """"Check for recent capture_loss.log entries"""
        files = find_recent_log_files(self.log_directory, "capture_loss.*", days=GOBACK)
        if not files:
            self.error("No capture_loss logs in the past {} days".format(GOBACK) )
            return False

    def cmd_custom(self, cmd, args, cmdout):
        self.message("Using log directory {}".format(self.log_directory))
        results = BroControl.cmdresult.CmdResult()
        results.ok = True

        for f in [self.check_reporter]:
            results.ok = f() and results.ok

        return results

