import BroControl.plugin
from BroControl import config

from collections import defaultdict, namedtuple
import gzip
import glob
import json
import os
import subprocess

def bro_ascii_reader(f):
    line = ''
    headers = {}
    it = iter(f)
    while not line.startswith("#types"):
        line = next(it).rstrip()
        k,v = line[1:].split(None, 1)
        headers[k] = v

    sep = headers['separator'].decode("string-escape")

    for k,v in headers.items():
        if sep in v:
            headers[k] = v.split(sep)

    headers['separator'] = sep
    fields = headers['fields']
    types = headers['types']
    set_sep = headers['set_separator']

    vectors = [field for field, type in zip(fields, types) if type.startswith("vector[")]

    for row in it:
        if row.startswith("#close"): break
        parts = row.rstrip().split(sep)
        rec = dict(zip(fields, parts))
        for f in vectors:
            rec[f] = rec[f].split(set_sep)
        yield rec

def bro_json_reader(f):
    for line in f:
        yield json.loads(f)

def open_log(filename):
    if filename.endswith(".log"):
        return open(filename)
    if filename.endswith(".gz"):
        return gzip.open(filename)
    raise Exception("Unknown log extension: {}".format(filename))

def read_bro_log(filename):
    reader = None
    with open_log(filename) as f:
        first_byte = f.read(1)
        if first_byte == '#':
            reader = bro_ascii_reader
        if first_byte == '{':
            reader = bro_json_reader
    if not reader:
        raise Exception("Unknown bro log type, first line: {!r}".format(f.readline().strip()))

    f = open_log(filename)
    for rec in reader(f):
        yield rec
    f.close()

def find_recent_log_directories(base_dir, days=7):
    dirs = os.listdir(base_dir)
    dirs.sort()
    #Fix in 983 years
    return [os.path.join(base_dir, d) for d in dirs if d.startswith("20")][-days:]

def find_recent_log_files(base_dir, glob_pattern,  days=7):
    dirs = find_recent_log_directories(base_dir, days)
    matches = []
    for d in dirs:
        matches.extend(glob.glob(os.path.join(base_dir, d, glob_pattern)))
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
        self.bro_binary = self.getGlobalOption("bro")
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

        workers = defaultdict(list)
        want_records = 10000
        for f in reversed(files):
            for rec in read_bro_log(f):
                want_records -= 1
                if not want_records:
                    break
                workers[rec['peer']].append(rec)

        self.message("Capture loss stats:")
        for w, recs in sorted(workers.items()):
            min_loss = min(float(rec['percent_lost']) for rec in recs)
            max_loss = max(float(rec['percent_lost']) for rec in recs)
            total_gaps = sum(int(rec['gaps']) for rec in recs)
            total_acks = sum(int(rec['acks']) for rec in recs)
            overall_pct = 100.0 * total_gaps/total_acks
            loss_count = sum(1 for rec in recs if float(rec['percent_lost']) != 0.0)
            noloss_count = len(recs) - loss_count

            self.message("worker={} loss_count={} noloss_count={} min_loss={} max_loss={} overall_loss={}".format(w, loss_count, noloss_count, min_loss, max_loss, overall_pct))

    def check_pfring(self):
        """Check to see if bro is linked against pf_ring if it is configured to use it"""

        pfring_configured = any(n.lb_method == 'pf_ring' for n in self.nodes())

        bro_ldd = subprocess.check_output(["ldd", self.bro_binary])
        pfring_linked = 'pfring' in bro_ldd

        if pfring_configured == pfring_linked:
            self.message("pf_ring: ok! configured={} linked={}".format(pfring_configured, pfring_linked))
        else:
            self.error("pf_ring: error! configured={} linked={}".format(pfring_configured, pfring_linked))
        
    def cmd_custom(self, cmd, args, cmdout):
        self.message("Using log directory {}".format(self.log_directory))
        results = BroControl.cmdresult.CmdResult()
        results.ok = True

        for f in [self.check_pfring, self.check_reporter, self.check_capture_loss]:
            results.ok = f() and results.ok

        return results

