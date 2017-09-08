import BroControl.plugin
from BroControl import config

from collections import defaultdict, namedtuple
import gzip
import glob
import json
import os
import subprocess
import string

lowercase_chars = set(string.lowercase)
uppercase_chars = set(string.uppercase)
        
GOBACK = 7 # days
LOSS_THRESHOLD = 1

RED = '\033[91m'
ENDC = '\033[0m'
GREEN = '\033[92m'
def red(s):
    return RED + s + ENDC
def green(s):
    return GREEN + s + ENDC

def all_lowercase(s):
    return all(c in lowercase_chars for c in s)
def all_uppercase(s):
    return all(c in uppercase_chars for c in s)

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

def read_bro_logs_with_line_limit(filenames, limit=10000):
    # TODO: just use itertools.islice?
    for f in filenames:
        for rec in read_bro_log(f):
            yield rec
            limit -= 1
            if limit == 0:
                return
        

def find_recent_log_directories(base_dir, days=7):
    dirs = os.listdir(base_dir)
    dirs.sort()
    #Fix in 983 years
    return [os.path.join(base_dir, d) for d in dirs if d.startswith("20")][-days:]

def find_recent_log_files(base_dir, glob_pattern,  days=7):
    dirs = find_recent_log_directories(base_dir, days)
    matches = []
    for d in dirs + ["current"]:
        matches.extend(glob.glob(os.path.join(base_dir, d, glob_pattern)))

    return matches

class Doctor(BroControl.plugin.Plugin):
    def __init__(self):
        super(Doctor, self).__init__(apiversion=1)

    def name(self):
        return "doctor"

    def pluginVersion(self):
        return 1

    def init(self):
        self.log_directory = self.getGlobalOption("logdir")
        self.bro_binary = self.getGlobalOption("bro")
        return True

    def commands(self):
        return [("bro", "", "Troubleshoot Bro installation")]

    def err(self, msg):
        self.error(red(msg))

    def ok(self, msg):
        self.message(green(msg))
    def ok_if(self, msg, is_ok):
        if is_ok:
            self.ok(msg)
        else:
            self.err(msg)
        return is_ok

    def check_reporter(self):
        """Checking for recent reporter.log entries"""
        files = find_recent_log_files(self.log_directory, "reporter.*", days=GOBACK)
        if not files:
            self.message("No reporter log files in the past {} days".format(GOBACK) )
            return True
        self.err("Found {} reporter log files in the past {} days".format(len(files), GOBACK) )

        self.message("Recent reporter.log messages:")
        seen = defaultdict(list)
        order = []
        for rec in read_bro_logs_with_line_limit(reversed(files), 1000):
            if rec['ts'] == '0.000000':
                rec['ts'] = ''
            if rec['location'] == '(empty)':
                rec['location'] = ''
            m = "{location} {ts} {level} {message}".format(**rec).lstrip()
            key = "{level} {message}".format(**rec).lstrip()
            if key not in seen:
                order.append(key)
            seen[key].append(m)

        for key in order:
            msgs = seen[key]
            count = len(msgs)
            for m in msgs[:2]:
                self.message(red(m))
            if len(msgs) > 2:
                self.message("{} duplicate messages suppressed".format(len(msgs)-2))
        return False

    def check_capture_loss(self):
        """Checking for recent capture_loss.log entries"""
        files = find_recent_log_files(self.log_directory, "capture_loss.*", days=GOBACK)
        if not files:
            self.err("No capture_loss log files in the past {} days".format(GOBACK) )
            self.err("Add '@load misc/capture-loss' to your local.bro")
            return False

        workers = defaultdict(list)
        for rec in read_bro_logs_with_line_limit(reversed(files), 10000):
            workers[rec['peer']].append(rec)

        self.message("Capture loss stats:")
        
        ok = True
        for w, recs in sorted(workers.items()):
            min_loss = min(float(rec['percent_lost']) for rec in recs)
            max_loss = max(float(rec['percent_lost']) for rec in recs)
            total_gaps = sum(int(rec['gaps']) for rec in recs)
            total_acks = sum(int(rec['acks']) for rec in recs)
            overall_pct = 100.0 * total_gaps/total_acks
            loss_count = sum(1 for rec in recs if float(rec['percent_lost']) != 0.0)
            noloss_count = len(recs) - loss_count

            msg = "worker={} loss_count={} noloss_count={} min_loss={} max_loss={} overall_loss={}".format(w, loss_count, noloss_count, min_loss, max_loss, overall_pct)
            ok = self.ok_if(msg, overall_pct <= LOSS_THRESHOLD) and ok
        return ok

    def check_pfring(self):
        """Checking if bro is linked against pf_ring if lb_method is pf_ring"""

        pfring_configured = any(n.lb_method == 'pf_ring' for n in self.nodes())

        cmds = []
        ldd_cmd = "ldd {}".format(self.bro_binary)
        interface_nodes = set(n for n in self.nodes() if n.interface)
        for n in interface_nodes:
            cmds.append((n, ldd_cmd))

        pfring_linked = True
        for (n, success, output) in self.executeParallel(cmds):
            out = ''.join(output)
            pfring_linked = pfring_linked and 'pfring' in out
            if pfring_configured and 'pfring' not in out:
                self.err("bro binary on node {} is not linked against pf_ring".format(n))
                self.message(out)
    
        msg = "configured to use pf_ring={}. linked against pf_ring={}".format(pfring_configured, pfring_linked)
        return self.ok_if(msg, pfring_configured == pfring_linked)

    def check_duplicate_5_tuples(self):
        """Checking if any recent connections have been logged multiple times"""
        #TODO: should really check against multiple workers, but will need 2 funcs for that

        files = find_recent_log_files(self.log_directory, "conn.*", days=1)
        if not files:
            self.err("No conn log files in the past day???")
            return False

        tuples = defaultdict(int)
        for rec in read_bro_logs_with_line_limit(reversed(files), 10000):
            # Only count connections that have completed a three way handshake
            # Also ignore flipped connections as those are probably backscatter
            if 'h' not in rec['history'].lower() or '^' in rec['history']:
                continue
            # Also ignore connections that didn't send bytes back and forth
            if rec['orig_bytes'] == '0' or rec['resp_bytes'] == '0':
                continue
            tup = (rec['proto'], rec['id.orig_h'], rec['id.orig_p'], rec['id.resp_h'], rec["id.resp_p"])
            tup = ' '.join(tup)
            tuples[tup] += 1

        bad = [(tup, cnt) for (tup, cnt) in tuples.items() if cnt > 1]
        bad_pct = 100 * len(bad) / len(tuples)
        if bad_pct >= 1:
            self.err("{}%, {} out of {} connections appear to be duplicate".format(bad_pct, len(bad), len(tuples)))
            self.err("First 20:")
            for tup, cnt in bad[:20]:
                self.message("count={} {}".format(cnt, tup))
        else:
            self.ok("ok, only {}%, {} out of {} connections appear to be duplicate".format(bad_pct, len(bad), len(tuples)))
            
        return not bool(bad)

    def check_SAD_connections(self):
        """Checking if many recent connections have a SAD or had history"""

        files = find_recent_log_files(self.log_directory, "conn.*", days=1)
        if not files:
            self.err("No conn log files in the past day???")
            return False

        histories = {"ok": 0, "bad": 0}
        for rec in read_bro_logs_with_line_limit(reversed(files), 100000):
            # Ignore flipped connections as those are probably backscatter
            if '^' in rec['history']:
                continue
            # Ignore non tcp
            if rec['proto'] != 'tcp':
                continue
            # Ignore connections that don't even appear to be from our address space
            if rec['local_orig'] != 'T' and rec['local_resp'] != 'T':
                continue
            # Also ignore connections that didn't send ANY bytes back and forth
            if rec['orig_bytes'] == '0' or rec['resp_bytes'] == '0':
                continue
            h = rec['history']
            #Only count connections that started with Syn or handhsake but were not JUST a syn(scan)
            if not h.startswith(("h", "S")) or len(h) == 1:
                continue
            if all_lowercase(h) or all_uppercase(h):
                print rec
                histories['bad'] += 1
            else:
                histories['ok'] += 1

        pct = histories['bad_pct'] = 100 * histories['bad'] / (histories['ok'] + histories['bad'])
        msg = "OK connections={ok}. Broken connections={bad}. Bad Percentage={bad_pct}".format(**histories)
        return self.ok_if(msg, pct <= 1)
        
    def cmd_custom(self, cmd, args, cmdout):
        args = args.split()
        self.message("Using log directory {}".format(self.log_directory))
        results = BroControl.cmdresult.CmdResult()
        results.ok = True

        funcs = [f for f in dir(self) if f.startswith("check_")]
        for func in funcs:
            if args and func not in args:
                continue
            f = getattr(self, func)
            self.message("#" * (len(f.__doc__)+4))
            self.message("# {} #".format( f.__doc__))
            self.message("#" * (len(f.__doc__)+4))
            results.ok = f() and results.ok
            self.message('')
            self.message('')

        return results

