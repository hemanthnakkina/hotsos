#!/usr/bin/python3
import re

from common import (
    helpers,
)


class ServiceChecksBase(object):

    def __init__(self, service_exprs, hint_range=None,
                 use_ps_axo_flags=False):
        """
        @param service_exprs: list of python.re expressions used to match a
        service name.
        @param use_ps_axo_flags: optional flag to change function used to get
        ps output.
        """
        self.services = {}
        self.service_exprs = []

        for expr in service_exprs:
            if hint_range:
                start, end = hint_range
            else:
                # arbitrarily use first 5 chars of search as a pre-search hint
                start = 0
                end = min(len(expr), 4)

            self.service_exprs.append((expr, expr[start:end]))

        # only use if exists
        if use_ps_axo_flags and helpers.get_ps_axo_flags_available():
            self.ps_func = helpers.get_ps_axo_flags
        else:
            self.ps_func = helpers.get_ps

    @property
    def has_ps_axo_flags(self):
        """Returns True if it is has been requested and is possible to get
        output of helpers.get_ps_axo_flags.
        """
        return self.ps_func == helpers.get_ps_axo_flags

    def get_service_info_str(self):
        """Create a list of "<service> (<num running>)" for running services
        detected. Useful for display purposes."""
        service_info_str = []
        for svc in sorted(self.services):
            num_daemons = self.services[svc]["ps_cmds"]
            service_info_str.append("{} ({})".format(svc, len(num_daemons)))

        return service_info_str

    def _get_running_services(self):
        """
        Execute each provided service expression against lines in ps and store
        each full line in a list against the service matched.
        """
        for line in self.ps_func():
            for expr, hint in self.service_exprs:
                ret = re.compile(hint).search(line)
                if not ret:
                    continue

                # look for running process with this name
                ret = re.compile(r".+\S*(\s|/)({})(\s+.+|$)".format(expr)
                                 ).match(line)
                if ret:
                    svc = ret.group(2)
                    if svc not in self.services:
                        self.services[svc] = {"ps_cmds": []}

                    self.services[svc]["ps_cmds"].append(ret.group(0))

    def __call__(self):
        """This can/should be extended by inheriting class."""
        self._get_running_services()


class LogData(object):
    def __init__(self):
        self.stats = {"min": 0,
                      "max": 0,
                      "stdev": 0,
                      "avg": 0,
                      "samples": []}
        self.samples = {}
        self.sample_conflict_seq_ids_end = {}
        self.sample_conflict_seq_ids_start = {}

    def get_samples_by_key(self, key):
        _samples = []
        for s in samples:
            _samples.append(s[key])

        return _samples

    def add_value(self, unique_key, key, value):
        self.samples[unique_key][key] = value

    def add_start(self, key, data):
        if key not in self.sample_conflict_seq_ids_end:
            return

        if key in self.sample_conflict_seq_ids_start:
            self.sample_conflict_seq_ids_start[key] += 1
        else:
            self.sample_conflict_seq_ids_start[key] = 0

        # ensure no overwrite
        key = "{}_{}".format(self.sample_conflict_seq_ids_start[key], key)
        self.samples[key] = {"start": start}
        return key

    def add_end(self, key, data):
        if key in self.sample_conflict_seq_ids_end:
            self.sample_conflict_seq_ids_end[key] += 1
        else:
            self.sample_conflict_seq_ids_end[key] = 0

        while key in self.samples:
            self.sample_conflict_seq_ids_end[key] += 1

        # ensure no overwrite
        key = "{}_{}".format(self.sample_conflict_seq_ids_end[key], key)
        self.samples[key] = data
        return key

    def get_start_value(self, key):
        return self.samples.get(key) 

    def get_end_value(self, key):
        return self.samples.get(key) 

    def has_end_key(self, key):
        return key in self.sample_conflict_seq_ids_end

    def get_top_samples(self, sort_by_key, reverse=False):
        count = 0
        top_n = {}
        top_n_sorted = {}

        for k, v in sorted(self.samples.items(),
                           key=lambda x: x[1].get(sort_by_key, 0),
                           reverse=reverse):
            # skip unterminated entries (e.g. on file wraparound)
            if "start" not in v:
                continue

            if count >= self.MAX_RESULTS:
                break

            count += 1
            top_n[k] = v

        for k, v in sorted(top_n.items(), key=lambda x: x[1]["start"],
                           reverse=reverse):
            router = k.rpartition('_')[0]
            router = router.partition('_')[2]
            top_n_sorted[router] = {"start": v["start"],
                                    "end": v["end"],
                                    "duration": v["duration"]}

        stats['min'] = round(min(stats['samples']), 2)
        stats['max'] = round(max(stats['samples']), 2)
        stats['stdev'] = round(statistics.pstdev(stats['samples']), 2)
        stats['avg'] = round(statistics.mean(stats['samples']), 2)
        num_samples = len(stats['samples'])
        stats['samples'] = num_samples


class LogSequenceDeltaBase(object):

    def __init__(self):
        self.data = LogData()

    def get_stats(self, results):
        for result in results.find_by_tag("end"):
            day = result.get(1)
            secs = result.get(2)
            router = result.get(3)
            end = "{} {}".format(day, secs)
            end = datetime.strptime(end, "%Y-%m-%d %H:%M:%S.%f")

            # router may have many updates over time across many files so we
            # need to have a way to make them unique.
            key = "{}_{}".format(os.path.basename(result.source), router)
            self.data.add_end(key, end)

        for result in results.find_by_tag("start"):
            day = result.get(1)
            secs = result.get(2)
            router = result.get(3)
            start = "{} {}".format(day, secs)
            start = datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f")

            key = "{}_{}".format(os.path.basename(result.source), router)
            unique_key = self.data.add_start(key, start)
            if self.data.has_end_key(unique_key):
                end = self.data.get_end_value(unique_key)
                etime = end - start
                if etime.total_seconds() < 0:
                    continue

                self.data.add_value(unique_key, "duration",
                                    etime.total_seconds())

        if not self.data.get_samples_by_key("duration"):
            return

        self.data.get_top_samples(5, sort_by="duration", reverse=True)

        self.l3_agent_info["router-spawn-events"] = {"top": top_n_sorted,
                                                     "stats": stats}


