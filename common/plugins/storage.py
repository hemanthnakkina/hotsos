import glob
import os
import re

from common import (
    checks,
    constants,
    plugintools,
)


CEPH_SERVICES_EXPRS = [r"ceph-[a-z0-9-]+",
                       r"rados[a-z0-9-:]+"]
CEPH_PKGS_CORE = [r"ceph-[a-z-]+",
                  r"rados[a-z-]+",
                  r"rbd",
                  ]
CEPH_LOGS = "var/log/ceph/"


class StorageChecksBase(plugintools.PluginPartBase):
    pass


class CephChecksBase(StorageChecksBase, checks.ServiceChecksBase):

    @property
    def output(self):
        if self._output:
            return {"ceph": self._output}

    @property
    def osd_ids(self):
        """Return list of ceph-osd ids."""
        ceph_osds = self.services.get("ceph-osd")
        if not ceph_osds:
            return []

        osd_ids = []
        for cmd in ceph_osds["ps_cmds"]:
            ret = re.compile(r".+\s+.*--id\s+([0-9]+)\s+.+").match(cmd)
            if ret:
                osd_ids.append(int(ret[1]))

        return osd_ids


class CephConfig(checks.SectionalConfigBase):
    pass


class BcacheChecksBase(StorageChecksBase):

    @property
    def output(self):
        if self._output:
            return {"bcache": self._output}

    def get_sysfs_cachesets(self):
        cachesets = []
        path = os.path.join(constants.DATA_ROOT, "sys/fs/bcache/*")
        for entry in glob.glob(path):
            if os.path.exists(os.path.join(entry, "cache_available_percent")):
                cachesets.append(entry)

        return cachesets
