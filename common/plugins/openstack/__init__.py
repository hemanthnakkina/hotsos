import os
import re

from common import (
    checks,
    constants,
    plugintools,
)
from common.cli_helpers import CLIHelper
from common.plugins.openstack import exceptions

# Plugin config opts from global
OPENSTACK_AGENT_ERROR_KEY_BY_TIME = \
    constants.bool_str(os.environ.get('OPENSTACK_AGENT_ERROR_KEY_BY_TIME',
                                      'False'))
OPENSTACK_SHOW_CPU_PINNING_RESULTS = \
    constants.bool_str(os.environ.get('OPENSTACK_SHOW_CPU_PINNING_RESULTS',
                                      'False'))

# These are the names of Openstack projects we want to track.
OST_PROJECTS = ["aodh",
                "barbican",
                "ceilometer",
                "cinder",
                "designate",
                "glance",
                "gnocchi",
                "heat",
                "horizon",
                "keystone",
                "neutron",
                "nova",
                "manila",
                "masakari",
                "octavia",
                "placement",
                "swift",
                ]

SVC_VALID_SUFFIX = r"[0-9a-zA-Z-_]*"

# expressions used to match openstack services for each project
OST_SERVICES_EXPRS = []
for project in OST_PROJECTS:
    OST_SERVICES_EXPRS.append(project + SVC_VALID_SUFFIX)

# Services that are not actually openstack projects but are used by them
OST_SERVICES_DEPS = [r"apache{}".format(SVC_VALID_SUFFIX),
                     r"dnsmasq",
                     r"ganesha.nfsd",
                     r"haproxy",
                     r"keepalived{}".format(SVC_VALID_SUFFIX),
                     r"mysqld",
                     r"vault{}".format(SVC_VALID_SUFFIX),
                     r"qemu-system-\S+",
                     ]

OST_PKG_ALIASES = ["openstack-dashboard"]
OST_PKGS_CORE = OST_PROJECTS + OST_PKG_ALIASES
OST_DEP_PKGS = [r"conntrack",
                r"dnsmasq",
                r"haproxy",
                r"keepalived",
                r"libvirt-daemon",
                r"libvirt-bin",
                r"mysql-?\S+",
                r"pacemaker",
                r"corosync",
                r"nfs--ganesha",
                r"python3?-oslo[.-]",
                r"qemu-kvm",
                ]

AGENT_DAEMON_NAMES = {
    "barbican": ["barbican-api", "barbican-worker"],
    "cinder": ["cinder-scheduler", "cinder-volume"],
    "designate": ["designate-agent", "designate-api", "designate-central",
                  "designate-mdns", "designate-producer", "designate-sink",
                  "designate-worker"],
    "glance": ["glance-api"],
    "heat": ["heat-engine", "heat-api", "heat-api-cfn"],
    "keystone": ["keystone"],
    "manila": ["manila-api", "manila-scheduler", "manila-data",
               "manila-share"],
    "neutron": ["neutron-openvswitch-agent", "neutron-dhcp-agent",
                "neutron-l3-agent", "neutron-server",
                "neutron-sriov-agent"],
    "nova": ["nova-compute", "nova-scheduler", "nova-conductor",
             "nova-api-os-compute", "nova-api-wsgi", "nova-api-metadata.log"],
    "octavia": ["octavia-api", "octavia-worker",
                "octavia-health-manager", "octavia-housekeeping",
                "octavia-driver-agent"],
    }


# These can exist in any service
AGENT_EXCEPTIONS_COMMON = [
    r"(AMQP server on .+ is unreachable)",
    r"(amqp.exceptions.ConnectionForced):",
    r"(OSError: Server unexpectedly closed connection)",
    r"(ConnectionResetError: .+)",
]
for exc in exceptions.OSLO_DB_EXCEPTIONS + \
        exceptions.OSLO_MESSAGING_EXCEPTIONS + \
        exceptions.PYTHON_BUILTIN_EXCEPTIONS:
    AGENT_EXCEPTIONS_COMMON.append(r"({})".format(exc))

SERVICE_RESOURCES = {}
for service in OST_PROJECTS:
    SERVICE_RESOURCES[service] = {"logs": os.path.join("var/log", service),
                                  "exceptions_base": [] +
                                  AGENT_EXCEPTIONS_COMMON,
                                  "daemons":
                                  AGENT_DAEMON_NAMES.get(service, [])}

NEUTRON_HA_PATH = 'var/lib/neutron/ha_confs'


class OpenstackServiceChecksBase(plugintools.PluginPartBase,
                                 checks.ServiceChecksBase):
    pass


class OpenstackChecksBase(plugintools.PluginPartBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._instances = []

    @property
    def running_instances(self):
        if self._instances:
            return self._instances

        for line in CLIHelper().ps():
            ret = re.compile(".+product=OpenStack Nova.+").match(line)
            if ret:
                guest = {}
                expr = r".+uuid\s+([a-z0-9\-]+)[\s,]+.+"
                ret = re.compile(expr).match(ret[0])
                if ret:
                    guest["uuid"] = ret[1]

                expr = r".+\s+-name\s+guest=(instance-\w+)[,]*.*\s+.+"
                ret = re.compile(expr).match(ret[0])
                if ret:
                    guest["name"] = ret[1]

                if guest:
                    self._instances.append(guest)

        return self._instances

    def __call__(self):
        pass


class AgentChecksBase(object):
    MAX_RESULTS = 5

    def __init__(self, searchobj, master_results_key=None):
        """
        @param searchobj: FileSearcher object used for searches.
        @param master_results_key: optional - key into which results
                                   will be stored in master yaml.
        """
        self.searchobj = searchobj
        if master_results_key:
            self.master_results_key = master_results_key

    def register_search_terms(self):
        raise NotImplementedError

    def process_results(self, results):
        raise NotImplementedError


class OpenstackConfig(checks.SectionalConfigBase):
    pass


class OpenstackPackageChecksBase(plugintools.PluginPartBase,
                                 checks.APTPackageChecksBase):

    def __init__(self):
        super().__init__(core_pkgs=OST_PKGS_CORE, other_pkgs=OST_DEP_PKGS)


class OpenstackDockerImageChecksBase(plugintools.PluginPartBase,
                                     checks.DockerImageChecksBase):

    def __init__(self):
        super().__init__(core_pkgs=OST_PKGS_CORE, other_pkgs=OST_DEP_PKGS)