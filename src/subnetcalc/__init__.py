"""subnetting-sim: simulador de subnetting IPv4/IPv6."""

from subnetcalc.core import SubnetError, SubnetInfo, analyze
from subnetcalc.exceptions import SecurityError
from subnetcalc.subnets import split_network
from subnetcalc.supernet import summarize
from subnetcalc.verify import verify_ip
from subnetcalc.vlsm import vlsm_allocate

__version__ = "0.1.0"

__all__ = [
    "SubnetError",
    "SecurityError",
    "SubnetInfo",
    "analyze",
    "split_network",
    "summarize",
    "verify_ip",
    "vlsm_allocate",
    "__version__",
]
