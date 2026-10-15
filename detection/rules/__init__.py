"""Rule registry and runner."""

from typing import List, Type
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.rules.rapid_onward import RapidOnwardTransferRule
from detection.rules.fan_in import MultiSourceFanInRule
from detection.rules.fan_out import FanOutSplittingRule
from detection.rules.cycles import TransactionCycleRule
from detection.rules.complaint_convergence import ComplaintConvergenceRule
from detection.rules.new_account_burst import NewAccountBurstRule
from detection.rules.collect_abuse import CollectRequestAbuseRule
from detection.rules.shared_device import SharedDeviceRule


ALL_RULES: List[Type[BaseRule]] = [
    RapidOnwardTransferRule,
    MultiSourceFanInRule,
    FanOutSplittingRule,
    TransactionCycleRule,
    ComplaintConvergenceRule,
    NewAccountBurstRule,
    CollectRequestAbuseRule,
    SharedDeviceRule,
]
