# RF (direction, timing): direction + timing for Random Forest attack
# Used by "RF (direction, timing)" attack in the table

from . import PktNum, Time


def RFFeature(times, sizes, features):
    """Direction + timing: PktNum + Time."""
    PktNum.PacketNumFeature(times, sizes, features)
    Time.TimeFeature(times, sizes, features)
