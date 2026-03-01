# DF-Tok (direction, timing, sizes): direction + timing + sizes in one block
# Used by "DF-Tok (direction, timing, sizes)" attack in the table

from . import PktNum, PktLen, Time


def DFTokFeature(times, sizes, features):
    """Direction + timing + sizes: PktNum + PktLen + Time."""
    PktNum.PacketNumFeature(times, sizes, features)
    PktLen.PktLenFeature(times, sizes, features)
    Time.TimeFeature(times, sizes, features)
