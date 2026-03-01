# DF (direction, sizes): direction + packet size features
# Used by "DF (direction, sizes)" attack in the table

from . import PktNum, PktLen


def DFFeature(times, sizes, features):
    """Direction + sizes: PktNum (direction/counts) + PktLen (unique packet lengths)."""
    PktNum.PacketNumFeature(times, sizes, features)
    PktLen.PktLenFeature(times, sizes, features)
