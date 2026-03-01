# KNN attack: first 20 packets + burst + packet distribution + interval (KNN)
# Used by "KNN" attack in the table

from . import HeadTail, Burst, PktDistribution, Interval


def KNNFeature(times, sizes, features):
    """KNN feature set: First20 + Burst + PktDistribution + Interval KNN."""
    HeadTail.First20(times, sizes, features)
    Burst.BurstFeature(times, sizes, features)
    PktDistribution.PktDistFeature(times, sizes, features)
    Interval.IntervalFeature(times, sizes, features, 'KNN')
