# Tik-Tok (timing only): global inter-packet time and transmission time, no direction split
# Used by "Tik-Tok (timing)" attack in the table

import numpy
from features.common import X


def interTimeStats(times):
    res = []
    for i in range(1, len(times)):
        res.append(times[i] - times[i - 1])
    if len(res) == 0:
        return [X, X, X, X]
    return [numpy.max(res), numpy.mean(res), numpy.std(res), numpy.percentile(res, 75)]


def transTimeStats(times):
    if len(times) == 0:
        return [X, X, X, X]
    return [numpy.percentile(times, 25), numpy.percentile(times, 50),
            numpy.percentile(times, 75), numpy.percentile(times, 100)]


def TikTokTimingOnlyFeature(times, sizes, features):
    """Timing only (no direction): total inter-packet time + transmission time stats."""
    features.extend(interTimeStats(times))
    features.extend(transTimeStats(times))
