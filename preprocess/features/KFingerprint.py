# k-Fingerprinting: timing + packets per second + burst-based timing statistics
# Used by "k-Fingerprinting" attack in the table (from extract_timing_feature / Tik-Tok repo)

import numpy
from features.common import X

from . import Time, PktSec


def _extract_bursts(times, sizes):
    """Return list of bursts; each burst is list of (t, s) for consecutive same-direction packets."""
    if not sizes:
        return []
    bursts = []
    current = [(times[0], sizes[0])]
    for i in range(1, len(sizes)):
        if (sizes[i] > 0) == (sizes[i - 1] > 0):
            current.append((times[i], sizes[i]))
        else:
            bursts.append(current)
            current = [(times[i], sizes[i])]
    if current:
        bursts.append(current)
    return bursts


def _safe_stats(vals, default=X):
    if not vals:
        return [default, default, default, default]
    a = numpy.array(vals)
    return [float(numpy.mean(a)), float(numpy.std(a)) if len(a) > 1 else 0.0,
            float(numpy.max(a)), float(numpy.min(a))]


def KFingerprintFeature(times, sizes, features, howlong):
    """
    k-FP feature set: Time + PktSec + burst timing summary stats (8 burst stats x 4 summary = 32).
    """
    Time.TimeFeature(times, sizes, features)
    PktSec.PktSecFeature(times, sizes, features, howlong)

    bursts = _extract_bursts(times, sizes)

    # intra-burst delay medians (per burst)
    medians = []
    for burst in bursts:
        ts = [p[0] for p in burst]
        if len(ts) >= 2:
            delays = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
            medians.append(numpy.median(delays))
    features.extend(_safe_stats(medians))

    # inter-burst delay first-first
    if len(bursts) >= 2:
        ts_first = [float(b[0][0]) for b in bursts]
        ibdff = numpy.diff(ts_first).tolist()
        features.extend(_safe_stats(ibdff))
    else:
        features.extend([X, X, X, X])

    # inter-burst delay incoming first-first
    in_bursts = [b for b in bursts if b[0][1] < 0]
    if len(in_bursts) >= 2:
        ts_first = [float(b[0][0]) for b in in_bursts]
        ibdiff = numpy.diff(ts_first).tolist()
        features.extend(_safe_stats(ibdiff))
    else:
        features.extend([X, X, X, X])

    # inter-burst delay last-first (burst duration)
    ibdlf = []
    for b in bursts:
        if len(b) >= 2:
            ibdlf.append(float(b[-1][0]) - float(b[0][0]))
    features.extend(_safe_stats(ibdlf))

    # inter-burst delay outgoing first-first
    out_bursts = [b for b in bursts if b[0][1] > 0]
    if len(out_bursts) >= 2:
        ts_first = [float(b[0][0]) for b in out_bursts]
        ibdoff = numpy.diff(ts_first).tolist()
        features.extend(_safe_stats(ibdoff))
    else:
        features.extend([X, X, X, X])

    # intra_interval (burst duration)
    interval = []
    for b in bursts:
        if len(b) >= 2:
            interval.append(float(b[-1][0]) - float(b[0][0]))
    features.extend(_safe_stats(interval))

    # inter_inramd: differences of intraBD medians
    if len(medians) >= 2:
        inter_inramd = [medians[i] - medians[i - 1] for i in range(1, len(medians))]
        features.extend(_safe_stats(inter_inramd))
    else:
        features.extend([X, X, X, X])

    # intra_burst_delay variance (per burst)
    ibdbvar = []
    for burst in bursts:
        ts = [p[0] for p in burst]
        if len(ts) >= 2:
            delays = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
            ibdbvar.append(numpy.var(delays))
    features.extend(_safe_stats(ibdbvar))
