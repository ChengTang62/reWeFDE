# Traffic statistics feature extraction
# Combines traff_stats (packet/timing/burst statistics) and pkt_len (binned packet lengths)
# Input: times (list of timestamps), sizes (list of signed packet sizes)
# Convention: positive = outgoing, negative = incoming (same as Time.py, Burst.py)

import collections
import numpy as np
from scipy.stats import kurtosis, skew


def _round_to_nearest(n, m):
    r = n % m
    return n + m - r if r + r >= m else n - r


def TrafficStatsFeatures(times, sizes, padded=1, bin_width=5):
    """
    Extract traffic statistics and packet length bin features from a trace.
    Compatible with extract.py: receives times and sizes from parsed trace files.

    Args:
        times: list of float timestamps
        sizes: list of int signed packet sizes (positive=outgoing, negative=incoming)
        padded: packet size padding (default 1 = no padding)
        bin_width: bin width for packet length histogram (default 5)

    Returns:
        list of feature values (stats features + packet length bins)
    """
    # Split by direction: positive = outgoing, negative = incoming
    packetSizes = []
    packetSizesIn = []
    packetSizesOut = []
    packetTimes = []
    packetTimesIn = []
    packetTimesOut = []

    bin_dict = {}
    bin_dict2 = {}
    for i in range(0, 2000, bin_width):
        bin_dict[i] = 0
        bin_dict2[i] = 0

    # Burst tracking
    out_bursts_packets = []
    out_burst_sizes = []
    out_burst_times = []
    out_current_burst = 0
    out_current_burst_start = 0
    out_current_burst_size = 0

    in_bursts_packets = []
    in_burst_sizes = []
    in_burst_times = []
    in_current_burst = 0
    in_current_burst_start = 0
    in_current_burst_size = 0

    totalPackets = 0
    totalPacketsIn = 0
    totalPacketsOut = 0
    totalBytes = 0
    totalBytesIn = 0
    totalBytesOut = 0

    prev_ts = 0
    for idx, (ts, s) in enumerate(zip(times, sizes)):
        pkt_size = abs(s)
        remainder = pkt_size % padded
        if_remainder = 0 if remainder == 0 else 1
        pkt_size = (pkt_size // padded + if_remainder) * padded

        # Incoming (negative in sizes)
        if s < 0:
            totalPacketsIn += 1
            packetSizesIn.append(pkt_size)
            binned = _round_to_nearest(pkt_size, bin_width)
            bin_dict2[binned] = bin_dict2.get(binned, 0) + 1
            if prev_ts != 0:
                ts_difference = max(0, ts - prev_ts)
                packetTimesIn.append(ts_difference * 1000)

            if out_current_burst != 0:
                if out_current_burst > 1:
                    out_bursts_packets.append(out_current_burst)
                    out_burst_sizes.append(out_current_burst_size)
                    out_burst_times.append(ts - out_current_burst_start)
                out_current_burst = 0
                out_current_burst_size = 0
                out_current_burst_start = 0
            if in_current_burst == 0:
                in_current_burst_start = ts
            in_current_burst += 1
            in_current_burst_size += pkt_size
            totalBytesIn += pkt_size

        # Outgoing (positive in sizes)
        else:
            totalPacketsOut += 1
            packetSizesOut.append(pkt_size)
            binned = _round_to_nearest(pkt_size, bin_width)
            bin_dict[binned] = bin_dict.get(binned, 0) + 1
            if prev_ts != 0:
                ts_difference = max(0, ts - prev_ts)
                packetTimesOut.append(ts_difference * 1000)
            if out_current_burst == 0:
                out_current_burst_start = ts
            out_current_burst += 1
            out_current_burst_size += pkt_size

            if in_current_burst != 0:
                if in_current_burst > 1:
                    in_bursts_packets.append(in_current_burst)
                    in_burst_sizes.append(in_current_burst_size)
                    in_burst_times.append(ts - in_current_burst_start)
                in_current_burst = 0
                in_current_burst_size = 0
                in_current_burst_start = 0
            totalBytesOut += pkt_size

        totalPackets += 1
        totalBytes += pkt_size
        packetSizes.append(pkt_size)
        if prev_ts != 0:
            ts_difference = max(0, ts - prev_ts)
            packetTimes.append(ts_difference * 1000)
        prev_ts = ts

    def _safe_kurtosis(vals):
        if len(vals) < 4:
            return 0.0
        k = kurtosis(vals)
        return 0.0 if np.isnan(k) else k

    def _safe_skew(vals):
        if len(vals) < 3:
            return 0.0
        s = skew(vals)
        return 0.0 if np.isnan(s) else s

    def _stats(vals, defaults):
        if vals:
            return (
                np.mean(vals), np.median(vals), np.std(vals), np.var(vals),
                _safe_kurtosis(vals), _safe_skew(vals), np.amax(vals), np.amin(vals),
                np.percentile(vals, 10), np.percentile(vals, 20),
                np.percentile(vals, 30), np.percentile(vals, 40),
                np.percentile(vals, 50), np.percentile(vals, 60),
                np.percentile(vals, 70), np.percentile(vals, 80),
                np.percentile(vals, 90)
            )
        return defaults

    def _burst_stats(packets, sizes):
        if packets:
            return (
                len(packets), np.mean(packets), np.median(packets),
                np.std(packets), np.var(packets), np.amax(packets),
                _safe_kurtosis(packets), _safe_skew(packets),
                np.percentile(packets, 10), np.percentile(packets, 20),
                np.percentile(packets, 30), np.percentile(packets, 40),
                np.percentile(packets, 50), np.percentile(packets, 60),
                np.percentile(packets, 70), np.percentile(packets, 80),
                np.percentile(packets, 90)
            )
        return (0,) * 17

    out_burst_stats = _burst_stats(out_bursts_packets, out_burst_sizes)

    def _burst_bytes_stats(sizes):
        if sizes:
            return (
                np.mean(sizes), np.median(sizes), np.std(sizes), np.var(sizes),
                _safe_kurtosis(sizes), _safe_skew(sizes), np.amax(sizes), np.amin(sizes),
                np.percentile(sizes, 10), np.percentile(sizes, 20),
                np.percentile(sizes, 30), np.percentile(sizes, 40),
                np.percentile(sizes, 50), np.percentile(sizes, 60),
                np.percentile(sizes, 70), np.percentile(sizes, 80),
                np.percentile(sizes, 90)
            )
        return (0,) * 17

    out_burst_bytes = _burst_bytes_stats(out_burst_sizes)

    defaults = (0,) * 17
    (meanPacketSizes, medianPacketSizes, stdevPacketSizes, variancePacketSizes,
     kurtosisPacketSizes, skewPacketSizes, maxPacketSize, minPacketSize,
     p10, p20, p30, p40, p50, p60, p70, p80, p90) = _stats(packetSizes, defaults)

    (meanPacketSizesIn, medianPacketSizesIn, stdevPacketSizesIn, variancePacketSizesIn,
     kurtosisPacketSizesIn, skewPacketSizesIn, maxPacketSizeIn, minPacketSizeIn,
     p10In, p20In, p30In, p40In, p50In, p60In, p70In, p80In, p90In) = _stats(packetSizesIn, defaults)

    (meanPacketSizesOut, medianPacketSizesOut, stdevPacketSizesOut, variancePacketSizesOut,
     kurtosisPacketSizesOut, skewPacketSizesOut, maxPacketSizeOut, minPacketSizeOut,
     p10Out, p20Out, p30Out, p40Out, p50Out, p60Out, p70Out, p80Out, p90Out) = _stats(packetSizesOut, defaults)

    defaults_t = (0,) * 17
    (meanPacketTimes, medianPacketTimes, stdevPacketTimes, variancePacketTimes,
     kurtosisPacketTimes, skewPacketTimes, maxIPT, minIPT,
     p10t, p20t, p30t, p40t, p50t, p60t, p70t, p80t, p90t) = _stats(packetTimes, defaults_t)

    (meanPacketTimesIn, medianPacketTimesIn, stdevPacketTimesIn, variancePacketTimesIn,
     kurtosisPacketTimesIn, skewPacketTimesIn, maxPacketTimesIn, minPacketTimesIn,
     p10tIn, p20tIn, p30tIn, p40tIn, p50tIn, p60tIn, p70tIn, p80tIn, p90tIn) = _stats(packetTimesIn, defaults_t)

    (meanPacketTimesOut, medianPacketTimesOut, stdevPacketTimesOut, variancePacketTimesOut,
     kurtosisPacketTimesOut, skewPacketTimesOut, maxPacketTimesOut, minPacketTimesOut,
     p10tOut, p20tOut, p30tOut, p40tOut, p50tOut, p60tOut, p70tOut, p80tOut, p90tOut) = _stats(packetTimesOut, defaults_t)

    # Build feature list (traff_stats)
    features = []

    # Global packet features
    features.extend([totalPackets, totalPacketsIn, totalPacketsOut,
                    totalBytes, totalBytesIn, totalBytesOut])

    # Packet length (global)
    features.extend([minPacketSize, maxPacketSize, meanPacketSizes, stdevPacketSizes, variancePacketSizes])
    features.extend([p10, p20, p30, p40, p50, p60, p70, p80, p90])

    # Packet length (in)
    features.extend([minPacketSizeIn, maxPacketSizeIn, meanPacketSizesIn, stdevPacketSizesIn, variancePacketSizesIn])
    features.extend([p10In, p20In, p30In, p40In, p50In, p60In, p70In, p80In, p90In])

    # Packet length (out)
    features.extend([minPacketSizeOut, maxPacketSizeOut, meanPacketSizesOut, stdevPacketSizesOut, variancePacketSizesOut])
    features.extend([p10Out, p20Out, p30Out, p40Out, p50Out, p60Out, p70Out, p80Out, p90Out])

    # Packet timing (global)
    features.extend([maxIPT, minIPT, meanPacketTimes, stdevPacketTimes, variancePacketTimes])
    features.extend([p10t, p20t, p30t, p40t, p50t, p60t, p70t, p80t, p90t])

    # Packet timing (in)
    features.extend([minPacketTimesIn, maxPacketTimesIn, meanPacketTimesIn, stdevPacketTimesIn, variancePacketTimesIn])
    features.extend([p10tIn, p20tIn, p30tIn, p40tIn, p50tIn, p60tIn, p70tIn, p80tIn, p90tIn])

    # Packet timing (out)
    features.extend([minPacketTimesOut, maxPacketTimesOut, meanPacketTimesOut, stdevPacketTimesOut, variancePacketTimesOut])
    features.extend([p10tOut, p20tOut, p30tOut, p40tOut, p50tOut, p60tOut, p70tOut, p80tOut, p90tOut])

    # Outgoing burst stats (packets)
    features.extend(out_burst_stats)
    # Outgoing burst stats (bytes)
    features.extend(out_burst_bytes)

    # Packet length bins (pkt_len)
    od_dict = collections.OrderedDict(sorted(bin_dict.items(), key=lambda t: float(t[0])))
    bin_list = [od_dict[k] for k in od_dict]
    od_dict2 = collections.OrderedDict(sorted(bin_dict2.items(), key=lambda t: float(t[0])))
    bin_list2 = [od_dict2[k] for k in od_dict2]
    features.extend(bin_list)
    features.extend(bin_list2)

    return features
