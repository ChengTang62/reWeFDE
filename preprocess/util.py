
# extract params
FEATURE_EXT = ".features"
NORMALIZE_TRAFFIC = 0

# turn on/off debug:
# Generic feature blocks (off when using attack-specific blocks below)
PACKET_NUMBER = False
PKT_TIME = False
UNIQUE_PACKET_LENGTH = False
NGRAM_ENABLE = False   # removed from extract (not in table)
TRANS_POSITION = False  # removed from extract (not in table)
PACKET_DISTRIBUTION = False
BURSTS = False
FIRST20 = False
CUMUL = False  # use CUMUL_ATTACK block below for table attacks
FIRST30_PKT_NUM = False  # removed from extract (not in table)
LAST30_PKT_NUM = False   # removed from extract (not in table)
PKT_PER_SECOND = False   # removed from extract (not in table)
INTERVAL_KNN = False
INTERVAL_ICICS = False   # removed from extract (not in table)
INTERVAL_WPES11 = False  # removed from extract (not in table)
TRAFFIC_STATS = False  # traff_stats + pkt_len combined features

# Attack-specific feature blocks (table attacks) — run uses these only
KFINGERPRINT = True    # k-Fingerprinting
KNN_ATTACK = True      # KNN
CUMUL_ATTACK = True    # CUMUL (table)
DF_ATTACK = True       # DF (direction, sizes)
TIKTOK_TIMING_ONLY = True       # Tik-Tok (timing only)
TIKTOK_DIRECTION_TIMING = True  # Tik-Tok (direction, timing)
DFTOK_ATTACK = True    # DF-Tok (direction, timing, sizes)
RF_ATTACK = True       # RF (direction, timing)

# packet number per second, how many seconds to count?
howlong = 100

# n-gram feature
NGRAM = 3

# CUMUL feature number
featureCount = 100


# Python3 conversion of python2 cmp function
def cmp(a, b):
    return (a > b) - (a < b)


# normalize traffic
def normalize_traffic(times, sizes):
    # sort
    tmp = sorted(zip(times, sizes))

    times = [x for x, _ in tmp]
    sizes = [x for _, x in tmp]

    TimeStart = times[0]
    PktSize = 500

    # normalize time
    for i in range(len(times)):
        times[i] = times[i] - TimeStart

    # normalize size
    for i in range(len(sizes)):
        sizes[i] = (abs(sizes[i]) / PktSize) * cmp(sizes[i], 0)

    # flat it
    newtimes = list()
    newsizes = list()

    for t, s in zip(times, sizes):
        numCell = abs(s)
        oneCell = cmp(s, 0)
        for r in range(numCell):
            newtimes.append(t)
            newsizes.append(oneCell)

    return newtimes, newsizes

