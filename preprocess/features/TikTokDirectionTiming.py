# Tik-Tok (direction, timing): timing with direction split
# Used by "Tik-Tok (direction, timing)" attack in the table

from . import Time


def TikTokDirectionTimingFeature(times, sizes, features):
    """Timing with direction: inter-packet time and transmission time (total, out, in)."""
    Time.TimeFeature(times, sizes, features)
