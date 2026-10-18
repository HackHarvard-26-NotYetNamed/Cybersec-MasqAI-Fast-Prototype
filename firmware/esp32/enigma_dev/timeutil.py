"""Calendar arithmetic without the RTC (MicroPython's epoch differs by port; floats are single precision on ESP32).

Times are integer Unix seconds (UTC). The device's notion of "now" for key expiry comes from OpenRouter's TLS-
authenticated `Date` header, never from NTP or the host (design §13.5).
"""

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def days_from_civil(y, m, d):
    """Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm)."""
    if m <= 2:
        y -= 1
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(z):
    z += 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return (y + 1 if m <= 2 else y), m, d


def _valid(y, mo, d, h, mi, s):
    if not (1970 <= y <= 2200 and 1 <= mo <= 12 and 1 <= d <= 31 and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 60):
        return False
    return civil_from_days(days_from_civil(y, mo, d)) == (y, mo, d)


def to_unix(y, mo, d, h, mi, s):
    return days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s


def _int(text):
    if not text or not all("0" <= c <= "9" for c in text):
        raise ValueError("not a number")
    return int(text)


def parse_http_date(value):
    """IMF-fixdate, e.g. 'Sun, 18 Oct 2026 12:00:00 GMT' -> Unix seconds, or None."""
    try:
        parts = value.strip().split(" ")
        if len(parts) != 6 or parts[5] != "GMT" or not parts[0].endswith(","):
            return None
        d, y = _int(parts[1]), _int(parts[3])
        mo = _MONTHS.index(parts[2]) + 1
        hms = parts[4].split(":")
        if len(hms) != 3:
            return None
        h, mi, s = _int(hms[0]), _int(hms[1]), _int(hms[2])
    except (ValueError, AttributeError):
        return None
    if not _valid(y, mo, d, h, mi, s):
        return None
    return to_unix(y, mo, d, h, mi, s)


def parse_iso(value):
    """'2026-10-18T12:31:00Z', '...00.000Z' or '...00+00:00' -> Unix seconds (fraction dropped), or None."""
    if not isinstance(value, str) or len(value) < 20 or value[4] != "-" or value[7] != "-" or value[10] not in "Tt" \
            or value[13] != ":" or value[16] != ":":
        return None
    try:
        y, mo, d = _int(value[0:4]), _int(value[5:7]), _int(value[8:10])
        h, mi, s = _int(value[11:13]), _int(value[14:16]), _int(value[17:19])
    except ValueError:
        return None
    rest = value[19:]
    if rest.startswith("."):
        i = 1
        while i < len(rest) and "0" <= rest[i] <= "9":
            i += 1
        if i == 1:
            return None
        rest = rest[i:]
    if rest not in ("Z", "z", "+00:00"):
        return None
    if not _valid(y, mo, d, h, mi, s):
        return None
    return to_unix(y, mo, d, h, mi, s)


def iso(t):
    """Unix seconds -> 'YYYY-MM-DDTHH:MM:SSZ' (OpenRouter needs the seconds)."""
    days, rem = divmod(int(t), 86400)
    y, mo, d = civil_from_days(days)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (y, mo, d, rem // 3600, rem % 3600 // 60, rem % 60)
