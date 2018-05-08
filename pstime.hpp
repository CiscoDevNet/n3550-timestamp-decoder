#pragma once

struct pstime_t
{
    time_t sec;
    uint64_t psec;
    unsigned precision;

    pstime_t(time_t s, uint64_t ps, unsigned prec = 12)
    : sec(s)
    , psec(ps)
    , precision(prec)
    {}

    operator bool() const { return sec || psec; }
    explicit operator double() const { return sec + (psec / 1e12); }

    pstime_t operator-(const pstime_t& rhs) const
    {
        unsigned p = precision < rhs.precision ? precision : rhs.precision;
        if (psec < rhs.psec)
            return pstime_t(sec - rhs.sec - 1, 1000000000000ULL + psec - rhs.psec, p);
        else
            return pstime_t(sec - rhs.sec, psec - rhs.psec, p);
    }

    bool operator<(const pstime_t& rhs) const
    {
        return sec < rhs.sec || (sec == rhs.sec && psec < rhs.psec);
    }

    bool operator>(const pstime_t& rhs) const
    {
        return sec > rhs.sec || (sec == rhs.sec && psec > rhs.psec);
    }

    int64_t ns() const { return (sec * 1000000000LL) + (psec / 1000); }
};

static inline pstime_t ns_to_pstime(uint64_t ns)
{
    return pstime_t(ns / 1000000000, (ns % 1000000000) * 1000, 9);
}
