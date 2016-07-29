#pragma once

#include "record_reader.hpp"
#include "options.hpp"
#include <memory>

struct record_time_t
{
    // negative status are unrecoverable
    enum status_t
    {
        unsupported_keyframe = -3,
        unsupported_linktype = -2,
        unspecified = -1,
        ok = 0,
        record_too_short = 1,
        record_truncated = 2,
        record_no_fcs = 3,
        record_time_zero = 4,
        record_time_missing = 5,
        missing_recent_keyframe = 6,
        filtered = 7,
    };

    int status;
    bool is_keyframe;
    bool fixed_fcs;
    uint64_t hw_nanos;

    record_time_t(int s = record_time_t::unspecified)
    : status(s)
    , is_keyframe(false)
    , fixed_fcs(false)
    , hw_nanos(0)
    {}

    const char* status_str() const;
};

struct frame_filter;

struct record_process
{
private:
    struct keyframe_data
    {
        uint64_t utc_nanos;
        uint64_t clock_nanos;
        uint64_t counter;
        uint64_t freq;
        bool arista_compat;

        keyframe_data()
        : utc_nanos(0)
        , clock_nanos(0)
        , counter(0)
        , freq(350000000) // 350MHz standard
        , arista_compat(false)
        {}
    };

    const process_options options_;
    keyframe_data keyframe_;
    std::shared_ptr<frame_filter> filter_;

public:
    record_process(const process_options& opt);

    record_time_t process(const read_record_t& record, char* buffer);

private:
    uint64_t ticks_to_nanos(int64_t delta_ticks) const;
    record_time_t process_keyframe(const keyframe_data& data);
    record_time_t process_exa_keyframe(const read_record_t& record, const char* keyframe, size_t len);
    record_time_t process_compat_keyframe(const read_record_t& record, const char* keyframe, size_t len);

};

