#pragma once

#include "record_reader.hpp"
#include "options.hpp"
#include "pstime.hpp"

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
        unknown_format = 7,
    };

    int status;
    bool is_keyframe;
    bool fixed_fcs;
    pstime_t hw_time;
    int device_id;
    int port;

    record_time_t(int s = record_time_t::unspecified)
    : status(s)
    , is_keyframe(false)
    , fixed_fcs(false)
    , hw_time(0, 0)
    , device_id(-1)
    , port(-1)
    {}

    const char* status_str() const;
};

struct record_process
{
private:
    struct keyframe_data
    {
        uint64_t utc_nanos;
        uint64_t counter;
        uint64_t freq;
        bool arista_compat;
        pstime_t clock_time;

        keyframe_data()
        : utc_nanos(0)
        , counter(0)
        , freq(350000000) // 350MHz standard
        , arista_compat(false)
        , clock_time(0, 0)
        {}
    };

    const process_options options_;
    keyframe_data keyframe_;
    int time_offset_end_;
    int timestamp_format_;

public:
    record_process(const process_options& opt);

    record_time_t process(const read_record_t& record, char* buffer);

private:
    int64_t ticks_since_last_keyframe(const uint32_t* hw_time);

    record_time_t process_keyframe(const keyframe_data& data);
    record_time_t process_exa_keyframe(const read_record_t& record, const char* keyframe, size_t len);
    record_time_t process_compat_keyframe(const read_record_t& record, const char* keyframe, size_t len);

    record_time_t process_32bit_timestamps(const read_record_t& record, char* buffer);
    record_time_t process_trailer_timestamps(const read_record_t& record, char* buffer, bool force_trailer_mode);
};

