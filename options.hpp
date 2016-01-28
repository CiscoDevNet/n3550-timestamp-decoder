#pragma once

#include <string>

static const uint64_t nanos_per_sec = 1000000000LL;

struct read_options
{
    int verbose = 0;
    std::string source = "";
};

struct process_options
{
    int verbose = 0;
    bool fix_fcs = true;
    bool use_clock_times = false;
    int time_offset_end = 4;
};

struct write_options
{
    int verbose = 0;
    std::string dest = "-";
    bool write_keyframes = false;
    bool write_micros = false;
    bool write_clock_times = true;
    std::string text_date_format = "%Y/%m/%d-%H:%M:%S";
};

struct options
{
    int verbose = 0;
    read_options read = read_options();
    process_options process = process_options();
    write_options write = write_options();
    uint32_t count = 0;

    std::string to_str() const;
    int parse(int argc, char** argv);

    static std::string usage_str();
};

