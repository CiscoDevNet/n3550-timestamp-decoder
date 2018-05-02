#pragma once

#include <string>

struct read_options
{
    int verbose = 0;
    std::string source = "";
    bool promiscuous_mode = true;
};

struct process_options
{
    enum
    {
        timestamp_format_32bit = 0,
        timestamp_format_trailer = 1,
    };

    int verbose = 0;
    bool fix_fcs = true;
    bool use_clock_times = false;
    int time_offset_end = 0;
    bool ignore_fcs = false;
    int timestamp_format = timestamp_format_32bit;

    const char* timestamp_format_str() const;
};

struct write_options
{
    int verbose = 0;
    std::string dest = "-";
    bool write_keyframes = false;
    bool write_micros = false;
    bool write_picos = false;
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

