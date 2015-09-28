#pragma once

#include <pcap.h>

struct pcap_header_t
{
    uint32_t tv_secs;
    uint32_t tv_frac;
    uint32_t len_capture;
    uint32_t len_orig;
};

using pcap_file_header_t = struct pcap_file_header;

struct pcap_magic_t
{
    enum 
    {
        micro_magic = 0xa1b2c3d4,
        nanos_magic = 0xa1b23c4d         
    };
};

