#pragma once

#include <pcap/pcap.h>

#include <string>

struct read_record_t;

struct frame_filter
{
    int linktype;
    bpf_program filter;

    frame_filter(const std::string& src, int linktype, int snaplen);
    ~frame_filter();

    bool allows(const read_record_t& record, const char* buffer);
};
