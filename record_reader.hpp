#pragma once

#include <stdint.h>
#include <string>
#include <memory>
#include "options.hpp"

struct read_record_t
{
    enum status_t
    {
        overflow = -3,
        error = -2,
        eof = -1,
        ok = 0,
        again = 1
    };
    
    int status;
    int linktype;
    uint32_t len_capture;
    uint32_t len_orig;
    uint64_t clock_nanos;
    
    read_record_t(int s = read_record_t::error)
    : status(s)
    , linktype(0)
    , len_capture(0)
    , len_orig(0)
    , clock_nanos(0)
    {}
};

struct record_reader
{
    // will throw on access rights issues or unsupported pcap
    // must be little endian, link type DLT_EN10MB (ethernet), version 2.4
    static std::unique_ptr<record_reader> pcap(const read_options& opt);

    // will throw on access rights issues or invalid interface name
    static std::unique_ptr<record_reader> exanic(const read_options& opt);
    
    // returns empty reader on error (prints any errors to std::cerr)
    static std::unique_ptr<record_reader> make(const read_options& opt) noexcept;
    
    virtual ~record_reader() {}
    
    virtual std::string type() const = 0;
    
    virtual read_record_t next(char* buffer, size_t buffer_len) = 0;
};

