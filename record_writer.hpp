#pragma once

#include <memory>
#include "options.hpp"

struct read_record_t;
struct record_time_t;

struct record_writer
{
    record_time_t*  prev_time =NULL;
    // construct pcap writer, throw if any issues
    static std::unique_ptr<record_writer> pcap(const write_options& opt);

    // construct text writer for file or terminal, throw if any issues
    static std::unique_ptr<record_writer> text(const write_options& opt);
    
    // pick writer type to construct using name of output
    static std::unique_ptr<record_writer> make(const write_options& opt) noexcept;
    
    virtual ~record_writer() {}
    
    virtual std::string type() const = 0;
    
    // return zero on success, negative for an error, positive if the record is ignored
    virtual int write(const record_time_t& time, const read_record_t& record, const char* buffer) = 0;
};

