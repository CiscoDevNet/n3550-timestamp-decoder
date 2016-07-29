#include "record_filter.hpp"
#include "record_reader.hpp"

#include <assert.h>

frame_filter::frame_filter(const std::string& src, int linkty, int snaplen)
: linktype(linkty)
, filter()
{
    pcap_t* handle = pcap_open_dead(linktype, snaplen);
    if (!handle)
        throw std::runtime_error(std::string("unable to prepare filter"));
    if (pcap_compile(handle, &filter, src.c_str(), 1, 0x0))
    {
        std::string err = pcap_geterr(handle);
        pcap_close(handle);
        std::string msg = "unable to compile filter: " + err;
        throw std::invalid_argument(msg);
    }
    pcap_close(handle);
}

frame_filter::~frame_filter()
{
    pcap_freecode(&filter);
}

bool frame_filter::allows(const read_record_t& record, const char* buffer)
{
    assert(linktype == record.linktype);
    struct pcap_pkthdr hdr;
    hdr.len = record.len_orig;
    hdr.caplen = record.len_capture;
    hdr.ts.tv_sec = 0;
    hdr.ts.tv_usec = 0;
    return (pcap_offline_filter(&filter, &hdr, (const unsigned char*)buffer) != 0);
}

