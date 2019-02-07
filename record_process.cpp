#include "record_process.hpp"
#include "crc32.hpp"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <math.h>
#include <limits>
#include <iostream>

using eth_header_t = struct ether_header;
using ip_header_t = struct ip;
using arp_header_t = struct arphdr;

struct exa_keyframe
{
    enum
    {
        kf_version = 1,
        kf_magic = 0x464b5845,
        kf_ether_type = 0x88B5, // local experimental ethernet type
        kf_proto = 253 // depends on fusion version
    };

    uint32_t magic;
    uint8_t version;
    uint8_t __reserved[3];

    uint64_t utc;
    uint64_t counter;
    uint64_t freq;
    uint64_t last_sync;

} __attribute__((packed));

struct compat_keyframe
{
    enum
    {
        ckf_proto = 253,
        ckf_src = 0,
        ckf_dest = 0xFFFFFFFF,
        ckf_skeq = 1
    };

    uint64_t asic_time;
    uint64_t utc;
    uint64_t last_sync;
    uint64_t skew_num;
    uint64_t skew_denom;
    uint64_t timestamp;
    uint64_t drop_count;
    uint16_t device_id;
    uint16_t egress_port;
    uint8_t fcs_type;
    uint8_t __reserved;

} __attribute__((packed));

struct exablaze_timestamp_trailer
{
    uint32_t original_fcs;
    uint8_t device_id;
    uint8_t port;
    uint32_t seconds_since_epoch;
    uint8_t frac_seconds[5];
    uint8_t __reserved;

} __attribute__((packed));

#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htonll(x) __bswap_64(x)
#  define ntohll(x) __bswap_64(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#  define htonll(x) (x)
#  define ntohll(x) (x)
#else
#  error Unknown byte order
#endif

const char* record_time_t::status_str() const
{
    switch (status)
    {
    case unsupported_keyframe:      return "unsupported_keyframe";
    case unsupported_linktype:      return "unsupported_linktype";
    case unspecified:               return "unspecified";
    case ok:                        return "ok";
    case record_too_short:          return "record_too_short";
    case record_truncated:          return "record_truncated";
    case record_no_fcs:             return "record_no_fcs";
    case record_time_zero:          return "record_time_zero";
    case record_time_missing:       return "record_time_missing";
    case missing_recent_keyframe:   return "missing_recent_keyframe";
    default:
        return "unknown";
    }
}

record_process::record_process(const process_options& opt)
: options_(opt)
, keyframe_()
, time_offset_end_(opt.time_offset_end)
, timestamp_format_(opt.timestamp_format)
{}

record_time_t record_process::process_keyframe(const keyframe_data& data)
{
    keyframe_ = data;
    record_time_t result(record_time_t::ok);
    result.is_keyframe = true;
    result.hw_time = ns_to_pstime(data.utc_nanos);
    return result;
}

record_time_t record_process::process_exa_keyframe(const read_record_t& record, const char* keyframe, size_t len)
{
    const exa_keyframe* kf = reinterpret_cast<const exa_keyframe*>(keyframe);
    // TODO: check that we have magic in correct endian
    if (!(kf->version == 1 && kf->magic == exa_keyframe::kf_magic) && !(kf->version == 0 && kf->magic == 1))
        return record_time_t(record_time_t::unsupported_keyframe);

    keyframe_data data;
    data.utc_nanos = ntohll(kf->utc);
    data.clock_time = record.clock_time;
    data.counter = ntohll(kf->counter);
    data.freq = ntohll(kf->freq);
    return process_keyframe(data);
}

record_time_t record_process::process_compat_keyframe(const read_record_t& record, const char* keyframe, size_t len)
{
    const compat_keyframe* kf = reinterpret_cast<const compat_keyframe*>(keyframe);
    if (ntohll(kf->skew_num) != 1 || ntohll(kf->skew_denom) != 1)
        return record_time_t(record_time_t::unsupported_keyframe);

    keyframe_data data;
    data.utc_nanos = ntohll(kf->utc);
    data.clock_time = record.clock_time;
    data.counter = ntohll(kf->asic_time);
    data.arista_compat = true;
    return process_keyframe(data);
}


int64_t record_process::ticks_since_last_keyframe(const uint32_t* hw_time)
{
    int64_t ticks = ntohl(*hw_time);
    if (keyframe_.arista_compat)
    {
        ticks = ((ticks & ~0xff) >> 1) + (ticks & 0x7f);
        ticks -= (keyframe_.counter & 0x7fffffff);
        // handle tick rollover
        if (ticks < 0)
            ticks += 0x80000000;
    }
    else
    {
        ticks -= (keyframe_.counter & 0xffffffff);
        // handle tick rollover
        if (ticks < 0)
            ticks += 0x100000000;
    }
    return ticks;
}

record_time_t record_process::process_32bit_timestamps(const read_record_t& record, char* buffer)
{
    // only deal with ethernet frames
    if (record.linktype != DLT_EN10MB)
        return record_time_t(record_time_t::unsupported_linktype);

    // too short to be relevant
    if (record.len_capture < sizeof(eth_header_t))
        return record_time_t(record_time_t::record_too_short);

    // to process hardware time or fcs, we need whole packet
    if (record.len_capture != record.len_orig)
        return record_time_t(record_time_t::record_truncated);

    char* ptr = buffer;
    char* end = buffer + record.len_capture;

    const eth_header_t* eth = reinterpret_cast<const eth_header_t*>(ptr);
    const uint32_t eth_type = ntohs(eth->ether_type);
    ptr += sizeof(eth_header_t);

    if (eth_type == exa_keyframe::kf_ether_type)
    {
        const record_time_t ret = process_exa_keyframe(record, ptr, end - ptr);
        if (ret.status != record_time_t::unsupported_keyframe)
            return ret;
        // else fall through and try get the timestamp from the
        // unrecognised packet
    }
    else if (eth_type == 0x0800 && *ptr == 0x45)
    {
        const uint32_t len_eth_ip = sizeof(eth_header_t) + sizeof(ip_header_t);
        if (record.len_capture < len_eth_ip)
            return record_time_t(record_time_t::record_too_short);

        const ip_header_t* ip = reinterpret_cast<const ip_header_t*>(ptr);
        const uint32_t ip_len = ntohs(ip->ip_len);
        ptr += sizeof(ip_header_t);

        if (ip->ip_p == compat_keyframe::ckf_proto
            && ip->ip_ttl == IPDEFTTL
            && ip->ip_dst.s_addr == compat_keyframe::ckf_dest
            && ip->ip_src.s_addr == compat_keyframe::ckf_src )
        {
            uint32_t len = ip_len - sizeof(ip_header_t);
            if (len == sizeof(exa_keyframe))
                return process_exa_keyframe(record, ptr, end-ptr);
            else if (len == sizeof(compat_keyframe))
                return process_compat_keyframe(record, ptr, end-ptr);
            // else treat as normal ip packet
        }
    }

    // fallen through, so not a (recognised) keyframe

    pstime_t time_since_last_keyframe = record.clock_time - keyframe_.clock_time;
    // keyframes published every second, allow for some missing
    if (time_since_last_keyframe > pstime_t(5, 0))
    {
        // missed too many keyframes
        return record_time_t(record_time_t::missing_recent_keyframe);
    }

    if (time_offset_end_ == -1)
    {
        // heuristics to find the timestamp offset
        bool crc_valid = (crc32(0, buffer, end - buffer) == 0x2144DF1C);

        int64_t ticks4 = ticks_since_last_keyframe(reinterpret_cast<const uint32_t*>(end - 4));
        int64_t ticks8 = ticks_since_last_keyframe(reinterpret_cast<const uint32_t*>(end - 8));

        int64_t diff4 = ticks4 * 1000000000 / keyframe_.freq - time_since_last_keyframe.ns();
        int64_t diff8 = ticks8 * 1000000000 / keyframe_.freq - time_since_last_keyframe.ns();

        const int64_t max_diff = 10000000;

        if (-max_diff < diff4 && diff4 < max_diff && !crc_valid)
        {
            // last 4 bytes is a timestamp and not the FCS
            time_offset_end_ = 4;
            if (options_.verbose)
                std::cout << "Found 32 bit timestamp at offset " << time_offset_end_ <<
                    " from end of packet" << std::endl;
        }
        else if (-max_diff < diff8 && diff8 < max_diff && crc_valid)
        {
            // last 4 bytes is valid FCS, and a valid timestamp is before the FCS
            time_offset_end_ = 8;
            if (options_.verbose)
                std::cout << "Found 32 bit timestamp at offset " << time_offset_end_ <<
                    " from end of packet" << std::endl;
        }
        else
        {
            // could not find a valid timestamp
            return record_time_t(record_time_t::record_time_missing);
        }
    }

    record_time_t result(record_time_t::ok);

    int64_t ticks = ticks_since_last_keyframe(reinterpret_cast<const uint32_t*>(end - time_offset_end_));
    int64_t delta_ns = ticks * 1000000000 / keyframe_.freq;
    result.hw_time = ns_to_pstime(keyframe_.utc_nanos + delta_ns);

    if (time_offset_end_ == 4 && options_.fix_fcs)
    {
        // overwrite timestamp with recalculated FCS
        uint32_t* packet_fcs = reinterpret_cast<uint32_t*>(end - 4);
        *packet_fcs = crc32(0, buffer, end - buffer - 4);
        result.fixed_fcs = true;
    }

    return result;
}

record_time_t record_process::process_trailer_timestamps(const read_record_t& record, char* buffer)
{
    // only deal with ethernet frames
    if (record.linktype != DLT_EN10MB)
        return record_time_t(record_time_t::unsupported_linktype);

    // too short to be relevant
    if (record.len_capture < sizeof(exablaze_timestamp_trailer))
        return record_time_t(record_time_t::record_too_short);

    // to process hardware time or fcs, we need whole packet
    if (record.len_capture != record.len_orig)
        return record_time_t(record_time_t::record_truncated);

    char* ptr = buffer;
    char* end = buffer + record.len_capture;

    if (time_offset_end_ == -1)
    {
        // heuristics to find the timestamp offset
        // timestamp is considered valid if it is within a week of the capture time
        const time_t max_diff = 604800;

        for (unsigned extra = 0; extra <= 4; extra += 4)
        {
            if (end - ptr < sizeof(exablaze_timestamp_trailer) + extra)
                continue;

            const exablaze_timestamp_trailer* trailer =
                reinterpret_cast<const exablaze_timestamp_trailer*>(end -
                        sizeof(exablaze_timestamp_trailer) - extra);
            time_t sec = ntohl(trailer->seconds_since_epoch);
            time_t diff;

            // compare to wall clock time if it is a live capture
            if (record.is_real_time)
                diff = sec - time(NULL);
            else
                diff = sec - record.clock_time.sec;

            if (diff < -max_diff || max_diff < diff)
                continue;

            time_offset_end_ = sizeof(exablaze_timestamp_trailer) + extra;
            if (options_.verbose)
                std::cout << "Found Exablaze timestamp trailer at offset " <<
                    time_offset_end_ << " from end of packet" << std::endl;
            break;
        }

        if (time_offset_end_ == -1)
        {
            // could not find a valid timestamp
            return record_time_t(record_time_t::record_time_missing);
        }
    }

    if (end - ptr < time_offset_end_)
        return record_time_t(record_time_t::record_too_short);

    const exablaze_timestamp_trailer* trailer =
        reinterpret_cast<const exablaze_timestamp_trailer*>(end - time_offset_end_);

    uint32_t seconds_since_epoch = ntohl(trailer->seconds_since_epoch);
    double frac_seconds = ldexp((uint64_t(trailer->frac_seconds[0]) << 32) |
        (uint64_t(trailer->frac_seconds[1]) << 24) | (uint64_t(trailer->frac_seconds[2]) << 16) |
        (uint64_t(trailer->frac_seconds[3]) << 8) | uint64_t(trailer->frac_seconds[4]), -40);

    record_time_t result(record_time_t::ok);
    result.hw_time = pstime_t(seconds_since_epoch, frac_seconds * 1000000000000ULL);
    result.device_id = trailer->device_id;
    result.port = trailer->port;

    return result;
}

record_time_t record_process::process(const read_record_t& record, char* buffer)
{
    switch (timestamp_format_)
    {
    case process_options::timestamp_format_32bit:
        return process_32bit_timestamps(record, buffer);
    case process_options::timestamp_format_trailer:
        return process_trailer_timestamps(record, buffer);
    default:
        {
            // look for exablaze timestamp trailer
            record_time_t result = process_trailer_timestamps(record, buffer);
            if (result.status == record_time_t::ok)
            {
                timestamp_format_ = process_options::timestamp_format_trailer;
                return result;
            }
            else
            {
                // if trailer not found, parse as 32 bit timestamp
                result = process_32bit_timestamps(record, buffer);
                if (result.status == record_time_t::ok)
                    timestamp_format_ = process_options::timestamp_format_32bit;
                return result;
            }
        }
    }
}
