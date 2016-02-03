#include "record_process.hpp"
#include "crc32.hpp"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
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
        kf_ether_type = 0x88B5,
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
    case unsupported_keyframe: return "unsupported_keyframe";
    case unsupported_linktype: return "unsupported_linktype";
    case unspecified: return "unspecified";
    case ok: return "ok";
    case record_too_short: return "record_too_short";
    case record_truncated: return "record_truncated";
    case record_no_fcs: return "record_no_fcs";
    case record_time_zero: return "record_time_zero";
    case record_time_missing: return "record_time_missing";
    case missing_recent_keyframe: return "missing_recent_keyframe";
    default:
        return "unknown";
    }
}

record_process::record_process(const process_options& opt)
: options_(opt)
, keyframe_()
{}

uint64_t record_process::ticks_to_nanos(int64_t delta_ticks) const
{
    if (delta_ticks > std::numeric_limits<int64_t>::max()/nanos_per_sec)
        return 0;
    uint64_t nanos = delta_ticks * nanos_per_sec;
    nanos /= keyframe_.freq;
    return nanos;
}

record_time_t record_process::process_keyframe(const keyframe_data& data)
{
    keyframe_ = data;
    record_time_t result(record_time_t::ok);
    result.is_keyframe = true;
    result.hw_nanos = data.utc_nanos;
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
    data.clock_nanos = record.clock_nanos;
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
    data.clock_nanos = record.clock_nanos;
    data.counter = ntohll(kf->asic_time);
    data.arista_compat = true;
    return process_keyframe(data);
}

record_time_t record_process::process(const read_record_t& record, char* buffer)
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
        return process_exa_keyframe(record, ptr, end-ptr);

    // ip v4 packet starts with version info equating to 0x45
    const uint32_t len_eth_ip = sizeof(eth_header_t) + sizeof(ip_header_t);
    if (eth_type == 0x0800 && *ptr == 0x45 && record.len_capture >= len_eth_ip)
    {
        const ip_header_t* ip = reinterpret_cast<const ip_header_t*>(ptr);
        const uint32_t ip_len = ntohs(ip->ip_len);
        ptr += sizeof(ip_header_t);

        if (ip->ip_p == exa_keyframe::kf_proto
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

    uint32_t* packet_fcs = reinterpret_cast<uint32_t*>(end - 4);
    uint32_t* hw_time = reinterpret_cast<uint32_t*>(end - options_.time_offset_end);

    // fallen through, so not a keyframe
    record_time_t result(record_time_t::ok);
    //result.is_keyframe = false;

    // require all packets to have an FCS, which we check first
    uint32_t correct_fcs = crc32(0, buffer, (const char*)packet_fcs - buffer);

    if (options_.use_clock_times)
    {
        result.hw_nanos = record.clock_nanos;
    }
    else
    {
        // check that we have a hardware timestamp
        if (packet_fcs == hw_time && correct_fcs == *hw_time)
        {
            // no hardware timestamp
            result.status = record_time_t::record_time_missing;
            return result;
        }

        // keyframe stored in clock time, not hardware time
        int64_t nanos_last_keyframe = record.clock_nanos - keyframe_.clock_nanos;
        // keyframes published every second
        if (nanos_last_keyframe > static_cast<int64_t>(5*nanos_per_sec))
        {
            result.status = record_time_t::missing_recent_keyframe;
            return result;
        }

        int64_t ticks = ntohl(*hw_time);
        if (!ticks)
        {
            // hw_time is never zero
            result.status = record_time_t::record_time_zero;
            return result;
        }
        else
        {
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
            result.hw_nanos = ticks_to_nanos(ticks);
            result.hw_nanos += keyframe_.utc_nanos;
        }
    }

    if (options_.fix_fcs && correct_fcs != *packet_fcs)
    {
        // copy into buffer
        *packet_fcs = correct_fcs;
        result.fixed_fcs = true;
    }

    return result;
}

