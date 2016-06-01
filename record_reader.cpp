#include "record_reader.hpp"
#include "pcap_common.hpp"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_if.h>
#include <exanic/time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct pcap_record_reader : public record_reader
{
    std::ifstream is;
    bool nanos;
    
    pcap_record_reader(const std::string& fname)
    : is(fname.c_str())
    , nanos(false)
    {
        if (!is.good())
            throw std::invalid_argument(std::string("could not open file"));
        pcap_file_header_t header;
        is.read((char*)&header, sizeof(header));
        if (!is.good())
            throw std::invalid_argument(std::string("could not read pcap header"));
        
        if (header.version_major != 2 || header.version_minor != 4)
            throw std::invalid_argument(std::string("unsupported pcap version"));
        
        if (header.linktype != DLT_EN10MB)
            throw std::invalid_argument(std::string("unsupported pcap linktype"));
        
        if (header.magic == pcap_magic_t::nanos_magic)
            nanos = true;
        else if (header.magic != pcap_magic_t::micro_magic)
            throw std::invalid_argument(std::string("unsupported pcap architecture"));
    }
    
    virtual ~pcap_record_reader()
    {
        is.close();
    }
    
    std::string type() const override
    {
        return "pcap";
    }
    
    // for pcap the read is blocking
    read_record_t next(char* buffer, size_t buffer_len) override
    {
        if (!is.is_open())
            return read_record_t(read_record_t::eof);
        // packet_t in host endian format, so can be read directly
        pcap_header_t header;
        is.read((char*)&header, sizeof(header));

        if (is.eof())
            return read_record_t(read_record_t::eof);
        if (!is.good())
            return read_record_t(read_record_t::error);
        
        read_record_t record;
        record.linktype = DLT_EN10MB;
        record.len_capture = header.len_capture;
        record.len_orig = header.len_orig;
        record.clock_nanos = header.tv_secs * nanos_per_sec;
        if (nanos)
            record.clock_nanos += header.tv_frac;
        else
            record.clock_nanos += (header.tv_frac*1000);
        
        size_t to_read = (record.len_capture < buffer_len) ? record.len_capture : buffer_len;
        is.read(buffer, to_read);
        if (is.good())
            record.status = read_record_t::ok;
        return record;
    }
};

struct exanic_reader : public record_reader
{
    exanic_t* exa;
    exanic_rx_t* rx;

    exanic_reader(const exanic_reader&) = delete;
    void operator=(const exanic_reader&) = delete;
    
    exanic_reader(const std::string& interface)
    : exa(nullptr)
    , rx(nullptr)
    {
        char device[24];
        int devport = 0;
        if (exanic_find_port_by_interface_name(interface.c_str(), device, sizeof(device), &devport)
            && parse_device_port(interface, device, sizeof(device), devport))
        {
            throw std::invalid_argument(std::string("could not find interface"));
        }
        
        exa = exanic_acquire_handle(device);
        if (!exa)
            throw std::invalid_argument(std::string("could not acquire device"));
        
        rx = exanic_acquire_rx_buffer(exa, devport, 0);
        if (!rx)
        {
            exanic_release_handle(exa);
            exa = nullptr;
            throw std::invalid_argument(std::string("could not acquire rx buffer"));
        }
    }
    
    virtual ~exanic_reader()
    {
        if (rx)
            exanic_release_rx_buffer(rx);
        if (exa)
            exanic_release_handle(exa);
    }
    
    std::string type() const override
    {
        return "exanic";
    }

    int parse_device_port(const std::string& name, char* device, size_t max_len, int& port) const
    {
        size_t pos = name.find(':');
        if (pos == std::string::npos || pos >= max_len)
            return -1;

        memcpy(device, name.c_str(), pos);
        device[pos] = 0;
        port = std::stoi(name.substr(pos+1));
        return 0;
    }
    
    read_record_t next(char* buffer, size_t buffer_len) override
    {
        uint32_t timestamp = 0;
        int status = 0;
        int offset = exanic_receive_frame_ex(rx, buffer, buffer_len, &timestamp, &status);
        int orig = offset;
        if (status == EXANIC_RX_FRAME_SWOVFL)
            return read_record_t(read_record_t::overflow);
        else if (status == EXANIC_RX_FRAME_TRUNCATED)
            ++orig; // dont have orig length
        else if (offset < 0)
            return read_record_t(read_record_t::again);
        
        read_record_t record(read_record_t::ok);
        record.linktype = DLT_EN10MB;
        record.clock_nanos = exanic_timestamp_to_counter(exa, timestamp);
        record.len_capture = offset;
        record.len_orig = orig;
        return record;
    }
    
    // copied from exanic-capture
    ssize_t exanic_receive_frame_ex(exanic_rx_t *rx, char *rx_buf,
                                    size_t rx_buf_size, uint32_t *timestamp,
                                    int *frame_status)
    {
        union {
            struct rx_chunk_info info;
            uint64_t data;
        } u;

        u.data = rx->buffer[rx->next_chunk].u.data;

        if (u.info.generation == rx->generation)
        {
            size_t size = 0;

            /* Next expected packet */
            while (1)
            {
                const char *payload = (char *)rx->buffer[rx->next_chunk].payload;

                /* Advance next_chunk to next chunk */
                rx->next_chunk++;
                if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
                {   
                    rx->next_chunk = 0;
                    rx->generation++;
                }

                /* Process current chunk */
                if (u.info.length != 0)
                {
                    /* Last chunk */
                    if (size + u.info.length > rx_buf_size)
                    {   
                        if (frame_status != NULL)
                            *frame_status = EXANIC_RX_FRAME_TRUNCATED;
                        return -1;
                    }

                    memcpy(rx_buf + size, payload, u.info.length);
                    size += u.info.length;

                    /* TODO: Recheck that we haven't been lapped */

                    if (timestamp != NULL)
                        *timestamp = u.info.timestamp;

                    if (frame_status != NULL)
                        *frame_status =
                            (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

                    return size;
                }
                else
                {
                    /* More chunks to come */
                    if (size + EXANIC_RX_CHUNK_PAYLOAD_SIZE <= rx_buf_size)
                        memcpy(rx_buf + size, payload,
                                EXANIC_RX_CHUNK_PAYLOAD_SIZE);
                    size += EXANIC_RX_CHUNK_PAYLOAD_SIZE;

                    /* Spin on next chunk */
                    do
                        u.data = rx->buffer[rx->next_chunk].u.data;
                    while (u.info.generation == (uint8_t)(rx->generation - 1));

                    if (u.info.generation != rx->generation)
                    {
                        /* Got lapped? */
                        __exanic_rx_catchup(rx);
                        if (frame_status != NULL)
                            *frame_status = EXANIC_RX_FRAME_SWOVFL;
                        return -1;
                    }
                }
            }
        }
        else if (u.info.generation == (uint8_t)(rx->generation - 1))
        {
            /* No new packet */
            if (frame_status != NULL)
                *frame_status = 0;
            return -1;
        }
        else
        {
            /* Got lapped? */
            __exanic_rx_catchup(rx);
            if (frame_status != NULL)
                *frame_status = EXANIC_RX_FRAME_SWOVFL;
            return -1;
        }
    }
};

std::unique_ptr<record_reader> record_reader::pcap(const read_options& opt)
{
    return std::unique_ptr<record_reader>(new pcap_record_reader(opt.source));
}

std::unique_ptr<record_reader> record_reader::exanic(const read_options& opt)
{
    return std::unique_ptr<record_reader>(new exanic_reader(opt.source));
}

std::unique_ptr<record_reader> record_reader::make(const read_options& opt) noexcept
{
    try
    {
        /*
         * Choose file reader if we can find the named file, or
         * if the arg ends with standard pcap extention.
         */
        const size_t src_len = opt.source.size();
        struct stat stats;
        const bool is_file = (src_len>5 && opt.source.substr(src_len-5) == ".pcap")
            || (::stat(opt.source.c_str(), &stats) == 0);
        if (is_file)
            return record_reader::pcap(opt);
        else
            return record_reader::exanic(opt);
    }
    catch (std::exception& e)
    {
        std::cerr << "Problem creating reader: " << e.what() << std::endl;
        return std::unique_ptr<record_reader>();
    }
}

