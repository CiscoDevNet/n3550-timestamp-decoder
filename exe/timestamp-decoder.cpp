#include <cassert>
#include <iostream>
#include <sstream>
#include <signal.h>
#include "../options.hpp"
#include "../record_reader.hpp"
#include "../record_process.hpp"
#include "../record_writer.hpp"
#include "../crc32.hpp"

/**
 * Read hardware timestamped packets from a Exablaze Fusion
 * and convert them to real time.
 * There are two modes:
 *      one reads from pcap
 *      and one from exanic
 * The output is either to a pcap (fixed) or to file/screen.
 */

static int g_running = 1;

void signal_handler(int signal)
{
    g_running = 0;
}

enum struct return_value : int
{
    ok = 0,
    initialisation,
    reader_error,
    process_error,
    fault,
};

static void usage(char* exe)
{
    std::cout << "Usage: " << exe << "\n"
              << options::usage_str()
              << std::endl;
}

static void print_record(std::ostream& os, const char* buffer, size_t len,
                   const char* prefix = "    ")
{
    const char digits[] = "0123456789abcdef";
    const char* p = buffer;
    const char* end = p + len;
    int block = 0;
    while (p < end)
    {
        if (block)
            os << ' ';
        else
            os << prefix;
        for (size_t j = 0; j < 8 && p < end; ++j, ++p)
        {
            const uint8_t c = *p;
            os << digits[ (c >> 4) & 0xf ];
            os << digits[ c & 0xf ];
        }
        ++block;
        if (block == 4)
        {
            os << std::endl;
            block = 0;
        }
    }
    if (len > 4)
    {
        uint32_t fcs = crc32(0, buffer, len - 4);
        if (block)
            os << "     fcs=";
        else
            os << prefix << "    fcs=";
        for (int i = 0; i < 32; i += 8)
        {
            os << digits[(fcs >> (i+4)) & 0xf];
            os << digits[(fcs >> i) & 0xf];
        }
        os << std::endl;
    }
    else if (block)
        os << std::endl;
}

int main(int argc, char** argv)
{
    options opt;
    int ret = opt.parse(argc, argv);
    if (ret <= 0)
    {
        usage(argv[0]);
        return ret;
    }
    if (opt.verbose > 1)
        std::cout << "options: " << opt.to_str() << std::endl;

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGTERM, signal_handler);

    std::unique_ptr<record_reader> reader = record_reader::make(opt.read);
    if (!reader)
        return (int)return_value::initialisation;

    std::unique_ptr<record_writer> writer = record_writer::make(opt.write);
    if (!writer)
        return (int)return_value::initialisation;

    // pick a buffer len suitable for largest possible payload and various headers
    const size_t buffer_len = 0x10080;
    char buffer[buffer_len]; 
    record_process proc(opt.process);

    size_t count_packet_in = 0;
    size_t count_packet_out = 0;
    size_t count_errors = 0;
    size_t count_key_frames = 0;
    while (g_running)
    {
        read_record_t record = reader->next(buffer, buffer_len);
        if (record.status == read_record_t::again)
            continue;
        else if (record.status == read_record_t::eof)
            break;

        ++count_packet_in;
        if (record.status == read_record_t::ok)
        {
            record_time_t timed = proc.process(record, buffer);
            if (timed.status < 0)
            {
                std::cerr << "unrecoverable error processing record #"
                          <<  count_packet_in << " ("
                          << record.len_capture << " bytes): " << timed.status_str()
                          << std::endl;
                if (opt.verbose)
                    print_record(std::cerr, buffer, record.len_capture);
                ret = (int)return_value::process_error;
                ++count_errors;
                break;
            }
            else if (timed.status == record_time_t::record_time_missing && opt.write.write_all)
            {
                // lets this fall through, using clock time
            }
            else if (timed.status > 0)
            {
                if (opt.verbose > 1)
                {
                    std::cerr << "recoverable problem processing record #"
                              <<  count_packet_in << " ("
                              << record.len_capture << " bytes): " << timed.status_str()
                              << std::endl;
                    if (opt.verbose > 2)
                        print_record(std::cerr, buffer, record.len_capture);
                }
                ++count_errors;
                continue;
            }
            else
            {
                assert(timed.status == record_time_t::ok);
            }

            if (timed.is_keyframe)
                ++count_key_frames;
            const int err = writer->write(timed, record, buffer);
            if (err < 0)
            {
                if (opt.verbose)
                {
                    std::cerr << "unrecoverable write error (" << err << ")"
                              << std::endl;
                }
                ++count_errors;
                break;
            }
            else if (!err)
            {
                ++count_packet_out;
                if (count_packet_out == opt.count)
                    break;
            }
            // else its a key frame that is intentionally skipped
        }
        else if (record.status == read_record_t::error)
        {
            std::cerr << "problem reading record #" << count_packet_in << std::endl;
            ret = (int)return_value::reader_error;
            ++count_errors;
            break;
        }
        else if (record.status == read_record_t::overflow)
        {
            std::cerr << "overflow when reading record  #" << count_packet_in << std::endl;
            ret = (int)return_value::reader_error;
            ++count_errors;
            break;
        }
        else
        {
            std::cerr << "unknown record status" << std::endl;
            ret = (int)return_value::fault;
            ++count_errors;
            break;
        }
    }

    if (opt.verbose)
    {
        std::cout << "Packets: read " << count_packet_in
                  << ", key frames " << count_key_frames
                  << ", written " << count_packet_out
                  << ", errors " << count_errors
                  << std::endl;
    }
    return ret;
}

