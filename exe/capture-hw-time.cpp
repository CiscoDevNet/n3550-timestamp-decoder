#include <cassert>
#include <iostream>
#include <sstream>
#include "../options.hpp"
#include "../record_reader.hpp"
#include "../record_process.hpp"
#include "../record_writer.hpp"


/**
 * Read hardware timestamped packets from a Exablaze Fusion
 * and convert them to real time.
 * There are two modes:
 *      one reads from pcap
 *      and one from exanic
 * The output is either to a pcap (fixed) or to file/screen.
 */

static void usage(char* exe)
{
    std::cout << "Usage: " << exe << "\n"
              << options::usage_str()
              << std::endl;
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
    if (opt.verbose)
        std::cout << "options:" << opt.to_str() << std::endl;

    std::unique_ptr<record_reader> reader = record_reader::make(opt.read);
    if (!reader)
        return 1;

    std::unique_ptr<record_writer> writer = record_writer::make(opt.write);
    if (!writer)
        return 1;

    // pick a buffer len suitable for largest possible payload and various headers
    const size_t buffer_len = 0x10080;
    char buffer[buffer_len]; 
    record_process proc(opt.process);

    size_t count_packet_in = 0;
    size_t count_packet_out = 0;
    while (true)
    {
        read_record_t record = reader->next(buffer, buffer_len);
        if (record.status == read_record_t::again)
            continue;
        else if (record.status == read_record_t::eof)
            break;
        else if (record.status == read_record_t::error)
        {
            std::cerr << "problem reading record" << std::endl;
            ret = 2;
            break;
        }
        else 
        {
            assert(record.status == read_record_t::ok);
            ++count_packet_in;
            record_time_t timed = proc.process(record, buffer);
            if (timed.status < 0)
            {
                std::cerr << "unrecoverable problem processing records" << std::endl;
                ret = 3;
                break;
            }
            else if (timed.status > 0)
            {
                if (opt.verbose > 2)
                    std::cerr << "recoverable problem processing: " << timed.status << std::endl;
                continue;
            }
            else
            {
                assert(timed.status == record_time_t::ok);
                if (writer->write(timed, record, buffer))
                    break;
                ++count_packet_out;
                if (count_packet_out == opt.count)
                    break;
            }
        }
    }

    if (opt.verbose)
        std::cout << "Read " << count_packet_in << " packets, write " << count_packet_out << std::endl;

    return ret;
}

