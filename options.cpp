#include "options.hpp"
#include <sstream>
#include <iostream>
#include <getopt.h>

int options::parse(int argc, char** argv)
{
    static struct option long_options[] =
    {
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {"all",        no_argument,       0, 'a'},
        {"read",       required_argument, 0, 'r'},
        {"write",      required_argument, 0, 'w'},
        {"date",       required_argument, 0, 'd'},
        {"count",      required_argument, 0, 'c'},
        {"offset",     required_argument, 0, 'o'},
        {"32-bit",     no_argument,       0, '3'},
        {"trailer",    no_argument,       0, 't'},
        {"no-fix-fcs", no_argument,       0, 'f'},
        {"no-promisc", no_argument,       0, 'p'},
        {"no-payload", no_argument,       0, 'n'},
        {0, 0,                            0, 0}
    };

    int n = 0;
    while (1)
    {
        int index = 0;
        int c = getopt_long(argc, argv, "pvh?", long_options, &index);
        if (c == -1)
            break;
        switch (c)
        {
        case 'v':
            ++verbose;
            read.verbose = verbose;
            process.verbose = verbose;
            write.verbose = verbose;
            break;
        case 'r':
            ++n;
            read.source = optarg;
            break;
        case 'w':
            ++n;
            write.dest = optarg;
            break;
        case 'd':
            ++n;
            write.text_date_format = optarg;
            break;
        case 'c':
            ++n;
            count = std::atoi(optarg);
            break;
        case 'a':
            write.write_keyframes = true;
            break;
        case 'o':
            process.time_offset_end = std::atoi(optarg);
            break;
        case '3':
            process.timestamp_format = process_options::timestamp_format_32bit;
            break;
        case 't':
            process.timestamp_format = process_options::timestamp_format_trailer;
            break;
        case 'f':
            process.fix_fcs = false;
            break;
        case 'p':
            read.promiscuous_mode = false;
            break;
        case 'n':
            write.write_packet = false;
            break;
        case '?':
        case 'h':
            return 0;
        default:
            return -1;
        }
    }
    if (optind < argc)
    {
        std::cerr << argv[0] << ": unhandled arg '" << argv[optind] << "'" << std::endl;
        return -1;
    }
    switch (process.timestamp_format)
    {
    case process_options::timestamp_format_trailer:
        // 16 byte exablaze timestamp trailer appended to the packet
        if (process.time_offset_end != -1 && process.time_offset_end != 16 && process.time_offset_end != 20)
        {
            std::cerr << argv[0] << ": offset must be 16 or 20" << std::endl;
            return -1;
        }
        break;
    case process_options::timestamp_format_32bit:
        // 32 bit timestamps replacing the fcs or appended to the packet
        if (process.time_offset_end != -1 && process.time_offset_end != 4 && process.time_offset_end != 8)
        {
            std::cerr << argv[0] << ": offset must be 4 or 8" << std::endl;
            return -1;
        }
        break;
    default:
        if (process.time_offset_end != -1)
        {
            std::cerr << argv[0] << ": timestamp format must be provided: "
                      << "either --32bit or --trailer" << std::endl;
            return -1;
        }
        break;
    }
    return n;
}

std::string options::usage_str()
{
    std::ostringstream os;
    os << "Input options:\n"
       << "  --read <arg>      pcap file input, or exanic interface name\n"
       << "  --count <arg>     number of records to read, 0 for all\n"
       << "  --no-promisc, -p  do not attempt to put interface in promiscuous mode\n"
       << "\n"
       << "Output options:\n"
       << "  --write <arg>     file for output, - for stdout, or ending in .pcap\n"
       << "  --date <arg>      date-time format to use for output\n"
       << "  --all             write all packets, including keyframes\n"
       << "  --no-payload      don't write packet contents to stdout\n"
       << "\n"
       << "Timestamp options:\n"
       << "  --32-bit          parse 32 bit timestamps\n"
       << "  --trailer         parse Exablaze timestamp trailers\n"
       << "  --offset <arg>    timestamp offset from the end of packet\n"
       << "  --no-fix-fcs      don't rewrite 32 bit timestamp with correct FCS\n"
       << "\n"
       << "Other options:\n"
       << "  --verbose,    -v  specify more often to be more verbose\n"
       << "  --help,       -h  show this help and exit";
    return os.str();
}

