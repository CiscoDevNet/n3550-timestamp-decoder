#include "options.hpp"
#include <sstream>
#include <iostream>
#include <getopt.h>

const char* process_options::timestamp_format_str() const
{
    switch (timestamp_format)
    {
    case timestamp_format_32bit:    return "32bit";
    case timestamp_format_trailer:  return "trailer";
    default:                        return "unknown";
    }
}

std::string options::to_str() const
{
    std::ostringstream os;
    os << "{"
       << " verbose:" << verbose
       << " read:'" << read.source << "'"
       << " promisc:" << read.promiscuous_mode
       << " write:'" << write.dest << "'"
       << " date:'" << write.text_date_format << "'"
       << " count:" << count
       << " all:" << write.write_keyframes
       << " format:" << process.timestamp_format_str()
       << " offset:" << process.time_offset_end
       << " fcs:" << ((process.ignore_fcs || !process.fix_fcs)? "ignore" : "check")
       << " }";
    return os.str();
}

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
        {"trailer",    no_argument,       0, 't'},
        {"ignore-fcs", no_argument,       0, 'f'},
        {"no-promisc", no_argument,       0, 'p'},
        {"pico",       no_argument,       0, 'P'},
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
        case 't':
            process.timestamp_format = process_options::timestamp_format_trailer;
            break;
        case 'f':
            process.ignore_fcs = true;
            break;
        case 'p':
            read.promiscuous_mode = false;
            break;
        case 'P':
            write.write_picos = true;
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
        if (process.time_offset_end == 0)
            process.time_offset_end = 16;
        if (process.time_offset_end != 16 && process.time_offset_end != 20)
        {
            std::cerr << "expected offset to be 16 or 20" << std::endl;
            return -1;
        }
        break;
    case process_options::timestamp_format_32bit:
        // 32 bit timestamps replacing the fcs or appended to the packet
        if (process.time_offset_end == 0)
            process.time_offset_end = 4;
        if (process.time_offset_end != 4 && process.time_offset_end != 8)
        {
            std::cerr << "expected offset to be 4 or 8" << std::endl;
            return -1;
        }
        break;
    default:
        std::cerr << "timestamp format not specified" << std::endl;
        return -1;
    }
    return n;
}

std::string options::usage_str()
{
    std::ostringstream os;
    os << "  --read <arg>      pcap file input, or exanic interface name\n"
       << "  --write <arg>     file for output, - for std out, or ending in .pcap\n"
       << "  --count <arg>     number of records to read, 0 for all\n"
       << "  --date <arg>      date-time format to use for output\n"
       << "  --all             write all packets, including keyframes\n"
       << "  --trailer         parse Exablaze timestamp trailers\n"
       << "  --offset <arg>    hw timestamp offset from the end of packet:\n"
       << "                    4 if the timestamp mode is FCS,\n"
       << "                    8 if the timestamp mode is append\n"
       << "  --ignore-fcs      use this to skip FCS checks\n"
       << "  --no-promisc, -p  do not attempt to put interface in promiscuous mode\n"
       << "  --verbose,    -v  specify more often to be more verbose\n"
       << "  --help,       -h  show this help and exit";
    return os.str();
}

