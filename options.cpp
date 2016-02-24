#include "options.hpp"
#include <sstream>
#include <iostream>
#include <getopt.h>

std::string options::to_str() const
{
    std::ostringstream os;
    os << "{"
       << " verbose:" << verbose
       << " read:'" << read.source << "'"
       << " write:'" << write.dest << "'"
       << " date:'" << write.text_date_format << "'"
       << " count:" << count
       << " all:" << write.write_keyframes
       << " offset:" << process.time_offset_end
       << " fcs:" << ((process.ignore_fcs || !process.fix_fcs)? "ignore" : "check")
       << " }";
    return os.str();
}

int options::parse(int argc, char** argv)
{
    static struct option long_options[] =
    {
        { "verbose", no_argument, 0, 'v'},
        { "help", no_argument, 0, 'h'},
        { "all", no_argument, 0, 'a'},
        { "read", required_argument, 0, 'r'},
        { "write", required_argument, 0, 'w'},
        { "date", required_argument, 0, 'd'},
        { "count", required_argument, 0, 'c'},
        { "offset", required_argument, 0, 'o'},
        { "ignore-fcs", no_argument, 0, 'f'},
        { 0,0,0,0 }
    };

    int n = 0;
    while (1)
    {
        int index = 0;
        int c = getopt_long(argc, argv, "vh", long_options, &index);
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
            if (process.time_offset_end != 4 && process.time_offset_end != 8)
            {
                std::cerr << "expected offset to be 4 or 8" << std::endl;
                return -1;
            }
            break;
        case 'f':
            process.ignore_fcs = true;
            break;
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
    return n;
}

std::string options::usage_str()
{
    std::ostringstream os;
    os << "  --read <arg>    pcap file input, or exanic interface name\n"
       << "  --write <arg>   file for output, - for std out, or ending in .pcap\n"
       << "  --count <arg>   number of records to read, 0 for all\n"
       << "  --date <arg>    date-time format to use for output\n"
       << "  --all           write all packets, including keyframes\n"
       << "  --offset <arg>  hw timestamp offset, 4 or 8 depending on mode/FCS capture\n"
       << "  --ignore-fcs    use this to skip FCS checks\n"
       << "  --verbose, -v   be verbose\n"
       << "  --help,    -h   show this help and exit";
    return os.str();
}

