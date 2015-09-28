#include "options.hpp"
#include <sstream>
#include <iostream>
#include <getopt.h>

std::string options::to_str() const
{
    std::ostringstream os;
    os << "{"
       << " verbose:" << (int)verbose
       << " read:'" << read.source << "'"
       << " write:'" << write.dest << "'"
       << " date:'" << write.text_date_format << "'"
       << " count:" << count
       << " all:" << write.write_keyframes
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
       << "  --write <arg>   file for output, - for std out, and ending in .pcap\n"
       << "  --count <arg>   number of records to read\n"
       << "  --date <arg>    date-time format to use for output\n"
       << "  --all           write keyframe packets\n"
       << "  --verbose, -v   be verbose\n"
       << "  --help,    -h   show this help and exit";
    return os.str();
}

