#include "options.h"

#include <getopt.h>
#include <iostream>

static void usage()
{
}

int Options::dump_args(const Options::args &args)
{
    std::cout << "filter_func: " << args.filter_func << std::endl;
    std::cout << "filter_mark: " << args.filter_mark << std::endl;
    std::cout << "filter_pcap: " << args.filter_pcap << std::endl;
    std::cout << "output_skb: " << args.output_skb << std::endl;
    std::cout << "verbose: " << args.verbose << std::endl;
    return 0;
}

const Options::args Options::parse_args(int argc, char **argv)
{
    Options::args args{};

    const char *const short_options = "hvf:s";
    const option long_options[] = {
        option{ "help", no_argument, nullptr, 'h' },
        option{ "verbose", no_argument, nullptr, 'v' },
        option{ "filter-func", required_argument, nullptr, 'f' },
        option{ "filter-mark", required_argument, nullptr, 'm' },
        option{ "output-skb", no_argument, nullptr, 's' },
        option{ nullptr, 0, nullptr, 0 }, // Must be last
    };

    int c;
    while ((c = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 'h':
                usage();
                exit(0);
            case 'v':
                args.verbose++;
                break;
            case 'f':
                args.filter_func = optarg;
                break;
            case 'm':
                args.filter_mark = optarg;
                break;
            case 's':
                args.output_skb = true;
                break;
            default:
                usage();
                exit(1);
        }
    }

    while (optind < argc) {
        args.filter_pcap += argv[optind++];
        args.filter_pcap += " ";
    }

    return args;
}