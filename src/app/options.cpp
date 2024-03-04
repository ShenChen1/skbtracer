#include "options.h"
#include <getopt.h>

static void usage()
{
}

const Options::args Options::parse_args(int argc, char **argv)
{
    Options::args args{};

    const char *const short_options = "hvf:s";
    const option long_options[] = {
        option{ "help", no_argument, nullptr, 'h' },
        option{ "verbose", no_argument, nullptr, 'v' },
        option{ "filter-func", required_argument, nullptr, 'f' },
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
    }

    return args;
}