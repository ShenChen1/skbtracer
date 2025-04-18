#include "options.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <net/if.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage()
{
    std::cout << "Usage: skbtracer [OPTIONS] [PCAP_FILTER]\n"
              << "Trace sk_buff flow through the Linux kernel network stack.\n\n"
              << "Options:\n"
              << "  -h, --help            Show this help message\n"
              << "  -v, --verbose         Verbose debug logging\n"
              << "  -f, --filter-func     Regex to filter kernel functions (default: trace all kernel skb functions)\n"
              << "  -m, --filter-mark     Filter by skb mark (e.g. 100 or 0x64)\n"
              << "  -i, --filter-ifname   filter skb ifname in --filter-netns (if not specified, use current netns)\n"
              << "  -n, --filter-netns    filter netns (\"/proc/<pid>/ns/net\", \"inode:<inode>\")\n"
              << "  -M, --output-meta     Output skb metadata (len, mtu, mark, ifname, netns)\n"
              << "  -T, --output-tuple    Output network tuple (ip, port, proto, tcpflags)\n"
              << "  -t, --timestamp       Print timestamp per skb (\"current\", \"relative\", \"absolute\", \"none\") (default \"none\")\n\n"
              << "Examples:\n"
              << "  skbtracer 'icmp'\n"
              << "  skbtracer 'icmp6'\n"
              << "  skbtracer 'tcp and port 80'\n"
              << "  skbtracer 'ip6 and tcp port 80'\n"
              << "  skbtracer -f 'ip_rcv.*' 'host 127.0.0.1'\n"
              << "  skbtracer --filter-ifname eth0\n"
              << "  skbtracer --filter-ifname eth0 --filter-netns /proc/123/ns/net\n";
}

static bool parse_u32(const char *str, uint32_t &out)
{
    if (!str || *str == '\0') {
        return false;
    }
    char *endptr = nullptr;
    errno = 0;
    unsigned long val = std::strtoul(str, &endptr, 0);
    if (errno != 0 || endptr == str || *endptr != '\0' || val > UINT32_MAX) {
        return false;
    }
    out = static_cast<uint32_t>(val);
    return true;
}

static bool parse_netns_spec(const std::string &spec, uint32_t &netns_id, int &netns_fd, std::string &err)
{
    if (spec.empty() || spec == "/proc/self/ns/net") {
        netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        if (netns_fd < 0) {
            err = "Failed to open current netns: " + std::string(strerror(errno));
            return false;
        }
        struct stat st{};
        if (fstat(netns_fd, &st) < 0) {
            close(netns_fd);
            netns_fd = -1;
            err = "Failed to stat current netns: " + std::string(strerror(errno));
            return false;
        }
        netns_id = static_cast<uint32_t>(st.st_ino);
        return true;
    }

    if (spec.rfind("inode:", 0) == 0) {
        std::string inode_str = spec.substr(6);
        if (!parse_u32(inode_str.c_str(), netns_id)) {
            err = "Invalid netns inode format '" + spec + "'";
            return false;
        }
        netns_fd = -1;
        return true;
    }

    if (spec[0] == '/') {
        netns_fd = open(spec.c_str(), O_RDONLY | O_CLOEXEC);
        if (netns_fd < 0) {
            err = "Failed to open netns path '" + spec + "': " + std::string(strerror(errno));
            return false;
        }
        struct stat st{};
        if (fstat(netns_fd, &st) < 0) {
            close(netns_fd);
            netns_fd = -1;
            err = "Failed to stat netns path '" + spec + "': " + std::string(strerror(errno));
            return false;
        }
        netns_id = static_cast<uint32_t>(st.st_ino);
        return true;
    }

    err = "Invalid netns specifier '" + spec + "': must be path or 'inode:<inode>'";
    return false;
}

static bool resolve_ifname_in_netns(const std::string &ifname, int target_netns_fd, uint32_t &ifindex, std::string &err)
{
    if (ifname.empty()) {
        err = "Interface name cannot be empty";
        return false;
    }
    if (target_netns_fd < 0) {
        err = "inode netns specifier cannot be used with --filter-ifname";
        return false;
    }

    int self_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (self_fd < 0) {
        err = "Failed to open current netns: " + std::string(strerror(errno));
        return false;
    }

    struct stat self_st{}, target_st{};
    if (fstat(self_fd, &self_st) < 0 || fstat(target_netns_fd, &target_st) < 0) {
        close(self_fd);
        err = "Failed to stat netns descriptors";
        return false;
    }

    bool is_same_netns = (self_st.st_dev == target_st.st_dev && self_st.st_ino == target_st.st_ino);

    if (!is_same_netns) {
        if (setns(target_netns_fd, CLONE_NEWNET) < 0) {
            close(self_fd);
            err = "Failed to switch to target netns: " + std::string(strerror(errno));
            return false;
        }
    }

    unsigned int idx = if_nametoindex(ifname.c_str());
    int saved_errno = errno;

    if (!is_same_netns) {
        if (setns(self_fd, CLONE_NEWNET) < 0) {
            int restore_errno = errno;
            close(self_fd);
            err = "Failed to restore original netns: " + std::string(strerror(restore_errno));
            return false;
        }
    }
    close(self_fd);

    if (idx == 0) {
        err = "Interface '" + ifname + "' not found in target netns: " + std::string(strerror(saved_errno));
        return false;
    }

    ifindex = idx;
    return true;
}

bool Options::resolve_netns_and_ifname(Options::args &args, std::string &err_msg)
{
    if (args.filter_ifname.empty() && args.filter_netns.empty()) {
        args.filter_netns_id = 0;
        args.filter_ifindex = 0;
        return true;
    }

    int netns_fd = -1;
    uint32_t netns_id = 0;
    if (!parse_netns_spec(args.filter_netns, netns_id, netns_fd, err_msg)) {
        return false;
    }

    args.filter_netns_id = netns_id;

    if (!args.filter_ifname.empty()) {
        uint32_t ifindex = 0;
        bool ok = resolve_ifname_in_netns(args.filter_ifname, netns_fd, ifindex, err_msg);
        if (netns_fd >= 0) {
            close(netns_fd);
        }
        if (!ok) {
            return false;
        }
        args.filter_ifindex = ifindex;
    } else {
        if (netns_fd >= 0) {
            close(netns_fd);
        }
        args.filter_ifindex = 0;
    }

    return true;
}

int Options::dump_args(const Options::args &args)
{
    std::cout << "filter_func: " << args.filter_func << std::endl;
    std::cout << "filter_mark: 0x" << std::hex << args.filter_mark << std::dec << std::endl;
    std::cout << "filter_ifname: " << args.filter_ifname << std::endl;
    std::cout << "filter_ifindex: " << args.filter_ifindex << std::endl;
    std::cout << "filter_netns: " << args.filter_netns << std::endl;
    std::cout << "filter_netns_id: " << args.filter_netns_id << std::endl;
    std::cout << "filter_pcap: " << args.filter_pcap << std::endl;
    std::cout << "output_meta: " << args.output_meta << std::endl;
    std::cout << "output_tuple: " << args.output_tuple << std::endl;
    std::cout << "timestamp: " << args.timestamp << std::endl;
    std::cout << "verbose: " << args.verbose << std::endl;
    return 0;
}

const Options::args Options::parse_args(int argc, char **argv)
{
    Options::args args{};
    args.timestamp = "none";
    optind = 0;

    const char *const short_options = "hvf:m:i:n:MTt:";
    const option long_options[] = {
        option{ "help", no_argument, nullptr, 'h' },
        option{ "verbose", no_argument, nullptr, 'v' },
        option{ "filter-func", required_argument, nullptr, 'f' },
        option{ "filter-mark", required_argument, nullptr, 'm' },
        option{ "filter-ifname", required_argument, nullptr, 'i' },
        option{ "filter-netns", required_argument, nullptr, 'n' },
        option{ "output-meta", no_argument, nullptr, 'M' },
        option{ "output-tuple", no_argument, nullptr, 'T' },
        option{ "timestamp", required_argument, nullptr, 't' },
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
                if (!parse_u32(optarg, args.filter_mark)) {
                    std::cerr << "Error: Invalid filter-mark value '" << (optarg ? optarg : "") << "'\n";
                    usage();
                    exit(1);
                }
                break;
            case 'i':
                if (!optarg || optarg[0] == '\0') {
                    std::cerr << "Error: --filter-ifname cannot be empty\n";
                    usage();
                    exit(1);
                }
                args.filter_ifname = optarg;
                break;
            case 'n':
                if (!optarg || optarg[0] == '\0') {
                    std::cerr << "Error: --filter-netns cannot be empty\n";
                    usage();
                    exit(1);
                }
                args.filter_netns = optarg;
                break;
            case 'M':
                args.output_meta = true;
                break;
            case 'T':
                args.output_tuple = true;
                break;
            case 't': {
                if (!optarg || optarg[0] == '\0') {
                    std::cerr << "Error: --timestamp cannot be empty\n";
                    usage();
                    exit(1);
                }
                std::string ts_val = optarg;
                if (ts_val != "current" && ts_val != "relative" && ts_val != "absolute" && ts_val != "none") {
                    std::cerr << "Error: Invalid value for --timestamp: '" << ts_val
                              << "'. Supported values are: \"current\", \"relative\", \"absolute\", \"none\"\n";
                    usage();
                    exit(1);
                }
                args.timestamp = ts_val;
                break;
            }
            default:
                usage();
                exit(1);
        }
    }

    std::string err_msg;
    if (!resolve_netns_and_ifname(args, err_msg)) {
        std::cerr << "Error: " << err_msg << "\n";
        usage();
        exit(1);
    }

    while (optind < argc) {
        args.filter_pcap += argv[optind++];
        args.filter_pcap += " ";
    }

    return args;
}