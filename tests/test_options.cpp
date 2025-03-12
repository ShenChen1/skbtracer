#include <cassert>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "options.h"


static void test_parse_mark_decimal()
{
    char prog[] = "skbtracer";
    char flag[] = "-m";
    char val[] = "100";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_mark == 100);
    std::cout << "[PASS] test_parse_mark_decimal: " << args.filter_mark << std::endl;
}

static void test_parse_mark_hex()
{
    char prog[] = "skbtracer";
    char flag[] = "-m";
    char val[] = "0x1234";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_mark == 0x1234);
    std::cout << "[PASS] test_parse_mark_hex: 0x" << std::hex << args.filter_mark << std::dec << std::endl;
}

static void test_parse_mark_long_option()
{
    char prog[] = "skbtracer";
    char flag[] = "--filter-mark";
    char val[] = "0xabcd";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_mark == 0xabcd);
    std::cout << "[PASS] test_parse_mark_long_option: 0x" << std::hex << args.filter_mark << std::dec << std::endl;
}

static void test_combined_options()
{
    char prog[] = "skbtracer";
    char f1[] = "-v";
    char f2[] = "-m";
    char val[] = "0x50";
    char f3[] = "-s";
    char pcap[] = "icmp";
    char *argv[] = { prog, f1, f2, val, f3, pcap, nullptr };
    int argc = 6;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.verbose == 1);
    assert(args.filter_mark == 0x50);
    assert(args.output_skb == true);
    assert(args.filter_pcap == "icmp ");
    std::cout << "[PASS] test_combined_options" << std::endl;
}

static void test_default_no_mark()
{
    char prog[] = "skbtracer";
    char *argv[] = { prog, nullptr };
    int argc = 1;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_mark == 0);
    assert(args.filter_func.empty());
    std::cout << "[PASS] test_default_no_mark" << std::endl;
}

static void test_filter_func_options()
{
    char prog[] = "skbtracer";
    char f1[] = "-f";
    char val[] = "ip_rcv";
    char *argv_spec[] = { prog, f1, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args_spec = Options::parse_args(argc, argv_spec);
    assert(args_spec.filter_func == "ip_rcv");
    std::cout << "[PASS] test_filter_func_options" << std::endl;
}

static void test_parse_ifname_default_netns()
{
    char prog[] = "skbtracer";
    char flag[] = "--filter-ifname";
    char val[] = "lo";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_ifname == "lo");
    assert(args.filter_ifindex == 1);
    assert(args.filter_netns_id > 0);
    std::cout << "[PASS] test_parse_ifname_default_netns (ifindex=" << args.filter_ifindex
              << ", netns=" << args.filter_netns_id << ")" << std::endl;
}

static void test_parse_ifname_short_option()
{
    char prog[] = "skbtracer";
    char flag[] = "-i";
    char val[] = "lo";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_ifname == "lo");
    assert(args.filter_ifindex == 1);
    std::cout << "[PASS] test_parse_ifname_short_option" << std::endl;
}

static void test_parse_netns_inode()
{
    char prog[] = "skbtracer";
    char flag[] = "--filter-netns";
    char val[] = "inode:4026531999";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_netns == "inode:4026531999");
    assert(args.filter_netns_id == 4026531999U);
    assert(args.filter_ifindex == 0);
    std::cout << "[PASS] test_parse_netns_inode: " << args.filter_netns_id << std::endl;
}

static void test_parse_netns_path()
{
    char prog[] = "skbtracer";
    char flag[] = "--filter-netns";
    char val[] = "/proc/self/ns/net";
    char *argv[] = { prog, flag, val, nullptr };
    int argc = 3;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_netns == "/proc/self/ns/net");
    assert(args.filter_netns_id > 0);
    assert(args.filter_ifindex == 0);
    std::cout << "[PASS] test_parse_netns_path: " << args.filter_netns_id << std::endl;
}

static void test_parse_ifname_with_netns_path()
{
    char prog[] = "skbtracer";
    char f1[] = "--filter-ifname";
    char v1[] = "lo";
    char f2[] = "--filter-netns";
    char v2[] = "/proc/self/ns/net";
    char *argv[] = { prog, f1, v1, f2, v2, nullptr };
    int argc = 5;

    optind = 1;
    auto args = Options::parse_args(argc, argv);
    assert(args.filter_ifname == "lo");
    assert(args.filter_ifindex == 1);
    assert(args.filter_netns_id > 0);
    std::cout << "[PASS] test_parse_ifname_with_netns_path" << std::endl;
}

static void test_resolve_failures()
{
    std::string err;
    Options::args args{};

    // Non-existent interface in current netns
    args.filter_ifname = "non_existent_dev_xyz";
    assert(!Options::resolve_netns_and_ifname(args, err));
    assert(!err.empty());

    // Inode netns cannot be used with ifname
    args.filter_ifname = "lo";
    args.filter_netns = "inode:12345";
    assert(!Options::resolve_netns_and_ifname(args, err));
    assert(err.find("inode") != std::string::npos);

    // Invalid netns path
    args.filter_ifname = "";
    args.filter_netns = "/non/existent/path/netns";
    assert(!Options::resolve_netns_and_ifname(args, err));

    // Invalid netns specifier
    args.filter_netns = "invalid_format";
    assert(!Options::resolve_netns_and_ifname(args, err));

    std::cout << "[PASS] test_resolve_failures" << std::endl;
}

static void test_netns_invariance_after_resolve()
{
    struct stat before_st{};
    int fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(fstat(fd, &before_st) == 0);
    close(fd);

    Options::args args{};
    args.filter_ifname = "lo";
    args.filter_netns = "/proc/self/ns/net";
    std::string err;
    bool ok = Options::resolve_netns_and_ifname(args, err);
    assert(ok);
    assert(args.filter_ifindex == 1);

    struct stat after_st{};
    fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(fstat(fd, &after_st) == 0);
    close(fd);

    assert(before_st.st_ino == after_st.st_ino);
    assert(before_st.st_dev == after_st.st_dev);
    std::cout << "[PASS] test_netns_invariance_after_resolve" << std::endl;
}

int main()
{
    std::cout << "Running options regression and unit tests..." << std::endl;
    test_default_no_mark();
    test_filter_func_options();
    test_parse_mark_decimal();
    test_parse_mark_hex();
    test_parse_mark_long_option();
    test_combined_options();
    test_parse_ifname_default_netns();
    test_parse_ifname_short_option();
    test_parse_netns_inode();
    test_parse_netns_path();
    test_parse_ifname_with_netns_path();
    test_resolve_failures();
    test_netns_invariance_after_resolve();
    std::cout << "All options regression and unit tests passed successfully!" << std::endl;
    return 0;
}

