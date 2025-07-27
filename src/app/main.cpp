#include <csignal>
#include <spdlog/spdlog.h>

#include "options.h"
#include "output.h"
#include "symdb.h"
#include "trace.h"
#include "utils.h"

static void sig_handler(int sig)
{
    TraceMgr::getInstance().stop();
}

int main(int argc, char **argv)
{
    auto args = Options::parse_args(argc, argv);
    if (args.verbose) {
        Options::dump_args(args);
    }
    spdlog::set_level(args.verbose ? spdlog::level::debug : spdlog::level::info);
    Utils::enforce_infinite_rlimit();

    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    SymdbMgr &symdb = SymdbMgr::getInstance();
    int err = symdb.init();
    if (err) {
        spdlog::error("Failed to initialize SymdbMgr");
        return err;
    }

    TraceMgr &trace = TraceMgr::getInstance();
    err = trace.init(args);
    if (err) {
        spdlog::error("Failed to initialize TraceMgr");
        return err;
    }

    Output output = Output();
    err = output.init(args);
    if (err) {
        spdlog::error("Failed to initialize Output");
        return err;
    }

    const std::string &filter_func = args.filter_func;
    if (filter_func.empty()) {
        spdlog::warn("No --filter-func specified: tracing ALL kernel functions with sk_buff (may cause high overhead on busy systems)");
    } else {
        spdlog::info("Filtering kernel functions with regex: '{}'", filter_func);
    }

    if (!args.filter_ifname.empty()) {
        spdlog::info("Filtering network interface: '{}' (ifindex: {}) in netns: {}",
                     args.filter_ifname, args.filter_ifindex, args.filter_netns_id);
    } else if (args.filter_netns_id != 0) {
        spdlog::info("Filtering network namespace: {}", args.filter_netns_id);
    }

    auto [ret_get_skb_func_list, skb_func_list] = symdb.get_skb_func_list(filter_func);
    if (ret_get_skb_func_list) {
        spdlog::error("Failed to get skb function list");
        return ret_get_skb_func_list;
    }

    int attached_count = 0;
    for (const auto &func : skb_func_list) {
        const auto [ret_get_skb_func_param_pos, skb_param_pos] = symdb.get_skb_func_param_pos(func);
        if (ret_get_skb_func_param_pos) {
            continue;
        }

        err = trace.attach_skb_func(func, skb_param_pos);
        if (err) {
            spdlog::debug("Failed to attach skb function {}: {}", func, err);
            continue;
        }
        attached_count++;
    }

    if (attached_count == 0) {
        spdlog::error("No kernel functions with sk_buff were successfully attached. Exiting...");
        return -ENOENT;
    }
    spdlog::info("Successfully attached to {} network functions. Ready to trace packets...", attached_count);
    output.print_header();

    auto cb = [](void *ctx, const void *data, size_t len) {
        Output *out = static_cast<Output*>(ctx);
        if (len < sizeof(skb_event)) {
            return;
        }
        skb_event event = {};
        std::memcpy(&event, data, sizeof(skb_event));
        out->print_entry(event);
    };

    trace.register_output_callback(cb, &output);
    int ret = trace.run();
    spdlog::info("Tracing finished, exiting...");
    return ret;
}