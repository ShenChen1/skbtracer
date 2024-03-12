#include <regex>
#include <spdlog/spdlog.h>

#include "options.h"
#include "output.h"
#include "symdb.h"
#include "trace.h"
#include "utils.h"

int main(int argc, char **argv)
{
    int err;

    auto args = Options::parse_args(argc, argv);
    spdlog::set_level(args.verbose ? spdlog::level::debug : spdlog::level::info);
    Utils::enforce_infinite_rlimit();

    SymdbMgr &symdb = SymdbMgr::getInstance();
    err = symdb.init();
    if (err) {
        spdlog::error("Failed to initialize SymdbMgr");
        return err;
    }

    TraceMgr &trace = TraceMgr::getInstance();
    err = trace.init();
    if (err) {
        spdlog::error("Failed to initialize TraceMgr");
        return err;
    }

    auto [ret_get_skb_func_list, skb_func_list] = symdb.get_skb_func_list(args.filter_func);
    if (ret_get_skb_func_list) {
        spdlog::error("Failed to get skb function list");
        return ret_get_skb_func_list;
    }

    for (const auto &func : skb_func_list) {
        const auto [ret_get_skb_func_param_pos, skb_param_pos] = symdb.get_skb_func_param_pos(func);
        if (ret_get_skb_func_param_pos) {
            spdlog::warn("Failed to get skb function param pos");
            continue;
        }

        err = trace.attach_skb_func(func, skb_param_pos);
        if (err) {
            spdlog::warn("Failed to attach skb function: {}", func);
            continue;
        }
    }

    auto cb = [](void *ctx, const void *data, size_t len) {
        
    };

    trace.register_output_callback(cb, nullptr);
    return trace.run();
}