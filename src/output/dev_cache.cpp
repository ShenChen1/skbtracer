#include "dev_cache.h"

#include <cstring>
#include <mutex>
#include <net/if.h>
#include <unordered_map>

static std::mutex s_comm_mutex;
static std::unordered_map<uint32_t, std::string> s_comm_cache;

static std::mutex s_ifname_mutex;
static std::unordered_map<uint64_t, std::string> s_ifname_cache;
static uint32_t s_current_netns_id = 0;

static uint64_t make_cache_key(uint32_t netns, uint32_t ifindex)
{
    return (static_cast<uint64_t>(netns) << 32) | ifindex;
}

namespace DevCache {

void set_current_netns_id(uint32_t id)
{
    std::lock_guard<std::mutex> lock(s_ifname_mutex);
    s_current_netns_id = id;
}

uint32_t get_current_netns_id()
{
    std::lock_guard<std::mutex> lock(s_ifname_mutex);
    return s_current_netns_id;
}

void register_ifname(uint32_t netns, uint32_t ifindex, const std::string &ifname)
{
    std::lock_guard<std::mutex> lock(s_ifname_mutex);
    s_ifname_cache[make_cache_key(netns, ifindex)] = ifname;
}

void clear_ifname_cache()
{
    std::lock_guard<std::mutex> lock(s_ifname_mutex);
    s_ifname_cache.clear();
    s_current_netns_id = 0;
}

std::string resolve_dev_name(uint32_t netns, uint32_t ifindex)
{
    if (ifindex == 0) {
        return "";
    }

    std::lock_guard<std::mutex> lock(s_ifname_mutex);

    auto it = s_ifname_cache.find(make_cache_key(netns, ifindex));
    if (it != s_ifname_cache.end()) {
        return it->second;
    }

    if (netns == 0 || (s_current_netns_id != 0 && netns == s_current_netns_id)) {
        char buf[IF_NAMESIZE] = "";
        if (if_indextoname(ifindex, buf)) {
            std::string name(buf);
            s_ifname_cache[make_cache_key(netns, ifindex)] = name;
            return name;
        }
    }

    return "";
}

std::string format_iface(uint32_t netns, uint32_t ifindex)
{
    std::string name = resolve_dev_name(netns, ifindex);
    if (!name.empty()) {
        return name + ":" + std::to_string(ifindex);
    }
    return std::to_string(ifindex);
}

std::string resolve_comm(uint32_t pid)
{
    if (pid == 0) {
        return "swapper";
    }

    std::lock_guard<std::mutex> lock(s_comm_mutex);
    auto it = s_comm_cache.find(pid);
    if (it != s_comm_cache.end()) {
        return it->second;
    }

    std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
    FILE *f = fopen(comm_path.c_str(), "r");
    if (f) {
        char buf[64] = "";
        if (fgets(buf, sizeof(buf), f)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            std::string name(buf);
            fclose(f);
            s_comm_cache[pid] = name;
            return name;
        }
        fclose(f);
    }

    std::string fallback = std::to_string(pid);
    s_comm_cache[pid] = fallback;
    return fallback;
}

void clear_comm_cache()
{
    std::lock_guard<std::mutex> lock(s_comm_mutex);
    s_comm_cache.clear();
}

std::string format_proc(uint32_t pid)
{
    return std::to_string(pid) + "/" + resolve_comm(pid);
}

} // namespace DevCache
