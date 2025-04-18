#ifndef __DEV_CACHE_H__
#define __DEV_CACHE_H__

#include <cstdint>
#include <string>

namespace DevCache {

void register_ifname(uint32_t netns, uint32_t ifindex, const std::string &ifname);
std::string resolve_dev_name(uint32_t netns, uint32_t ifindex);
std::string format_iface(uint32_t netns, uint32_t ifindex);
void clear_ifname_cache();

void set_current_netns_id(uint32_t id);
uint32_t get_current_netns_id();

std::string resolve_comm(uint32_t pid);
void clear_comm_cache();

std::string format_proc(uint32_t pid);

} // namespace DevCache

#endif // __DEV_CACHE_H__
