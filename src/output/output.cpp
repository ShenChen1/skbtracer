#include "output.h"
#include "symdb.h"

#include <string>
#include <spdlog/spdlog.h>

Output::Output()
{
}

Output::~Output()
{
}

int Output::init(const Options::args &args)
{
    return 0;
}

int Output::print_header()
{
    return 0;
}

int Output::print_entry(const skb_event &event)
{
    SymdbMgr &symdb = SymdbMgr::getInstance();
    auto [ret_get_func_name, func_name] = symdb.get_func_by_addr(event.addr);

    spdlog::info("{:x} {}", event.skb_addr, func_name);
    return 0;
}