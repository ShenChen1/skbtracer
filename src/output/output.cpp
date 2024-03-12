#include "output.h"

#include <iostream>
#include <spdlog/spdlog.h>

Output::Output()
{
}

Output::~Output()
{
}

int Output::init()
{
    return 0;
}

int Output::print_header()
{
    return 0;
}

int Output::print_entry(const skb_event &event)
{
    std::cout << "print_entry" << std::endl;
    return 0;
}