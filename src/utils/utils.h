#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>

namespace Utils {

void enforce_infinite_rlimit();
int compile_filter(const std::string &filter_str);

}

#endif //__UTILS_H__