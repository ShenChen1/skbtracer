#ifndef __TIME_OUTPUT_H__
#define __TIME_OUTPUT_H__

#include <cstdint>
#include <string>

enum class TimestampMode {
    NONE,
    CURRENT,
    RELATIVE,
    ABSOLUTE
};

class TimeOutput {
  public:
    static TimestampMode parse_mode(const std::string &mode_str, bool &ok);
    static std::string format_header(TimestampMode mode);
    static std::string format_time(TimestampMode mode, uint64_t event_ts, uint64_t start_ts);
};

#endif // __TIME_OUTPUT_H__
