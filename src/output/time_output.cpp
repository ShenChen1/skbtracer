#include "time_output.h"

#include <ctime>
#include <spdlog/fmt/fmt.h>
#include <sys/time.h>

constexpr double NS_PER_SEC = 1e9;

static int64_t get_boot_realtime_ns()
{
    static int64_t s_boot_realtime_ns = 0;
    static bool s_init = false;
    if (!s_init) {
        struct timespec real_ts{}, mono_ts{};
        clock_gettime(CLOCK_REALTIME, &real_ts);
        clock_gettime(CLOCK_MONOTONIC, &mono_ts);
        s_boot_realtime_ns = (static_cast<int64_t>(real_ts.tv_sec) * 1000000000LL + real_ts.tv_nsec)
                           - (static_cast<int64_t>(mono_ts.tv_sec) * 1000000000LL + mono_ts.tv_nsec);
        s_init = true;
    }
    return s_boot_realtime_ns;
}

TimestampMode TimeOutput::parse_mode(const std::string &mode_str, bool &ok)
{
    ok = true;
    if (mode_str.empty() || mode_str == "none") {
        return TimestampMode::NONE;
    }
    if (mode_str == "current") {
        return TimestampMode::CURRENT;
    }
    if (mode_str == "relative") {
        return TimestampMode::RELATIVE;
    }
    if (mode_str == "absolute") {
        return TimestampMode::ABSOLUTE;
    }
    ok = false;
    return TimestampMode::NONE;
}

std::string TimeOutput::format_header(TimestampMode mode)
{
    switch (mode) {
        case TimestampMode::RELATIVE:
            return fmt::format("{:<10}", "TIME(s)");
        case TimestampMode::CURRENT:
            return fmt::format("{:<12}", "TIME");
        case TimestampMode::ABSOLUTE:
            return fmt::format("{:<23}", "TIME");
        case TimestampMode::NONE:
        default:
            return "";
    }
}

static std::string format_current_time(uint64_t event_ts)
{
    int64_t event_realtime_ns = get_boot_realtime_ns() + static_cast<int64_t>(event_ts);
    time_t sec = event_realtime_ns / 1000000000LL;
    int ms = static_cast<int>((event_realtime_ns % 1000000000LL) / 1000000LL);
    if (ms < 0) {
        ms += 1000;
    }

    struct tm tm_buf{};
    localtime_r(&sec, &tm_buf);
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ms);
    return fmt::format("{:<12}", buf);
}

static std::string format_absolute_time(uint64_t event_ts)
{
    int64_t event_realtime_ns = get_boot_realtime_ns() + static_cast<int64_t>(event_ts);
    time_t sec = event_realtime_ns / 1000000000LL;
    int ms = static_cast<int>((event_realtime_ns % 1000000000LL) / 1000000LL);
    if (ms < 0) {
        ms += 1000;
    }

    struct tm tm_buf{};
    localtime_r(&sec, &tm_buf);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ms);
    return fmt::format("{:<23}", buf);
}

std::string TimeOutput::format_time(TimestampMode mode, uint64_t event_ts, uint64_t start_ts)
{
    switch (mode) {
        case TimestampMode::RELATIVE: {
            double elapsed = (event_ts >= start_ts) ? static_cast<double>(event_ts - start_ts) / NS_PER_SEC : 0.0;
            return fmt::format("{:<10.6f}", elapsed);
        }
        case TimestampMode::CURRENT:
            return format_current_time(event_ts);
        case TimestampMode::ABSOLUTE:
            return format_absolute_time(event_ts);
        case TimestampMode::NONE:
        default:
            return "";
    }
}
