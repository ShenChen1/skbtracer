#ifndef __TRACE_MGR_H__
#define __TRACE_MGR_H__

#include "options.h"

class TraceMgr {
  public:
    static TraceMgr &getInstance() {
        static TraceMgr instance;
        return instance;
    }

    TraceMgr(const TraceMgr &) = delete;
    TraceMgr &operator=(const TraceMgr &) = delete;

    int init(const Options::args &args);
    int attach_skb_func(const std::string &skb_func, int skb_param_pos);
    int detach_skb_func(const std::string &skb_func);

    using output_callback_t = void (*)(void *ctx, const void *data, size_t len);
    int register_output_callback(output_callback_t cb, void *ctx);
    int run();

  private:
    TraceMgr();
    ~TraceMgr();

    void *priv;
};

#endif //__TRACE_MGR_H__