#ifndef __TRACE_MGR_H__
#define __TRACE_MGR_H__

#include <string>

class TraceMgr {
  public:
    static TraceMgr &getInstance() {
        static TraceMgr instance;
        return instance;
    }

    TraceMgr(const TraceMgr &) = delete;
    TraceMgr &operator=(const TraceMgr &) = delete;

    int init();
    int attach_skb_func(const std::string &skb_func, int skb_param_pos);
    int detach_skb_func(const std::string &skb_func);

  private:
    TraceMgr();
    ~TraceMgr();

    void *priv;
};

#endif //__TRACE_MGR_H__