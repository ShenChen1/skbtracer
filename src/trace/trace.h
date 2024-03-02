#ifndef __TRACE_MGR_H__
#define __TRACE_MGR_H__

class TraceMgr {
  public:
    TraceMgr();
    ~TraceMgr();

    int init();

  private:
    void *priv;
};

#endif //__TRACE_MGR_H__