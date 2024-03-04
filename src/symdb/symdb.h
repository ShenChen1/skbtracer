#ifndef __SYMDB_MGR_H__
#define __SYMDB_MGR_H__

#include <string>
#include <vector>

class SymdbMgr {
  public:
    static SymdbMgr &getInstance() {
        static SymdbMgr instance;
        return instance;
    }

    SymdbMgr(const SymdbMgr &) = delete;
    SymdbMgr &operator=(const SymdbMgr &) = delete;

    int init();

    std::pair<int, std::string> get_func_by_addr(const unsigned long addr) const;
    std::pair<int, unsigned long> get_addr_by_func(const std::string &func) const;

    std::pair<int, std::vector<std::string>> get_skb_func_list(const std::string &filter) const;
    std::pair<int, int> get_skb_func_param_pos(const std::string &func) const;

  private:
    SymdbMgr();
    ~SymdbMgr();

    void *priv;
};

#endif //__SYMDB_MGR_H__