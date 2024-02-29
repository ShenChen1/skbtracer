#ifndef __SYMDB_MGR_H__
#define __SYMDB_MGR_H__

#include <string>
#include <vector>

class SymdbMgr {
  public:
    SymdbMgr();
    ~SymdbMgr();

    int init();

    std::pair<int, std::string> get_func_by_addr(const unsigned long addr) const;
    std::pair<int, unsigned long> get_addr_by_func(const std::string &func) const;

    std::pair<int, std::vector<std::string>> get_skb_func_list(void) const;
    std::pair<int, int> get_skb_func_param_pos(const std::string &func) const;

  private:
    void *priv;
};

#endif //__SYMDB_MGR_H__