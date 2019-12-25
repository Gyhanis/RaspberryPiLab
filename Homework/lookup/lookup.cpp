#include "router.h"
#include <stdint.h>
#include <stdlib.h>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/
#define LIST_LEN 128
RoutingTableEntry entrys[128];
int cur_len;
uint32_t MaskList[33] = {
  0x00000000,
  0x00000080,0x000000c0,0x000000e0,0x000000f0,
  0x000000f8,0x000000fc,0x000000fe,0x000000ff,
  0x000080ff,0x0000c0ff,0x0000e0ff,0x0000f0ff,
  0x0000f8ff,0x0000fcff,0x0000feff,0x0000ffff,
  0x0080ffff,0x00c0ffff,0x00e0ffff,0x00f0ffff,
  0x00f8ffff,0x00fcffff,0x00feffff,0x00ffffff,
  0x80ffffff,0xc0ffffff,0xe0ffffff,0xf0ffffff,
  0xf8ffffff,0xfcffffff,0xfeffffff,0xffffffff
};

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  if(insert){
    for(int i = 0; i < cur_len; i++){
      if(entrys[i].addr == entry.addr && entrys[i].len == entry.len){
        entrys[i] = entry;
        return;
      }
    }
    if(cur_len < LIST_LEN){
      entrys[cur_len] = entry;
      cur_len++;
    }
  }else{
    int i,j;
    i = cur_len - 1;
    if(i < 0)
      return;
    for(j = 0; j < cur_len; j++){
      if(entrys[j].addr == entry.addr && entrys[j].len == entry.len){
        entrys[j] = entrys[i];
        entrys[i].addr = 0;
        cur_len--;
        return;
      }
    }
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  int maxlen = 0;
  *nexthop = 0;
  *if_index = 0;
  for(int i = 0; i < cur_len; i++){
    if(maxlen < entrys[i].len && ((entrys[i].addr & MaskList[entrys[i].len]) == (addr & MaskList[entrys[i].len]))){
      *nexthop = entrys[i].nexthop;
      *if_index = entrys[i].if_index;
      maxlen = entrys[i].len;
    }
  }
  return (maxlen)?true:false;
}
