#ifndef ENTRYLIST
#define ENTRYLIST

#include <stdint.h>
#include <stdio.h>
#include "tools.h"

#define LIST_LEN 64

typedef struct {
    uint32_t addr; // 地址
    uint32_t len; // 前缀长度
    uint32_t if_index_out; // 出端口编号
    uint32_t nexthop; // 下一跳的地址，0 表示直连，注意和 RIP Entry 的 nexthop 区别： RIP 中的 nexthop = 0 表示的是源 IP 地址

    uint32_t mask;
    uint32_t metric;
    uint32_t bnhop;
    uint32_t if_index_in;
} ENTRY;

void ListInit();
ENTRY* getEntry(int index);
void printList();
void printEntry(ENTRY *entry);
bool update(bool insert, ENTRY entry);
bool query(uint32_t addr, uint32_t *nexthop, int *if_index);
#endif