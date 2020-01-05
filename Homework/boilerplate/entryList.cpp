#include "entryList.h"

int entryCount;
ENTRY entryList[LIST_LEN];

bool listInited = false;

void ListInit(){
    entryCount = 0;
    listInited = true;
}

ENTRY* getEntry(int index){
    if(!listInited){
        printf("List not inited\n");
        return NULL;
    }
    if(index < 0 || index > entryCount){
        printf("Index out of range\n");
        return NULL;
    }
    return entryList + index;
}

bool update(bool insert, ENTRY entry) {
  if(!listInited){
    printf("List not inited\n");
    return false;
  }
  if(insert){
    for(int i = 0; i < entryCount; i++){
      if(entryList[i].addr == entry.addr && entryList[i].len == entry.len){
        if(entryList[i].nexthop == entry.nexthop){
            entryList[i] = entry;
            return true;
        }else{
            if(reverse(entryList[i].metric) > reverse(entry.metric)){
                entryList[i] = entry;
                return true;
            }
            return false;
        }
      }
    }
    if(entryCount < LIST_LEN){
      entryList[entryCount] = entry;
      entryCount++;
      return true;
    }
    return false;
  }else{
    int i,j;
    i = entryCount - 1;
    for(j = 0; j < entryCount; j++){
      if(entryList[j].addr == entry.addr && entryList[j].len == entry.len){
        entryList[j] = entryList[i];
        entryList[i].addr = 0;
        entryCount--;
        return true;
      }
    }
    return false;
  }
}

bool query(uint32_t addr, uint32_t *nexthop, int *if_index) {
  if(!listInited){
    printf("List not inited\n");
    return false;
  }
  int maxlen = 0;
  *nexthop = 0;
  *if_index = 0;
  for(int i = 0; i < entryCount; i++){
    if(maxlen < entryList[i].len && ((entryList[i].addr & MaskList[entryList[i].len]) == (addr & MaskList[entryList[i].len]))){
      *nexthop = entryList[i].nexthop;
      *if_index = entryList[i].if_index_out;
      maxlen = entryList[i].len;
    }
  }
  return (maxlen)?true:false;
}

void printEntry(ENTRY *entry){
  printf("<=============E N T R Y================>\n");
  printf("addr:");
  printip(entry->addr);
  putchar(10);
  printf("len:%d\t",entry->len);
  printf("ifout:%d\t",entry->if_index_out);
  printf("ifin:%d\n",entry->if_index_in);
  printf("nexthop:");
  printip(entry->nexthop);
  putchar(10);
  printf("mask:");
  printip(entry->mask);
  putchar(10);
  printf("bnhop:");
  printip(entry->bnhop);
  putchar(10);
}

void printList(){
  printf(">>>>>>>>>>List start>>>>>>>>>>>>>\n");
  for(int i = 0; i < entryCount; i++){
    printEntry(entryList+i);
  }
  printf("<<<<<<<<<<List end<<<<<<<<<<<<<<\n");
}