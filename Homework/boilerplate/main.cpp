#include "router_hal.h"
#include "tools.h"
#include "ripman.h"
#include "entryList.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint8_t packet[2048];
uint8_t output[2048];
macaddr_t srcmac,dstmac;
int if_index;

// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0101a8c0, 0x0103a8c0};
macaddr_t macs[N_IFACE_ON_BOARD];
bool post();

int init(){
  ENTRY e;
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  ListInit();
  RipInit();
  e.addr=0x0001a8c0;
  e.len =24;
  e.if_index_out = 0;
  e.nexthop = 0;
  e.mask = MaskList[24];
  e.metric = reverse((uint32_t)1);
  e.bnhop = 0;
  e.if_index_in = -1;
  update(true,e);
  e.addr=0x0003a8c0;
  e.if_index_out = 1;
  update(true,e);
  for(int i = 0; i < N_IFACE_ON_BOARD; i++){
    res = HAL_GetInterfaceMacAddress(i, macs[i]);
    if(res < 0)
      return res;
  }
  return 0;
}

bool isValid(int len){
  return len == getLen(packet) && ipchecksum(packet,false);
}

bool toMe(){
  uint32_t ip = getDst(packet);
  //Multicast
  if(ip == MULTICAST) return true;
  //Direct
  for(int i = 0; i < N_IFACE_ON_BOARD; i++){
    if(ip == addrs[i]) return true;
  }
  //Broadcast
  if((ip & 0xff000000) == 0xff000000 && (ip & 0x00ffffff) == addrs[if_index]){
    return true;
  }
  return false;
}

void printips(){
  printf(">>>destination ip:");
  printip(getDst(packet));
  putchar(10);
  printf(">>>source ip:");
  printip(getSrc(packet));
  putchar(10);
  putchar(10);
}

int main(int argc, char *argv[]) {
  int res;
  uint64_t last_time;
  if(init())
    return -1;
  for(int i = 0; i < N_IFACE_ON_BOARD; i++)
    LaunchRip(addrs[i],i);
  last_time = HAL_GetTicks();

  while(true){
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 10 * 1000) {
      printf("10s Timer\n");
      printList();
      for(int i = 0; i < N_IFACE_ON_BOARD; i++)
        LaunchRip(addrs[i],i);
      last_time = time;
    }
    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), srcmac, dstmac,1000, &if_index);
    if (res == HAL_ERR_EOF) {
      return 0;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      continue;
    } else if (res > sizeof(packet)) {
      continue;
    }else if(!isValid(res)){
      printf("packet invalid\n");
      continue;
    }
    if(toMe()){
      switch(handleRip(packet,if_index)){
      case RIP_UPDATE: 
        printf("Rip updated,launching package\n");
        printList();
        for(int i = 0; i < N_IFACE_ON_BOARD; i++){
          if(i == if_index) continue;
          LaunchRip(addrs[i],i);
        }
        break;
      case RIP_REQUEST:
        LaunchRip(addrs[if_index],if_index);
        break;
      }
    }else if(memcmp(dstmac,macs[if_index],6) == 0){ //not to me
      post();
    }else{
      printf("Something wrong with the switcher\n");
      printips();
      printf("dstmac:");
      printmac(dstmac);
      putchar(10);
      printf("if_index:%d\n",if_index);
      printf("macs[if_index]");
      printmac(macs[if_index]);
      putchar(10);
      putchar(10);
    }
  }
  return 0;
}

bool post(){
  uint32_t nexthop;
  int if_index;
  if(query(getDst(packet),&nexthop,&if_index)){
    // printf("nexthop:%x\n",nexthop);
    // printf("if_index:%d\n",if_index);
    if(nexthop == 0){
      nexthop = getDst(packet);
    }
    if(HAL_ArpGetMacAddress(if_index,nexthop,dstmac) == 0){
      if(forward(packet)){
      // HAL_GetInterfaceMacAddress(0, target);
        HAL_SendIPPacket(if_index, packet, getLen(packet),dstmac);  
        return true;
      }else{
        printf("TTL meets its end.\n");
        return false;
      }
    }else{
      printf("mac not found\n");
      printips();
      return false;
    }
  }else{
    printf("destination unreachable\n");
    printips();
    return false;
  }
}
