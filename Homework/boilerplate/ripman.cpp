#include "ripman.h"

int count;
uint16_t id;
int ripinited = 0;
uint32_t source_ip;
macaddr_t dst_mac = {0x01,0x00,0x5e,0x00,0x00,0x09}; 
uint8_t RipBuffer[2048];
uint8_t *ip;
uint8_t *udp;
uint8_t *rip;

void RipInit(){
  count = 0;
  ip = RipBuffer;
  udp = ip + 20;
  rip = udp + 8;
  id = 1;

  ip[0] = 0x45;
  ip[1] = 0xc0;
  ip[6] = 0; ip[7] = 0;
  ip[8] = 1;                        // ttl;
  ip[9] = 17;                       //protocol: udp
  *(uint32_t*)(ip+16) = MULTICAST; //multicast

  udp[0] = 0x02;udp[1] = 0x08;
  udp[2] = 0x02;udp[3] = 0x08;
  udp[6] = 0;   udp[7] = 0;

  rip[0] = 2;
  rip[1] = 2;
  rip[2] = 0;
  rip[3] = 0;
  
  ripinited = 1;
}

int LaunchRip(uint32_t ipaddr,int if_index){
  uint8_t * pe;
  ENTRY * entry;
  uint32_t tmp;
  if(!ripinited){
    printf("Rip module not inited.\n");
    return -1;
  }
  pe = rip + 4;
  for(int i = 0; entry = getEntry(i); i++){
    if(entry->if_index_in == if_index)
      continue;
    pe[0] = 0;
    pe[1] = 2;
    pe[2] = 0;
    pe[3] = 0;
    ((uint32_t*)pe)[1] = entry->addr;
    ((uint32_t*)pe)[2] = entry->mask;
    ((uint32_t*)pe)[3] = entry->bnhop;
    ((uint32_t*)pe)[4] = entry->metric;
    pe += 20;
  }
  tmp = pe - udp;    //udp length;
  udp[4] = tmp >> 8; udp[5] = tmp & 0xff;

  tmp = pe - ip;     //ip length;
  ip[2] = tmp >> 8; ip[3] = tmp & 0xff;
  ip[4] = id >> 8;  ip[5] = id & 0xff;

  ip[10] = 0x00; ip[11] = 0x00;
  *(uint32_t*)(ip+12) = ipaddr;
  ipchecksum(ip,true);
  id++;
  return HAL_SendIPPacket(if_index, ip, tmp, dst_mac);
}

#define ENTRY_ERROR   -1
#define ENTRY_DROPPED 0
#define ENTRY_CHANGED 1
int extractEntry(const uint8_t *source,int if_index){
  ENTRY e;
  uint16_t family = ((uint16_t)(source[0]) << 8) | source[1];
  uint16_t tag    = ((uint16_t)(source[2]) << 8) | source[3];
  e.addr   = *(uint32_t *)(source + 4);
  e.mask   = *(uint32_t *)(source + 8);
  e.bnhop  = *(uint32_t *)(source + 12);
  e.metric = *(uint32_t *)(source + 16);
  uint32_t temp;
  uint32_t i;
  if(family != 2 || tag != 0){
    return ENTRY_ERROR;
  }
  for(i = 0; i < 33; i++){
    if(MaskList[i] == e.mask){
      break;
    }
  }
  if(i == 33){
    return ENTRY_ERROR;
  }
  temp = e.addr & (~e.mask);
  if(temp){
    e.len = 32;
  }else{
    e.len = i;
  }
  i = reverse(e.metric);
  if(i <= 0 || i > 16){
    return ENTRY_ERROR;
  }
  if(i < 16)
    i++;
  e.metric = reverse(i);
  e.nexthop = source_ip;
  if(e.bnhop == 0) 
    e.bnhop = source_ip;
  e.if_index_out = if_index;
  e.if_index_in = if_index;
  return update(true,e)?ENTRY_CHANGED : ENTRY_DROPPED;
}

int handleRip(uint8_t *packet,int if_index){
  int iplen = ((uint16_t)packet[2]<<8) | packet[3];
  int iphlen = (packet[0] & 0x0f) << 2;
  uint8_t *udp = (uint8_t*)packet + iphlen;
  uint8_t *rip = udp + 8;
  uint8_t *entry = rip + 4;
  uint8_t *end = (uint8_t*)packet + iplen;
  uint8_t cmd = rip[0];
  uint8_t ver = rip[1];
  uint8_t zero = rip[2]|rip[3];
  int count = 0;
  bool changed = false;
  int tmp;
  if(!ripinited){
    printf("Rip module not inited.\n");
    return RIP_ERROR;
  }
  if( zero || ver != 2){
    return RIP_ERROR;
  }
  if(cmd == 1){
    return RIP_REQUEST;
  }else if(cmd == 2){
    source_ip = ((uint32_t*)packet)[3];
    while(entry < end){
      switch(extractEntry(entry,if_index)){
        case ENTRY_ERROR: return RIP_ERROR;
        case ENTRY_CHANGED: changed = true;
      }
      entry += 20;
      count++;
    }
    return (changed)?RIP_UPDATE:RIP_NONE;
  }else
    return RIP_ERROR;
}