#include "tools.h"

uint32_t reverse(uint32_t a){
    uint32_t result = 0;
    uint8_t *p = (uint8_t *)&a;
    for(int i = 0; i < 4; i++){
        result <<= 8;
        result |= p[i];
    }
    return result;
}

uint16_t reverse(uint16_t a){
  return (a << 8) | (a & 0x00ff);
}

bool ipchecksum(uint8_t *packet,bool cal) {
  uint32_t sum,carry;
  uint32_t len,temp;
  sum = 0;
  len = packet[0];
  len &= 0x0f;
  len <<= 2;
  for(int i = 0; i < len; i+=2){
    temp = packet[i];
    temp <<= 8;
    temp += packet[i+1];
    sum += temp;
  }
  while(carry = (sum>>16)){
    sum &= 0xffff;
    sum += carry;
  }
  if(cal){
    temp = ~sum;
    packet[11] = temp & 0xff;
    packet[10] = temp >> 8;
    return true;
  }else{
    return sum == 0xffff;
  }
}

bool forward(uint8_t *packet) {
  if(packet[8] == 1)
    return false;
  packet[8]--;
  packet[10] = packet[11] = 0;
  ipchecksum(packet,true);
  return true;
}

void printmac(macaddr_t mac){
  printf("%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void printip(uint32_t addr){
  printf("%d.%d.%d.%d",addr&0xff,(addr>>8)&0xff,(addr>>16)&0xff,(addr>>24));
}