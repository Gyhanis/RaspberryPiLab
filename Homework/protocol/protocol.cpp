#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
// #include <stdio.h>
#include <string.h>
const uint32_t MaskList[33] = {
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
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */

#define b2l(x) (((uint32_t)(*(char*)(x)) << 24)|((uint32_t)(*(char*)(x+1)) << 16)|((uint32_t)(*(char*)(x+2)) << 8)|((uint32_t)(*(char*)(x+2))))

bool loadEntry(const uint8_t *source, RipEntry * dest,uint8_t cmd){
  uint16_t family = ((uint16_t)(source[0]) << 8) | source[1];
  uint16_t tag    = ((uint16_t)(source[2]) << 8) | source[3];
  uint32_t addr   = *(uint32_t *)(source + 4);
  uint32_t mask   = *(uint32_t *)(source + 8);
  uint32_t next   = *(uint32_t *)(source + 12);
  uint32_t metric = *(uint32_t *)(source + 16);
  unsigned int i;
  if((family != ((cmd-1) << 1)) || (tag != 0)){
    // printf("family or tag error\n");
    return false;
  }
  for(i = 0; i < 33; i++){
    if(MaskList[i] == mask){
      break;
    }
  }
  // printf("checkpoint\n");
  if(i == 33){
    // printf("MaskError\n");
    return false;
  }
  i = metric >> 24;
  if(i == 0 || i > 16){
    return false;
  }
  dest->addr = addr;
  dest->mask = mask;
  dest->nexthop = next;
  dest->metric = metric;
  return true;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
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
  if(iplen > len || zero || ver != 2){
    // printf("len zero error\n");
    return false;
  }
  if(cmd != 1 && cmd != 2){
    // printf("cmd error\n");
    return false;
  }
  while(entry < end){
    if(!loadEntry(entry,(output->entries + count),cmd)){
      // printf("load error\n");
      return false;
    }
    entry += 20;
    count++;
  }
  output->numEntries = count;
  output->command = cmd;
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  uint8_t * entry;
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = 0;
  buffer[3] = 0;
  entry = buffer+4;
  // printf("rip:%p\n",rip);
  // printf("entry:%p\n",entry);
  // entry[0] = 0xff;
  for(int i = 0; i < rip->numEntries; i++){
    // printf("writing\n");
    entry[0] = 0;
    entry[1] = (rip->command-1) << 1;
    entry[2] = 0;
    entry[3] = 0;
    // memcpy(entry+4,&(rip->entries[i].addr),20);
    // printf("Rip addr:%x\n",rip->entries[i].addr);
    ((uint32_t*)entry)[1] = rip->entries[i].addr;
    ((uint32_t*)entry)[2] = rip->entries[i].mask;
    ((uint32_t*)entry)[3] = rip->entries[i].nexthop;
    ((uint32_t*)entry)[4] = rip->entries[i].metric;
    entry += 20;
  }
  return (uint32_t)((char*)entry-(char*)buffer);
}
