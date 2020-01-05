#ifndef MY_TOOLS
#define MY_TOOLS

#include <stdint.h>
#include <stdio.h>

typedef uint8_t macaddr_t[6];

#define MULTICAST 0x090000e0

#define getSrc(packet) (((uint32_t*)(packet))[3])
#define getDst(packet) (((uint32_t*)(packet))[4])
#define getLen(packet) ((((uint16_t)(packet[2])) << 8)|((uint16_t)(packet[3])))

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

uint32_t reverse(uint32_t a);
uint16_t reverse(uint16_t a);
void printip(uint32_t addr);
void printmac(macaddr_t mac);
bool forward(uint8_t *packet);
bool ipchecksum(uint8_t *packet,bool cal);
#endif
