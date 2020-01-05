#ifndef RIPMAN
#define RIPMAN

#include "router_hal.h"
#include "tools.h"
#include "entryList.h"
#include <stdint.h>
#include <stdio.h>

#define RIP_REQUEST 2
#define RIP_UPDATE  1
#define RIP_NONE    0
#define RIP_ERROR   -1

#define RIP_MAX_ENTRY 25

void RipInit();
int  LaunchRip(uint32_t ipaddr,int if_index);
int  handleRip(uint8_t *packet,int if_index);
#endif