#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


int validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  uint16_t *p;
  uint32_t sum,carry;
  sum = 0;
  len >>= 1;
  p = (uint16_t*) packet;

  for(int i = 0; i < len; i++){
    sum += p[i];
  }
  while(carry = (sum>>16)){
    sum &= 0xffff;
    sum += carry;
  }
  if(sum)
    return 0;
  else
    return 1;
}

int main(){
	uint8_t packet[20]={0x45,0x00,0x00,0x20,0x00,0x00,0x40,0x00,0x40,0x11,0x0d,0x63,0xb7,0xad,0x71,0xb7,0x01,0x02,0x03,0x04};
	for(int i = 0; i < 20; i++)
		packet[i] = 0;
	if(validateIPChecksum(packet,20)){
		printf("Yes\n");
	}else
		printf("No\n");
	return 0;
}
