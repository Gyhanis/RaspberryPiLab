#include <stdint.h>
#include <stdlib.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  uint32_t sum,carry;
  sum = 0;
  len = packet[0];
  len &= 0x0f;
  len <<= 2;
  //printf("%d\n",len);
  for(int i = 0; i < len; i+=2){
    uint32_t temp;
    temp = packet[i];
    temp <<= 8;
    temp += packet[i+1];
    //printf("temp:%x\n",temp);
    sum += temp;
  }
  while(carry = (sum>>16)){
    sum &= 0xffff;
    sum += carry;
  }
  if(sum == 0xffff)
    return true;
  else
    return false;
}
