#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */

bool validateIPChecksum(uint8_t *packet) {
  uint32_t sum,carry,sum2;
  size_t len;
  sum = 0;
  len = packet[0];
  len &= 0x0f;
  len <<= 2;
  for(int i = 0; i < len; i+=2){
    uint32_t temp;
    temp = packet[i];
    temp <<= 8;
    temp += packet[i+1];
    sum += temp;
  }
  sum2 = sum;
  while(carry = (sum>>16)){
    sum &= 0xffff;
    sum += carry;
  }
  if(sum == 0xffff)
    return true;
  else{
    uint32_t temp;
    temp = packet[10];
    temp <<= 8;
    temp |= packet[11];
    sum2 -= temp;
    while(carry = (sum2>>16)){
      sum2 &= 0xffff;
      sum2 += carry;
    }
    temp = ~sum2;
    packet[11] = temp;
    packet[10] = temp>>8;
    return false;
  }
}

bool forward(uint8_t *packet, size_t len) {
  if(validateIPChecksum(packet)){
    packet[8]--;
    validateIPChecksum(packet);
    return true;
  }
  return false;
}
