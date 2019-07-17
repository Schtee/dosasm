#include <stdint.h>
#include <stdio.h>

void int_sim(uint8_t interrupt, uint16_t ax)
{
	printf("int 0x%02x, 0x%02x\n", interrupt, ax);
}
