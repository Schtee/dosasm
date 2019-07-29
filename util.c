#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

extern void exe;

struct Registers
{
	uint16_t ax;
	uint16_t bx;
	uint16_t cx;
	uint16_t dx;
};

void int21(uint8_t ah, struct Registers *r)
{
	switch (ah)
	{
		case 0x2A:
			{
				time_t rawTime = time(NULL);
				struct tm *info = localtime(&rawTime);
				// al = day, cx = year (1980-2099, dh = month (1-12), dl = day (1-31)
				r->ax = (r->ax & 0xFF00) | info->tm_wday;
				r->cx = 1900 + info->tm_year;
				r->dx = ((info->tm_mon + 1) << 8) | info->tm_mday;
			}
			break;
		
		case 0x2C:
			{
				time_t rawTime = time(NULL);
				struct tm *info = localtime(&rawTime);
				// CH = hour (0-23), CL = minutes (0-59), DH = seconds (0-59), DL = hundredths (0-99)
				r->cx = (info->tm_hour << 8) | info->tm_min;
				r->dx = (info->tm_sec << 8);
			}
			break;

		// Get DOS version. Let's be 7.00!
		case 0x30:
			r->ax = 0x0007;
			// BH = MS-DOS OEM number if DOS 5+ and AL=01h or1 version flag bit 3: DOS is in ROM other: reserved (0)
			// 24 bit serial number in BL:CX
			r->bx = 0;
			r->cx = 0;
			break;

		case 0x40:
			if (r->bx == 1)
			{
				char* buff = malloc(r->cx);
				char* src = &exe + r->dx;
				strncpy(buff, src, r->cx);
				printf("Got stdout int with: %s\n", buff);
			}
			else
			{
				printf("Writing to unhandled file handle %d\n", r->bx);
			}
			break;
		case 0x4C:
			printf("Got exit interrupt - quitting.\n");
			exit(ah);
			break;
		default:
			printf("Unhandled int 0x20, ah: 0x%01x\n", ah);
			break;
	}
}

/* weird ordering is intentional, as linux x64 calling convention uses:
rdi, rsi, rdx, rcx, r8
the expected order (ax, bx, cx, dx) would need swapping to get rdx populated without losing cx
returns 64bit [ax][bx][cx][dx]*/
uint64_t int_sim(uint8_t interrupt, uint16_t ax, uint16_t dx, uint16_t cx, uint16_t bx)
{
	uint8_t ah = ax >> 8;

	struct Registers r;
	r.ax = ax;
	r.bx = bx;
	r.cx = cx;
	r.dx = dx;

	printf("int 0x%01x, ah: 0x%01x ax: 0x%02x, bx: 0x%02x, cx: 0x%02x, dx: 0x%02x\n", interrupt, ah, ax, bx, cx, dx);

	switch (interrupt)
	{
		case 0x21:
			int21(ah, &r);
			break;
		default:
			printf("Unhandled int 0x%02x\n", interrupt);
			break;
	}

	printf("Setting registers ax: 0x%02x, bx: 0x%02x, cx: 0x%02x, dx: 0x%02x\n", r.ax, r.bx, r.cx, r.dx);

	uint64_t result = ((uint64_t)r.ax << 3 * 16) | ((uint64_t)r.bx << 2 * 16) | ((uint64_t)r.cx << 16) | (r.dx);
	return result;
}
