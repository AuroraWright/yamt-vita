/*
	YAMT-V by SKGleba
	All Rights Reserved
*/

#include "tai_compat.h"

static char *umastr = NULL;

static int mthr(SceSize args, void *argp)
{
	ksceIoUmount(0x800, 0, 0, 0);
	ksceIoUmount(0x800, 1, 0, 0);
	ksceIoMount(0x800, NULL, 0, 0, 0, 0);

	if(umastr)
	{
		ksceIoUmount(0xF00, 0, 0, 0);
		ksceIoUmount(0xF00, 1, 0, 0);
		ksceIoMount(0xF00, NULL, 0, 0, 0, 0);
	}

	ksceKernelExitDeleteThread(0);
	return 1;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	// check insert state for gc slot
	if(((unsigned int)(*(int *)(*(int *)(ksceSdifGetSdContextGlobal(1) + 0x2430) + 0x24) << 0xf) >> 0x1f) <= 0)
	    return SCE_KERNEL_START_NO_RESIDENT;

	// Patch SD checks
	char movsr01[2] = {0x01, 0x20};
	INJECT("SceSysmem", 0x21610, movsr01, sizeof(movsr01));

	// String edit iof
#ifdef FW365
	size_t base_oof = (0x1D498 - 0xA0);
#else
	size_t base_oof = (0x1D340 - 0xA0);
#endif
	static char conve[64];
	size_t t_off = 0x808;

	// check for memory card
	if(kscePervasiveRemovableMemoryGetCardInsertState())
		umastr = "sdstor0:xmc-lp-ign-userext";
	else
	{
		// check for internal storage
		void *sysroot = ksceKernelGetSysrootBuffer();
  		if (sysroot) {
			if (*(unsigned char *)(sysroot + 0x35) == 0xFE)
			{
				umastr = "sdstor0:int-lp-ign-userext";
				t_off = 0x340;
			}
		}
		
	}

	memset(&conve, 0, sizeof(conve));
	snprintf(conve, sizeof(conve), "sdstor0:gcd-lp-act-entire");
	INJECT("SceIofilemgr", (base_oof + t_off), conve, strlen(conve) + 1);

	if(umastr)
	{
		memset(&conve, 0, sizeof(conve));
		snprintf(conve, sizeof(conve), umastr);
		INJECT("SceIofilemgr", (base_oof + 0x43C), conve, strlen(conve) + 1);
	}

	// ksceIoMount threaded to save time
	SceUID mthid = ksceKernelCreateThread("x", mthr, 0x00, 0x1000, 0, 0, 0);
	ksceKernelStartThread(mthid, 0, NULL);

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
