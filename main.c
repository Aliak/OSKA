#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include "oska.h"

static void waitKey()
{
	while (aptMainLoop()) {
		gspWaitForVBlank();

		hidScanInput();
		if (hidKeysDown() & KEY_X)
			break;

		gfxFlushBuffers();
		gfxSwapBuffers();
	}
}

int main()
{
	srvInit();
	aptInit();
	hidInit(NULL);
	gfxInitDefault();
	fsInit();
	sdmcInit();
	hbInit();

	qtmInit();
	consoleInit(GFX_TOP, NULL);

	svcSleepThread(1000000000);

	exploit();
	
	//consoleClear();
	printf("\nPress [X] to return to launcher\n");

	waitKey();

	printf("Exiting...\n");

	hbExit();
	sdmcExit();
	fsExit();
	gfxExit();
	hidExit();
	aptExit();
	srvExit();

	return 0;
}
