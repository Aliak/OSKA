#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include "oska.h"

void waitKey() {
	while (aptMainLoop())
	{
		// Wait next screen refresh
		gspWaitForVBlank();

		// Read which buttons are currently pressed 
		hidScanInput();
		u32 kDown = hidKeysDown();
		u32 kHeld = hidKeysHeld();
		
		// If B is pressed, break loop and quit
		if (kDown & KEY_X){
			break;
		}

		// Flush and swap framebuffers
		gfxFlushBuffers();
		gfxSwapBuffers();
	}
}

int main()
{
	// Initialize services
	srvInit();			// mandatory
	aptInit();			// mandatory
	hidInit(NULL);	// input (buttons, screen)
	gfxInitDefault();			// graphics
	fsInit();
	sdmcInit();
	hbInit();

	qtmInit();
	consoleInit(GFX_BOTTOM, NULL);

	svcSleepThread(1000000000);

	run_exploit();

	//consoleClear();	                     
	printf("\nPress [X] to return to launcher\n");

	waitKey();

	printf("Exiting...\n");

	// Exit services
	hbExit();
	sdmcExit();
	fsExit();
	gfxExit();
	hidExit();
	aptExit();
	srvExit();
	
	// Return to hbmenu
	return 0;
}
