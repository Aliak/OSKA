#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include "bootstrap.h"

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

	doARM11Hax();

	//consoleClear();

	while (aptMainLoop())
	{
		// Wait next screen refresh
		gspWaitForVBlank();

		// Read which buttons are currently pressed 
		hidScanInput();
		u32 kDown = hidKeysDown();
		u32 kHeld = hidKeysHeld();
		
		// If START is pressed, break loop and quit
		if (kDown & KEY_X){
			break;
		}

		if (kDown & KEY_A)
		{
			consoleClear();
			printf("%x \n", arm11_buffer[0]);
			int i;
			for(i = 0; i < 0x80; i += 4)
			{
				printf("%x ", arm11_buffer[1+i]);
				if((i/4) % 4 == 0 && i != 0)
					printf("\n");
			}
		}
		// Flush and swap framebuffers
		gfxFlushBuffers();
		gfxSwapBuffers();
	}

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
