/*
 * Copyright (C) 2015 Aliak <aliakr18@gmail.com>
 * Copyright (C) 2015 173210 <root.3.173210@live.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
