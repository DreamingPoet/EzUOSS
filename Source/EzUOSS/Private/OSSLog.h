// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once
#include "EzUOSS.h"


enum OBS_LOGLEVEL
{
	OBS_LOGDEBUG = 0,
	OBS_LOGINFO = 1,
	OBS_LOGWARN = 2,
	OBS_LOGERROR = 3
};


class OSSLog
{

// public:
// 	static void CheckAndLogNoneZero(int ret, const char* name, const char* funcName, unsigned long line) {
// 		if (ret != 0) {
// 			UE_LOG(LogOSS, Warning, TEXT("%s failed in %s.(%ld)"), name, funcName, line);
// 		}
// 	}
// 
// 	static void CheckAndLogNeg(int ret, const char* name, const char* funcName, unsigned long line) {
// 		if (ret < 0) {
// 			UE_LOG(LogOSS, Warning, TEXT("%s failed in %s.(%ld)"), name, funcName, line);
// 		}
// 	}

};
