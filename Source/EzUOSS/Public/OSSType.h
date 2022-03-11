// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

/* success */
#define EOK (0)

#define int32_t int32
#define int64_t int64
#define uint32_t uint32
#define uint64_t uint64


enum OBS_LOGLEVEL
{
	OBS_LOGDEBUG = 0,
	OBS_LOGINFO,
	OBS_LOGWARN,
	OBS_LOGERROR
};

// memset_s(void* dest, size_t destMax, int c, size_t count);
#define memset_s(dest, destMax, c, count) FMemory::Memset(dest, c, count)

// memcpy_s(void* dest, size_t destMax, const void* src, size_t count);
#define memcpy_s(dest, destMax, src, count) FMemory::Memcpy(dest, src, count)

// memmove_s(void* dest, size_t destMax, const void* src, size_t count);
#define memmove_s(dest, destMax, src, count) FMemory::Memmove(dest, src, count)


// SECURECTYPE.H
/* define the max length of the string */
#define SECUREC_STRING_MAX_LEN (0x7fffffffUL)
#define SECUREC_WCHAR_STRING_MAX_LEN (SECUREC_STRING_MAX_LEN / WCHAR_SIZE)

/* add SECUREC_MEM_MAX_LEN for memcpy and memmove*/
#define SECUREC_MEM_MAX_LEN (0x7fffffffUL)
#define SECUREC_WCHAR_MEM_MAX_LEN (SECUREC_MEM_MAX_LEN / WCHAR_SIZE)


#define PRODUCT "obs-sdk-c"