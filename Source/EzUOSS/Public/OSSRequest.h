// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once
/*
#include "CoreMinimal.h"
#include "OSSType.h"
#include "OSSPackage.h"
// #include "HAL/PlatformAtomics.h"
// #include "HAL/PlatformMisc.h"
#include "curl/curl.h"
#include "util.h"
#include "string_buffer.h"
#include "response_headers_handler.h"
#include "error_parser.h"

#define HEAD_NORMAL_LEN 128
#define HEAD_WEBSITE_LEN 2200
#define HEAD_AUTH_LEN 1028
#define BUCKET_LEN 65
#define DOMAIN_LEN 254

#define OBS_SDK_VERSION "3.21.8"
#define USER_AGENT_VALUE  "obs-sdk-c-3.21.8" ;

#define DEFAULT_LOW_SPEED_LIMIT    (1)
#define DEFAULT_LOW_SPEED_TIME_S   (300)
#define DEFAULT_CONNECTTIMEOUT_MS  (60000)
#define DEFAULT_TIMEOUT_S          (0)

#define signbuf_append(format, ...)                             \
    if (snprintf_s(&(signbuf[len]), buf_len - (len), _TRUNCATE,format, __VA_ARGS__) > 0) \
    {\
        (len) += snprintf_s(&(signbuf[len]), buf_len - (len), _TRUNCATE,      \
            format, __VA_ARGS__);                                                     \
    }\

#define uri_append(fmt, ...)                                                 \
        do {                                                                     \
            len += snprintf_s(&(buffer[len]), buffer_size - len, _TRUNCATE,  fmt, __VA_ARGS__); \
            if (len >= buffer_size) {                                             \
                return OBS_STATUS_UriTooLong;                                       \
            }                                                                    \
        } while (0)

#define curl_easy_setopt_safe(opt, val)                                 \
                if ((status = curl_easy_setopt                                      \
                     (request->curl, opt, val)) != CURLE_OK) {                      \
                    UE_LOG(LogOSS, Warning, TEXT("curl_easy_setopt_safe failed, status: %d"),status);  \
                    return OBS_STATUS_FailedToIInitializeRequest;                       \
                }

#define append_standard_header(fieldName)                               \
                    if (values-> fieldName [0]) {                                       \
                        request->headers = curl_slist_append(request->headers,          \
                                                             values-> fieldName);       \
                    }

#define append_request(str) len += sprintf_s(&(buffer[len]), buffer_size-len, "%s", str)

#define return_status(status)                                           \
    (*(params->complete_callback))(status, 0, params->callback_data);     \
	UE_LOG(LogOSS, Warning, TEXT("%s status = %d"), __FUNCTION__,status);\
    return


#define return_status(status)                                           \
    (*(params->complete_callback))(status, 0, params->callback_data);     \
    UE_LOG(LogOSS, Warning, TEXT("%s status = %d"), __FUNCTION__,status);\
    return

// ======================== request_util start ==========

#define SSEC_KEY_MD5_LENGTH 64

#define signbuf_attach(format, ...)                             \
        do{\
            int lenAdded = snprintf_s(&(signbuf[len]), sizeof(signbuf) - len,_TRUNCATE,format, __VA_ARGS__);\
            if (lenAdded > 0)  \
            {\
                len += lenAdded;\
            }else\
            {\
				UE_LOG(LogOSS, Error, TEXT("attch string failed in compose_authV2_temp_header, lenAdded is[%d]"),lenAdded);\
            }\
        }while(0)


// ======================== request_util end ==========

// ======================== util start ==========

int urlEncode(char* dest, const char* src, int maxSrcSize, char ignoreChar)
{
	if (dest == NULL) {
		// COMMLOG(OBS_LOGERROR, "dest for urlEncode is NULL.");
		return -1;
	}
	if (src == NULL) {
		// COMMLOG(OBS_LOGWARN, "src for urlEncode is NULL.");
		*dest = 0;
		return 1;
	}
	int len = 0;
	while (*src) {
		if (++len > maxSrcSize) {
			*dest = 0;
			return 0;
		}
		unsigned char c = *src;
		if (isalnum(c) || (c == '.') || (c == '-')
			|| (c == '_') || (c == '~')
			|| (c == ignoreChar))
		{
			*dest++ = c;
		}
		else {
			*dest++ = '%';
			*dest++ = "0123456789ABCDEF"[c >> 4];
			*dest++ = "0123456789ABCDEF"[c & 15];
		}
		++src;
	}

	*dest = 0;
	return 1;
}

int urlDecode(char* dest, const char* src, int maxSrcSize)
{
	int len = 0;
	char strOne[4] = { 0 };
	int charGot = 0;

	if (src) while (*src) {
		if (++len > maxSrcSize) {
			*dest = 0;
			return 0;
		}
		unsigned char c = *src;
		if (c == '%') {
			src++;

			FMemory::Memmove(strOne, src, 2);
			errno_t err = 0;
			if (err != EOK)
			{
				// COMMLOG(OBS_LOGWARN, "%s(%d): memmove_s failed!(%d)", __FUNCTION__, __LINE__, err);
			}
			int ret = sscanf_s(strOne, "%02x", &charGot);
			if (ret != 1) {
				// COMMLOG(OBS_LOGWARN, "%s(%d): sscanf_s failed!(%d)", __FUNCTION__, __LINE__);
			}
			FMemory::Memset(strOne, 0, 4);
			src++;

			*dest++ = (char)charGot;
		}
		else
		{
			*dest++ = c;
		}
		src++;
	}

	*dest = 0;

	return 1;
}

// ======================== util end ==========

struct request_computed_values
{
	char* amzHeaders[OBS_MAX_METADATA_COUNT + 3];

	int amzHeadersCount;

	char amzHeadersRaw[30000 + COMPACTED_METADATA_BUFFER_SIZE + 256 + 1];

	string_multibuffer(canonicalizedAmzHeaders,
		COMPACTED_METADATA_BUFFER_SIZE + 30000 + 256 + 1);

	char urlEncodedKey[MAX_URLENCODED_KEY_SIZE + 1];

	char urlEncodedSrcKey[MAX_URLENCODED_KEY_SIZE + 1];

	char canonicalizedResource[MAX_CANONICALIZED_RESOURCE_SIZE + 1];

	char cacheControlHeader[HEAD_NORMAL_LEN];

	char contentTypeHeader[HEAD_NORMAL_LEN];

	char md5Header[HEAD_NORMAL_LEN];

	char contentDispositionHeader[HEAD_NORMAL_LEN];

	char contentEncodingHeader[HEAD_NORMAL_LEN];

	char websiteredirectlocationHeader[HEAD_WEBSITE_LEN];

	char expiresHeader[HEAD_NORMAL_LEN];

	char ifModifiedSinceHeader[HEAD_NORMAL_LEN];

	char ifUnmodifiedSinceHeader[HEAD_NORMAL_LEN];

	char ifMatchHeader[HEAD_NORMAL_LEN];

	char ifNoneMatchHeader[HEAD_NORMAL_LEN];

	char rangeHeader[HEAD_NORMAL_LEN];

	char authorizationHeader[HEAD_AUTH_LEN];

	char tokenHeader[HEAD_AUTH_LEN];

	char userAgent[HEAD_NORMAL_LEN];

};

struct temp_auth_info
{
	char* tempAuthParams;
	char* temp_auth_headers;
};

struct http_request
{
	struct http_request* prev, * next;
	obs_status status;
	int httpResponseCode;
	struct curl_slist* headers;
	CURL* curl;
	char uri[MAX_URI_SIZE + 1];
	obs_response_properties_callback* properties_callback;
	obs_put_object_data_callback* toS3Callback;
	int64_t toS3CallbackBytesRemaining;
	obs_get_object_data_callback* fromS3Callback;
	obs_response_complete_callback* complete_callback;
	void* callback_data;
	response_headers_handler responseHeadersHandler;
	int propertiesCallbackMade;
	error_parser errorParser;
};


class OSSRequest
{

public:
	static void set_use_api_switch(const obs_options* options, obs_use_api* use_api_temp);

	void request_perform(const request_params* params);

	static void request_finish(http_request* request);

	static void request_release(http_request* request);

	static obs_status get_api_version(char *bucket_name,char *host_name,obs_protocol protocol);

	// ======================== request_util start ==========
	obs_status encode_key(const char* pSrc, char* pValue);

	// ======================== request_util end ==========

	static void release_token();

	static obs_status request_get(const request_params* params,
		const request_computed_values* values,
		http_request** reqReturn,
		temp_auth_info* stTempAuthInfo);


PACKAGE_SCOPE:

	// Used to lock access to add/remove/find requests
	static FCriticalSection RequestLock;


};

*/