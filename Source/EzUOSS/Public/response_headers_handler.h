/*********************************************************************************
* Copyright 2019 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use
* this file except in compliance with the License.  You may obtain a copy of the
* License at
* 
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software distributed
* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
* CONDITIONS OF ANY KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations under the License.
**********************************************************************************
*/

#pragma once
#include "OSSType.h"
#include "string_buffer.h"

#if WITH_LIBCURL
#if PLATFORM_WINDOWS || PLATFORM_HOLOLENS
#include "Windows/WindowsHWrapper.h"
#include "Windows/AllowWindowsPlatformTypes.h"
#endif
#include "curl/curl.h"
#if PLATFORM_WINDOWS || PLATFORM_HOLOLENS
#include "Windows/HideWindowsPlatformTypes.h"
#endif

#include "util.h"


struct response_headers_handler
{
   
    // obs_response_properties responseProperties;

    // int done;

    //string_multibuffer(responsePropertyStrings, 5 * 129);

    //string_multibuffer(responseMetaDataStrings, COMPACTED_METADATA_BUFFER_SIZE);

    // obs_name_value responseMetaData[OBS_MAX_METADATA_COUNT];

};
//
//void response_headers_handler_initialize(response_headers_handler* handler);
//
//void response_headers_handler_add(response_headers_handler* handler,
//		char* data, int dataLen);
//
//void response_headers_handler_done(response_headers_handler* handler,
//		CURL* curl);

#endif //WITH_LIBCURL