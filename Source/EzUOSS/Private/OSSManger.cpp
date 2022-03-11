
#include "OSSManger.h"
#include "util.h"
#include "OSSRequest.h"

#if WITH_LIBCURL
#if PLATFORM_WINDOWS || PLATFORM_HOLOLENS
#include "Windows/WindowsHWrapper.h"
#include "Windows/AllowWindowsPlatformTypes.h"
#endif
#include <curl/curl.h>
#if PLATFORM_WINDOWS || PLATFORM_HOLOLENS
#include "Windows/HideWindowsPlatformTypes.h"
#endif

obs_status obs_initialize(int win32_flags)
{
	CURLcode retCode = CURLE_OK;
	obs_status ret = OBS_STATUS_OK;

	SYSTEMTIME reqTime;
	GetLocalTime(&reqTime);

	// LOG_INIT();
	// xmlInitParser();
	// COMMLOG(OBS_LOGWARN, "%s OBS SDK Version= %s", __FUNCTION__, OBS_SDK_VERSION);
	retCode = curl_global_init(CURL_GLOBAL_ALL);
	if (retCode != CURLE_OK)
	{
		// COMMLOG(OBS_LOGWARN, "%s curl_global_init failed retcode = %d", __FUNCTION__, retCode);
		return OBS_STATUS_InitCurlFailed;
	}

	ret = request_api_initialize(win32_flags);

	SYSTEMTIME rspTime;
	GetLocalTime(&rspTime);
	// INTLOG(reqTime, rspTime, ret, "");

	return ret;
}

void obs_deinitialize()
{
	// LOG_EXIT();
	request_api_deinitialize();
	// TODO:: xmlCleanupParser();
	curl_global_cleanup();
}

void init_obs_options(obs_options* options)
{
	options->request_options.speed_time = DEFAULT_LOW_SPEED_TIME_S;
	options->request_options.max_connected_time = DEFAULT_TIMEOUT_S;
	options->request_options.connect_time = DEFAULT_CONNECTTIMEOUT_MS;
	options->request_options.speed_limit = DEFAULT_LOW_SPEED_LIMIT;
	options->request_options.proxy_auth = NULL;
	options->request_options.proxy_host = NULL;
	options->request_options.ssl_cipher_list = NULL;
	options->request_options.http2_switch = OBS_HTTP2_CLOSE;
	options->request_options.bbr_switch = OBS_BBR_CLOSE;
	options->request_options.auth_switch = OBS_NEGOTIATION_TYPE;
	options->request_options.buffer_size = 16 * 1024L;

	options->bucket_options.access_key = NULL;
	options->bucket_options.secret_access_key = NULL;
	options->bucket_options.bucket_name = NULL;
	options->bucket_options.certificate_info = g_ca_info[0] ? g_ca_info : NULL;
	options->bucket_options.host_name = NULL;
	options->bucket_options.protocol = g_protocol;
	options->bucket_options.storage_class = OBS_STORAGE_CLASS_STANDARD;
	options->bucket_options.token = NULL;
	options->bucket_options.uri_style = OBS_URI_STYLE_VIRTUALHOST;
	options->bucket_options.epid = NULL;
	options->temp_auth = NULL;
}

void list_bucket(const obs_options* options, obs_list_service_handler* handler, void* callback_data)
{
// 	obs_use_api use_api = OBS_USE_API_S3;
// 
// 	if (options->request_options.auth_switch == OBS_OBS_TYPE)
// 	{
// 		use_api = OBS_USE_API_OBS;
// 	}
// 	else if (options->request_options.auth_switch == OBS_S3_TYPE)
// 	{
// 		use_api = OBS_USE_API_S3;
// 	}
// 
// 	request_params      params;
// 
// 	// COMMLOG(OBS_LOGINFO, "Enter list_bucket successfully !");
// 
// 	xml_callback_data* data = (xml_callback_data*)malloc(sizeof(xml_callback_data));
// 	if (!data)
// 	{
// 		(void)(*(handler->response_handler.complete_callback))(OBS_STATUS_OutOfMemory,
// 			0, callback_data);
// 		// COMMLOG(OBS_LOGERROR, "Malloc XmlCallbackData failed !");
// 		return;
// 	}
// 	memset_s(data, sizeof(xml_callback_data), 0, sizeof(xml_callback_data));
// 
// 	simplexml_initialize(&(data->simpleXml), &xml_callback, data);
// 
// 	data->responsePropertiesCallback = handler->response_handler.properties_callback;
// 	data->listServiceCallback = handler->listServiceCallback;
// 	data->responseCompleteCallback = handler->response_handler.complete_callback;
// 	data->callback_data = callback_data;
// 
// 	string_buffer_initialize(data->owner_id);
// 	string_buffer_initialize(data->owner_display_name);
// 	string_buffer_initialize(data->bucket_name);
// 	string_buffer_initialize(data->creationDate);
// 
// 	memset_s(&params, sizeof(request_params), 0, sizeof(request_params));
// 
// 	errno_t err = EOK;
// 	err = memcpy_s(&params.bucketContext, sizeof(obs_bucket_context), &options->bucket_options,
// 		sizeof(obs_bucket_context));
// 	// CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);
// 	err = memcpy_s(&params.request_option, sizeof(obs_http_request_option), &options->request_options,
// 		sizeof(obs_http_request_option));
// 	// CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);
// 
// 	params.httpRequestType = http_request_type_get;
// 	params.properties_callback = &properties_callback;
// 	params.fromObsCallback = &data_callback;
// 	params.complete_callback = &complete_callback;
// 	params.callback_data = data;
// 	params.isCheckCA = options->bucket_options.certificate_info ? 1 : 0;
// 	params.storageClassFormat = no_need_storage_class;
// 	params.temp_auth = options->temp_auth;
// 	params.use_api = use_api;
// 
// 	request_perform(&params);
	// COMMLOG(OBS_LOGINFO, "Leave list_bucket successfully !");
}



#endif //WITH_LIBCURL