#include "OSSManger.h"
#include "EzUOSS.h"
#include "OSSRequest.h"
#include "OSSLog.h"


/*

void OSSManager::put_object(const obs_options* options, char* key, uint64 content_length, obs_put_properties* put_properties, server_side_encryption_params* encryption_params, obs_put_object_handler* handler, void* callback_data)
{

// 	// 请求参数
// 	request_params params;
// 	UE_LOG(LogOSS, Log, TEXT("Enter put_object successfully !"));
// 	obs_use_api use_api = OBS_USE_API_S3;
// 	OSSRequest::set_use_api_switch(options, &use_api);
// 
// 	if (!options->bucket_options.bucket_name) {
// 		UE_LOG(LogOSS, Log, TEXT("bucket_name is NULL!"));
// 		(void)(*(handler->response_handler.complete_callback))(OBS_STATUS_InvalidBucketName, 0, callback_data);
// 		return;
// 	}
// 	FMemory::Memset(&params, 0, sizeof(request_params));
// 
// 	FMemory::Memcpy(&params.bucketContext, &options->bucket_options, sizeof(obs_bucket_context));
// 
// 	FMemory::Memcpy(&params.request_option, &options->request_options, sizeof(obs_http_request_option));
// 
// 	params.temp_auth = options->temp_auth;
// 	params.httpRequestType = http_request_type_put;
// 	params.key = key;
// 	params.put_properties = put_properties;
// 	params.encryption_params = encryption_params;
// 	params.toObsCallback = handler->put_object_data_callback;
// 	params.toObsCallbackTotalSize = content_length;
// 	params.properties_callback = handler->response_handler.properties_callback;
// 	params.complete_callback = handler->response_handler.complete_callback;
// 	params.callback_data = callback_data;
// 	params.isCheckCA = options->bucket_options.certificate_info ? 1 : 0;
// 	params.storageClassFormat = storage_class;
// 	params.use_api = use_api;
// 
// 	OSSRequest Request;
// 	Request.request_perform(&params);
// 	UE_LOG(LogOSS, Log, TEXT("Leave put_object successfully !"));
}

*/