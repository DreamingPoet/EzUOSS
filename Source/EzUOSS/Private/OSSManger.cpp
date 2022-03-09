#include "OSSManger.h"
#include "EzUOSS.h"




void put_object(const oss_options* options, char* key, uint64_t content_length, oss_put_properties* put_properties, server_side_encryption_params* encryption_params, oss_put_object_handler* handler, void* callback_data)
{

	// ÇëÇó²ÎÊý
	request_params params;
	UE_LOG(LogOSS, Log, TEXT("Enter put_object successfully !"));
	oss_use_api use_api = oss_USE_API_S3;
	set_use_api_switch(options, &use_api);

	if (!options->bucket_options.bucket_name) {
		UE_LOG(LogOSS, Log, TEXT("bucket_name is NULL!"));
		(void)(*(handler->response_handler.complete_callback))(oss_STATUS_InvalidBucketName, 0, callback_data);
		return;
	}

	memset_s(&params, sizeof(request_params), 0, sizeof(request_params));
	errno_t err = EOK;
	err = memcpy_s(&params.bucketContext, sizeof(oss_bucket_context), &options->bucket_options,
		sizeof(oss_bucket_context));
	CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);
	err = memcpy_s(&params.request_option, sizeof(oss_http_request_option), &options->request_options,
		sizeof(oss_http_request_option));
	CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

	params.temp_auth = options->temp_auth;
	params.httpRequestType = http_request_type_put;
	params.key = key;
	params.put_properties = put_properties;
	params.encryption_params = encryption_params;
	params.toObsCallback = handler->put_object_data_callback;
	params.toObsCallbackTotalSize = content_length;
	params.properties_callback = handler->response_handler.properties_callback;
	params.complete_callback = handler->response_handler.complete_callback;
	params.callback_data = callback_data;
	params.isCheckCA = options->bucket_options.certificate_info ? 1 : 0;
	params.storageClassFormat = storage_class;
	params.use_api = use_api;

	request_perform(&params);
	UE_LOG(LogOSS, Log, TEXT("Leave put_object successfully !"));
}
