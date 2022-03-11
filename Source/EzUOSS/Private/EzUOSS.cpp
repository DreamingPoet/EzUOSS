// Copyright Epic Games, Inc. All Rights Reserved.

#include "EzUOSS.h"
//#include "HttpModule.h"
//#include "Interfaces/IHttpRequest.h"

#include "OSSManger.h"

#define LOCTEXT_NAMESPACE "FEzUOSSModule"

DEFINE_LOG_CATEGORY(LogOSS);

void FEzUOSSModule::StartupModule()
{
	// This code will execute after your module is loaded into memory; the exact timing is specified in the .uplugin file per-module

	/*
	// 初始化
	ossmanger.obs_initialize(OBS_INIT_ALL);

	obs_options option;
	init_obs_options(&option);

	option.bucket_options.host_name = HOST_NAME;
	option.bucket_options.access_key = ACCESS_KEY_ID;
	option.bucket_options.secret_access_key = SECRET_ACCESS_KEY;
	option.bucket_options.protocol = OBS_PROTOCOL_HTTPS;
	option.request_options.auth_switch == OBS_S3_TYPE;

	list_service_data data;
	memset_s(&data, sizeof(data), 0, sizeof(list_service_data));

	obs_list_service_handler listHandler =
	{
		{&response_properties_callback,
		&list_bucket_complete_callback },
		&listServiceCallback
	};

	list_bucket(&option, &listHandler, &data);
	if (data.ret_status == OBS_STATUS_OK)
	{
		printf("list bucket successfully. \n");
	}
	else
	{
		printf("list bucket failed(%s).\n", obs_get_status_name(data.ret_status));
	}
	*/
}

void FEzUOSSModule::ShutdownModule()
{
	// This function may be called during shutdown to clean up your module.  For modules that support dynamic reloading,
	// we call this function before unloading the module.

	/*
		// 创建Http 请求
	TSharedRef<IHttpRequest> Request = FHttpModule::Get().CreateRequest();
	// 设置请求头
	Request->SetHeader("Content-Type", "text/javascript;charset=utf-8");
	// 设置请求方式
	Request->SetVerb("POST");
	// 请求的链接
	Request->SetURL("192.168.5.21:8000/test_ue4"); // 服务端预留的测试接口
	// 内容包
	//Request->SetContentAsString(server_data);
	// 设置回调函数
	Request->OnProcessRequestComplete().BindUObject(this, &UNetWidget::RequestComplete);
	// 发送请求
	Request->ProcessRequest();
*/
}


#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FEzUOSSModule, EzUOSS)