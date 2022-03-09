// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"


enum http_request_type
{
	http_request_type_get,
	http_request_type_head,
	http_request_type_put,
	http_request_type_copy,
	http_request_type_delete,
	http_request_type_post,
	http_request_type_options
};

struct oss_options
{
// 	oss_bucket_context bucket_options;
// 	oss_http_request_option request_options;
// 	temp_auth_configure* temp_auth;
};

struct oss_put_properties
{
// 	char* content_type;
// 	char* md5;
// 	char* cache_control;
// 	char* content_disposition_filename;
// 	char* content_encoding;
// 	char* website_redirect_location;
// 	oss_get_conditions* get_conditions;
// 	uint64_t start_byte;
// 	uint64_t byte_count;
// 	int64_t expires;
// 	oss_canned_acl canned_acl;
// 	oss_az_redundancy az_redundancy;
// 	grant_domain_config* domain_config;
// 	int meta_data_count;
// 	oss_name_value* meta_data;
// 	file_object_config* file_object_config;
// 	metadata_action_indicator metadata_action;
};


struct server_side_encryption_params
{
// 	oss_encryption_type encryption_type;
// 	char* kms_server_side_encryption;
// 	char* kms_key_id;
// 	char* ssec_customer_algorithm;
// 	char* ssec_customer_key;
// 	char* des_ssec_customer_algorithm;
// 	char* des_ssec_customer_key;
};


struct oss_put_object_handler
{
// 	oss_response_handler response_handler;
// 	oss_put_object_data_callback* put_object_data_callback;
};

/**************************return struct*******************************************/
struct oss_bucket_context
{
	char* host_name;
	char* bucket_name;
	oss_protocol protocol;
	oss_uri_style uri_style;
	char* access_key;
	char* secret_access_key;
	char* certificate_info;
	oss_storage_class storage_class;
	char* token;
	char* epid;
	oss_bucket_type bucket_type;
	oss_bucket_list_type bucket_list_type;
};

enum oss_http2_switch
{
	OSS_HTTP2_OPEN = 0,
	OSS_HTTP2_CLOSE = 1
};

enum oss_bbr_switch
{
	OSS_BBR_OPEN = 0,
	OSS_BBR_CLOSE = 1
};

enum oss_openssl_switch
{
	OSS_OPENSSL_CLOSE = 0,
	OSS_OPENSSL_OPEN = 1
};

//
enum oss_auth_switch
{
	OSS_NEGOTIATION_TYPE = 0,
	OSS_OSS_TYPE = 1,
	OSS_S3_TYPE = 2
};

// 协议 HTTPS/HTTP
enum oss_protocol
{
	OSS_PROTOCOL_HTTPS = 0,
	OSS_PROTOCOL_HTTP = 1
};

// 域名或者IP
enum oss_uri_style
{
	OSS_URI_STYLE_VIRTUALHOST = 0,
	OSS_URI_STYLE_PATH = 1
};

//
struct oss_http_request_option
{
	int speed_limit;
	int speed_time;
	int connect_time;
	int max_connected_time;
	char* proxy_host;
	char* proxy_auth;
	char* ssl_cipher_list;
	oss_http2_switch http2_switch;
	oss_bbr_switch   bbr_switch;
	oss_auth_switch  auth_switch;
	long buffer_size;
};


// 请求参数
struct request_params
{
	http_request_type httpRequestType;

	oss_bucket_context bucketContext;

	oss_http_request_option request_option;

	temp_auth_configure* temp_auth;

	char* key;

	char* queryParams;

	char* subResource;

	char* copySourceBucketName;

	char* copySourceKey;

	oss_get_conditions* get_conditions;

	oss_cors_conf* corsConf;

	oss_put_properties* put_properties;

	server_side_encryption_params* encryption_params;

	oss_response_properties_callback* properties_callback;

	oss_put_object_data_callback* toObsCallback;

	int64_t toObsCallbackTotalSize;

	oss_get_object_data_callback* fromObsCallback;

	oss_response_complete_callback* complete_callback;

	void* callback_data;

	int isCheckCA;

	oss_storage_class_format storageClassFormat;

	oss_use_api use_api;

};

static void put_object(const oss_options* options, char* key, uint64_t content_length,
	oss_put_properties* put_properties,
	server_side_encryption_params* encryption_params,
	oss_put_object_handler* handler, void* callback_data);