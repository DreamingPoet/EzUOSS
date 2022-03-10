// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include <string.h>

// define error code
#ifndef errno_t
typedef int errno_t;
#endif

// success 
#define EOK (0)


#define OBS_MAX_METADATA_SIZE               4096

#define OBS_METADATA_HEADER_NAME_PREFIX     "x-amz-meta-"

#define OBS_COMMON_LEN_256 256

#define OBS_MAX_ACL_GRANT_COUNT             100

#define OBS_MAX_GRANTEE_EMAIL_ADDRESS_SIZE  128

#define OBS_MAX_GRANTEE_USER_ID_SIZE        128

#define OBS_MAX_GRANTEE_DISPLAY_NAME_SIZE   128

#define OBS_MAX_HOSTNAME_SIZE               255

#define OBS_MAX_KEY_SIZE                    1024

#define OBS_MAX_METADATA_SIZE               4096

#define OBS_METADATA_HEADER_NAME_PREFIX     "x-amz-meta-"

#define OBS_VERSION_STATUS_ENABLED           "Enabled"

#define OBS_VERSION_STATUS_SUSPENDED        "Suspended"

#define OBS_MAX_METADATA_COUNT \
    (OBS_MAX_METADATA_SIZE / (sizeof(OBS_METADATA_HEADER_NAME_PREFIX "nv") - 1))

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

enum obs_use_api
{
	OBS_USE_API_S3 = 0,
	OBS_USE_API_OBS = 1
};


enum obs_http2_switch
{
	OBS_HTTP2_OPEN = 0,
	OBS_HTTP2_CLOSE = 1
};

enum obs_bbr_switch
{
	OBS_BBR_OPEN = 0,
	OBS_BBR_CLOSE = 1
};

enum obs_openssl_switch
{
	OBS_OPENSSL_CLOSE = 0,
	OBS_OPENSSL_OPEN = 1
};

//
enum obs_auth_switch
{
	OBS_NEGOTIATION_TYPE = 0,
	OBS_OBS_TYPE = 1,
	OBS_S3_TYPE = 2
};

// 协议 HTTPS/HTTP
enum obs_protocol
{
	OBS_PROTOCOL_HTTPS = 0,
	OBS_PROTOCOL_HTTP = 1
};

// 域名或者IP
enum obs_uri_style
{
	OBS_URI_STYLE_VIRTUALHOST = 0,
	OBS_URI_STYLE_PATH = 1
};


// 
enum image_process_mode
{
	OBS_image_process_invalid_mode = 0,
	OBS_image_process_cmd = 1,
	OBS_image_process_style = 2
};

// ACL:访问控制列表
enum obs_canned_acl
{
	OBS_CANNED_ACL_PRIVATE = 0,  //used by s3 and obs_ api
	OBS_CANNED_ACL_PUBLIC_READ = 1,  //used by s3 and obs_ api
	OBS_CANNED_ACL_PUBLIC_READ_WRITE = 2,  //used by s3 and obs_ api
	OBS_CANNED_ACL_AUTHENTICATED_READ = 3,  //only used by s3 api
	OBS_CANNED_ACL_BUCKET_OWNER_READ = 4,  //only used by s3 api
	OBS_CANNED_ACL_BUCKET_OWNER_FULL_CONTROL = 5,  //only used by s3 api
	OBS_CANNED_ACL_LOG_DELIVERY_WRITE = 6,  //only used by s3 api
	OBS_CANNED_ACL_PUBLIC_READ_DELIVERED = 7,  //only used by obs_ api
	OBS_CANNED_ACL_PUBLIC_READ_WRITE_DELIVERED = 8,  //only used by obs_ api
	OBS_CANNED_ACL_BUTT = 9
};

// Region：在Region地理上的区域
// 容灾冗余 AZ是Availability Zone的缩写，是指一个故障隔离域
enum obs_az_redundancy
{
	OBS_REDUNDANCY_1AZ = 0,
	OBS_REDUNDANCY_3AZ = 1,  //only used by obs_ api
	OBS_REDUNDANCY_BUTT
};

// 授权域名
enum obs_grant_domain
{
	OBS_GRANT_READ = 0,
	OBS_GRANT_WRITE = 1,
	OBS_GRANT_READ_ACP = 2,
	OBS_GRANT_WRITE_ACP = 3,
	OBS_GRANT_FULL_CONTROL = 4,
	OBS_GRANT_READ_DELIVERED = 5,
	OBS_GRANT_FULL_CONTROL_DELIVERED = 6,
	OBS_GRANT_BUTT
};

enum metadata_action_indicator
{
	OBS_NO_METADATA_ACTION = 0,
	OBS_REPLACE = 1,
	OBS_REPLACE_NEW = 2
};

enum obs_encryption_type
{
	OBS_ENCRYPTION_KMS,
	OBS_ENCRYPTION_SSEC
};

enum obs_storage_class
{
	OBS_STORAGE_CLASS_STANDARD = 0, // STANDARD //
	OBS_STORAGE_CLASS_STANDARD_IA = 1, // STANDARD_IA //
	OBS_STORAGE_CLASS_GLACIER = 2, // GLACIER //
	OBS_STORAGE_CLASS_BUTT
};

enum obs_bucket_type
{
	OBS_BUCKET_OBJECT = 0,   //object bucket
	OBS_BUCKET_PFS = 1    //pfs bucket
};

enum obs_bucket_list_type
{
	OBS_BUCKET_LIST_ALL = 0,   //list all type bucket
	OBS_BUCKET_LIST_OBJECT = 1,   //list object bucket
	OBS_BUCKET_LIST_PFS = 2    //list pfs bucket
};


enum obs_status
{
	OBS_STATUS_OK = 0,
	OBS_STATUS_InitCurlFailed,
	OBS_STATUS_InternalError,
	OBS_STATUS_OutOfMemory,
	OBS_STATUS_Interrupted,
	OBS_STATUS_QueryParamsTooLong,
	OBS_STATUS_FailedToIInitializeRequest,
	OBS_STATUS_MetadataHeadersTooLong,
	OBS_STATUS_BadContentType,
	OBS_STATUS_ContentTypeTooLong,
	OBS_STATUS_BadMd5,
	OBS_STATUS_Md5TooLong,
	OBS_STATUS_BadCacheControl,
	OBS_STATUS_CacheControlTooLong,
	OBS_STATUS_BadContentDispositionFilename,
	OBS_STATUS_ContentDispositionFilenameTooLong,
	OBS_STATUS_BadContentEncoding,
	OBS_STATUS_ContentEncodingTooLong,
	OBS_STATUS_BadIfMatchEtag,
	OBS_STATUS_IfMatchEtagTooLong,
	OBS_STATUS_BadIfNotMatchEtag,
	OBS_STATUS_IfNotMatchEtagTooLong,
	OBS_STATUS_UriTooLong,
	OBS_STATUS_XmlParseFailure,
	OBS_STATUS_UserIdTooLong,
	OBS_STATUS_UserDisplayNameTooLong,
	OBS_STATUS_EmailAddressTooLong,
	OBS_STATUS_GroupUriTooLong,
	OBS_STATUS_PermissionTooLong,
	OBS_STATUS_TooManyGrants,
	OBS_STATUS_BadGrantee,
	OBS_STATUS_BadPermission,
	OBS_STATUS_XmlDocumentTooLarge,
	OBS_STATUS_NameLookupError,
	OBS_STATUS_FailedToConnect,
	OBS_STATUS_ServerFailedVerification,
	OBS_STATUS_ConnectionFailed,
	OBS_STATUS_AbortedByCallback,
	OBS_STATUS_PartialFile,
	OBS_STATUS_InvalidParameter,
	OBS_STATUS_NoToken,
	OBS_STATUS_OpenFileFailed,
	OBS_STATUS_EmptyFile,


	// ==== Errors from the obs_ service

	OBS_STATUS_AccessDenied,
	OBS_STATUS_AccountProblem,
	OBS_STATUS_AmbiguousGrantByEmailAddress,
	OBS_STATUS_BadDigest,
	OBS_STATUS_BucketAlreadyExists,
	OBS_STATUS_BucketAlreadyOwnedByYou,
	OBS_STATUS_BucketNotEmpty,
	OBS_STATUS_CredentialsNotSupported,
	OBS_STATUS_CrossLocationLoggingProhibited,
	OBS_STATUS_EntityTooSmall,
	OBS_STATUS_EntityTooLarge,
	OBS_STATUS_ExpiredToken,
	OBS_STATUS_IllegalVersioningConfigurationException,
	OBS_STATUS_IncompleteBody,
	OBS_STATUS_IncorrectNumberOfFilesInPostRequest,
	OBS_STATUS_InlineDataTooLarge,
	OBS_STATUS_InvalidAccessKeyId,
	OBS_STATUS_InvalidAddressingHeader,
	OBS_STATUS_InvalidArgument,
	OBS_STATUS_InvalidBucketName,
	OBS_STATUS_InvalidKey,
	OBS_STATUS_InvalidBucketState,
	OBS_STATUS_InvalidDigest,
	OBS_STATUS_InvalidLocationConstraint,
	OBS_STATUS_InvalidObjectState,
	OBS_STATUS_InvalidPart,
	OBS_STATUS_InvalidPartOrder,
	OBS_STATUS_InvalidPayer,
	OBS_STATUS_InvalidPolicyDocument,
	OBS_STATUS_InvalidRange,
	OBS_STATUS_InvalidRedirectLocation,
	OBS_STATUS_InvalidRequest,
	OBS_STATUS_InvalidSecurity,
	OBS_STATUS_InvalidSOAPRequest,
	OBS_STATUS_InvalidStorageClass,
	OBS_STATUS_InvalidTargetBucketForLogging,
	OBS_STATUS_InvalidToken,
	OBS_STATUS_InvalidURI,
	OBS_STATUS_MalformedACLError,
	OBS_STATUS_MalformedPolicy,
	OBS_STATUS_MalformedPOSTRequest,
	OBS_STATUS_MalformedXML,
	OBS_STATUS_MaxMessageLengthExceeded,
	OBS_STATUS_MaxPostPreDataLengthExceededError,
	OBS_STATUS_MetadataTooLarge,
	OBS_STATUS_MethodNotAllowed,
	OBS_STATUS_MissingAttachment,
	OBS_STATUS_MissingContentLength,
	OBS_STATUS_MissingRequestBodyError,
	OBS_STATUS_MissingSecurityElement,
	OBS_STATUS_MissingSecurityHeader,
	OBS_STATUS_NoLoggingStatusForKey,
	OBS_STATUS_NoSuchBucket,
	OBS_STATUS_NoSuchKey,
	OBS_STATUS_NoSuchLifecycleConfiguration,
	OBS_STATUS_NoSuchUpload,
	OBS_STATUS_NoSuchVersion,
	OBS_STATUS_NotImplemented,
	OBS_STATUS_NotSignedUp,
	OBS_STATUS_NotSuchBucketPolicy,
	OBS_STATUS_OperationAborted,
	OBS_STATUS_PermanentRedirect,
	OBS_STATUS_PreconditionFailed,
	OBS_STATUS_Redirect,
	OBS_STATUS_RestoreAlreadyInProgress,
	OBS_STATUS_RequestIsNotMultiPartContent,
	OBS_STATUS_RequestTimeout,
	OBS_STATUS_RequestTimeTooSkewed,
	OBS_STATUS_RequestTorrentOfBucketError,
	OBS_STATUS_SignatureDoesNotMatch,
	OBS_STATUS_ServiceUnavailable,
	OBS_STATUS_SlowDown,
	OBS_STATUS_TemporaryRedirect,
	OBS_STATUS_TokenRefreshRequired,
	OBS_STATUS_TooManyBuckets,
	OBS_STATUS_UnexpectedContent,
	OBS_STATUS_UnresolvableGrantByEmailAddress,
	OBS_STATUS_UserKeyMustBeSpecified,
	OBS_STATUS_InsufficientStorageSpace,
	OBS_STATUS_NoSuchWebsiteConfiguration,
	OBS_STATUS_NoSuchBucketPolicy,
	OBS_STATUS_NoSuchCORSConfiguration,
	OBS_STATUS_InArrearOrInsufficientBalance,
	OBS_STATUS_NoSuchTagSet,
	OBS_STATUS_ErrorUnknown,
	//
	// The following are HTTP errors returned by obs_ without enough detail to
	// distinguish any of the above OBS_STATUS_error conditions
	//
	OBS_STATUS_HttpErrorMovedTemporarily,
	OBS_STATUS_HttpErrorBadRequest,
	OBS_STATUS_HttpErrorForbidden,
	OBS_STATUS_HttpErrorNotFound,
	OBS_STATUS_HttpErrorConflict,
	OBS_STATUS_HttpErrorUnknown,

	//
	// posix new add errors
	//
	OBS_STATUS_QuotaTooSmall,

	//
	// obs_-meta errors
	//
	OBS_STATUS_MetadataNameDuplicate,


	OBS_STATUS_BUTT
};

enum obs_storage_class_format
{
	no_need_storage_class,
	default_storage_class,
	storage_class
};

//
struct image_process_configure
{
	image_process_mode _image_process_mode;
	char* cmds_stylename;
};

//
struct obs_get_conditions
{
	uint64 start_byte;
	uint64 byte_count;
	int64 if_modified_since;
	int64 if_not_modified_since;
	char* if_match_etag;
	char* if_not_match_etag;
	image_process_configure* image_process_config;
};

// 
struct grant_domain_config
{
	char* domain;
	obs_grant_domain grant_domain;
};

// 
struct obs_name_value
{
	char* name;
	char* value;
};

// 
struct file_object_config
{
	int auto_split;
	char* file_name;
	void (*print_process_callback)(uint64 remain_bytes, int progress_rate);
};

// 
struct obs_put_properties
{
	char* content_type;
	char* md5;
	char* cache_control;
	char* content_disposition_filename;
	char* content_encoding;
	char* website_redirect_location;
	obs_get_conditions* get_conditions;
	uint64 start_byte;
	uint64 byte_count;
	int64 expires;
	obs_canned_acl canned_acl;
	obs_az_redundancy az_redundancy;
	grant_domain_config* domain_config;
	int meta_data_count;
	obs_name_value* meta_data;
	file_object_config* file_object_config;
	metadata_action_indicator metadata_action;
};


struct server_side_encryption_params
{
	obs_encryption_type encryption_type;
	char* kms_server_side_encryption;
	char* kms_key_id;
	char* ssec_customer_algorithm;
	char* ssec_customer_key;
	char* des_ssec_customer_algorithm;
	char* des_ssec_customer_key;
};


//-*************************return struct******************************************-//
struct obs_bucket_context
{
	char* host_name;
	char* bucket_name;
	obs_protocol protocol;
	obs_uri_style uri_style;
	char* access_key;
	char* secret_access_key;
	char* certificate_info;
	obs_storage_class storage_class;
	char* token;
	char* epid;
	obs_bucket_type bucket_type;
	obs_bucket_list_type bucket_list_type;
};

//
struct obs_http_request_option
{
	int speed_limit;
	int speed_time;
	int connect_time;
	int max_connected_time;
	char* proxy_host;
	char* proxy_auth;
	char* ssl_cipher_list;
	obs_http2_switch http2_switch;
	obs_bbr_switch   bbr_switch;
	obs_auth_switch  auth_switch;
	long buffer_size;
};


// 
struct temp_auth_configure
{
	long long int expires;
	void (*temp_auth_callback)(char* temp_auth_url, char* temp_auth_headers, void* callback_data);
	void* callback_data;
};

struct obs_options
{
	obs_bucket_context bucket_options;
	obs_http_request_option request_options;
	temp_auth_configure* temp_auth;
};

struct obs_cors_conf
{
	char* origin;
	char* requestMethod[100];
	unsigned int rmNumber;
	char* requestHeader[100];
	unsigned int rhNumber;
};

struct obs_response_properties
{
	const char* request_id;

	const char* request_id2;

	const char* content_type;

	uint64 content_length;

	const char* server;

	const char* etag;

	const char* expiration;

	const char* website_redirect_location;

	const char* version_id;

	int64 last_modified;

	int meta_data_count;

	const obs_name_value* meta_data;

	char use_server_side_encryption;

	const char* allow_origin;

	const char* allow_headers;

	const char* max_age;

	const char* allow_methods;

	const char* expose_headers;

	const char* storage_class;

	const char* server_side_encryption;

	const char* kms_key_id;

	const char* customer_algorithm;

	const char* customer_key_md5;

	const char* bucket_location;

	const char* obs_version;

	const char* restore;

	const char* obs_object_type;

	const char* obs_next_append_position;

	const char* obs_head_epid;

	const char* reserved_indicator;
};


struct obs_error_details
{
	const char* message;

	const char* resource;

	const char* further_details;

	int extra_details_count;

	obs_name_value* extra_details;
};


//-**************************response handle function******************************************-//
typedef obs_status(obs_response_properties_callback)(const obs_response_properties* properties,void* callback_data);
typedef int (obs_put_object_data_callback)(int buffer_size, char* buffer, void* callback_data);
typedef int (obs_append_object_data_callback)(int buffer_size, char* buffer, void* callback_data);
typedef int (obs_modify_object_data_callback)(int buffer_size, char* buffer, void* callback_data);
typedef obs_status(obs_get_object_data_callback)(int buffer_size, const char* buffer, void* callback_data);
typedef void (obs_response_complete_callback)(obs_status status, const obs_error_details* error_details, void* callback_data);


// -*************************response handler struct*********************************************- //
struct obs_response_handler
{
	obs_response_properties_callback* properties_callback;
	obs_response_complete_callback* complete_callback;
};


struct obs_put_object_handler
{
	obs_response_handler response_handler;
	obs_put_object_data_callback* put_object_data_callback;
};


// 请求参数
struct request_params
{
	http_request_type httpRequestType;

	obs_bucket_context bucketContext;

	obs_http_request_option request_option;

	temp_auth_configure* temp_auth;

	char* key;

	char* queryParams;

	char* subResource;

	char* copySourceBucketName;

	char* copySourceKey;

	obs_get_conditions* get_conditions;

	obs_cors_conf* corsConf;

	obs_put_properties* put_properties;

	server_side_encryption_params* encryption_params;

	obs_response_properties_callback* properties_callback;

	obs_put_object_data_callback* toObsCallback;

	int64 toObsCallbackTotalSize;

	obs_get_object_data_callback* fromObsCallback;

	obs_response_complete_callback* complete_callback;

	void* callback_data;

	int isCheckCA;

	obs_storage_class_format storageClassFormat;

	obs_use_api use_api;

};

