// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once


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

enum oss_use_api
{
	OSS_USE_API_S3 = 0,
	OSS_USE_API_OSS = 1
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
enum image_process_mode
{
	OSS_image_process_invalid_mode = 0,
	OSS_image_process_cmd = 1,
	OSS_image_process_style = 2
};

// ACL:访问控制列表
enum oss_canned_acl
{
	OSS_CANNED_ACL_PRIVATE = 0,  //used by s3 and oss api
	OSS_CANNED_ACL_PUBLIC_READ = 1,  //used by s3 and oss api
	OSS_CANNED_ACL_PUBLIC_READ_WRITE = 2,  //used by s3 and oss api
	OSS_CANNED_ACL_AUTHENTICATED_READ = 3,  //only used by s3 api
	OSS_CANNED_ACL_BUCKET_OWNER_READ = 4,  //only used by s3 api
	OSS_CANNED_ACL_BUCKET_OWNER_FULL_CONTROL = 5,  //only used by s3 api
	OSS_CANNED_ACL_LOG_DELIVERY_WRITE = 6,  //only used by s3 api
	OSS_CANNED_ACL_PUBLIC_READ_DELIVERED = 7,  //only used by oss api
	OSS_CANNED_ACL_PUBLIC_READ_WRITE_DELIVERED = 8,  //only used by oss api
	OSS_CANNED_ACL_BUTT = 9
};

// Region：在Region地理上的区域
// 容灾冗余 AZ是Availability Zone的缩写，是指一个故障隔离域
enum oss_az_redundancy
{
	OSS_REDUNDANCY_1AZ = 0,
	OSS_REDUNDANCY_3AZ = 1,  //only used by oss api
	OSS_REDUNDANCY_BUTT
};

// 授权域名
enum oss_grant_domain
{
	OSS_GRANT_READ = 0,
	OSS_GRANT_WRITE = 1,
	OSS_GRANT_READ_ACP = 2,
	OSS_GRANT_WRITE_ACP = 3,
	OSS_GRANT_FULL_CONTROL = 4,
	OSS_GRANT_READ_DELIVERED = 5,
	OSS_GRANT_FULL_CONTROL_DELIVERED = 6,
	OSS_GRANT_BUTT
};

enum metadata_action_indicator
{
	OSS_NO_METADATA_ACTION = 0,
	OSS_REPLACE = 1,
	OSS_REPLACE_NEW = 2
};

enum oss_encryption_type
{
	OSS_ENCRYPTION_KMS,
	OSS_ENCRYPTION_SSEC
};

enum oss_storage_class
{
	OSS_STORAGE_CLASS_STANDARD = 0, /* STANDARD */
	OSS_STORAGE_CLASS_STANDARD_IA = 1, /* STANDARD_IA */
	OSS_STORAGE_CLASS_GLACIER = 2, /* GLACIER */
	OSS_STORAGE_CLASS_BUTT
};

enum oss_bucket_type
{
	OSS_BUCKET_OBJECT = 0,   //object bucket
	OSS_BUCKET_PFS = 1    //pfs bucket
};

enum oss_bucket_list_type
{
	OSS_BUCKET_LIST_ALL = 0,   //list all type bucket
	OSS_BUCKET_LIST_OBJECT = 1,   //list object bucket
	OSS_BUCKET_LIST_PFS = 2    //list pfs bucket
};


enum oss_status
{
	OSS_STATUS_OK = 0,
	OSS_STATUS_InitCurlFailed,
	OSS_STATUS_InternalError,
	OSS_STATUS_OutOfMemory,
	OSS_STATUS_Interrupted,
	OSS_STATUS_QueryParamsTooLong,
	OSS_STATUS_FailedToIInitializeRequest,
	OSS_STATUS_MetadataHeadersTooLong,
	OSS_STATUS_BadContentType,
	OSS_STATUS_ContentTypeTooLong,
	OSS_STATUS_BadMd5,
	OSS_STATUS_Md5TooLong,
	OSS_STATUS_BadCacheControl,
	OSS_STATUS_CacheControlTooLong,
	OSS_STATUS_BadContentDispositionFilename,
	OSS_STATUS_ContentDispositionFilenameTooLong,
	OSS_STATUS_BadContentEncoding,
	OSS_STATUS_ContentEncodingTooLong,
	OSS_STATUS_BadIfMatchEtag,
	OSS_STATUS_IfMatchEtagTooLong,
	OSS_STATUS_BadIfNotMatchEtag,
	OSS_STATUS_IfNotMatchEtagTooLong,
	OSS_STATUS_UriTooLong,
	OSS_STATUS_XmlParseFailure,
	OSS_STATUS_UserIdTooLong,
	OSS_STATUS_UserDisplayNameTooLong,
	OSS_STATUS_EmailAddressTooLong,
	OSS_STATUS_GroupUriTooLong,
	OSS_STATUS_PermissionTooLong,
	OSS_STATUS_TooManyGrants,
	OSS_STATUS_BadGrantee,
	OSS_STATUS_BadPermission,
	OSS_STATUS_XmlDocumentTooLarge,
	OSS_STATUS_NameLookupError,
	OSS_STATUS_FailedToConnect,
	OSS_STATUS_ServerFailedVerification,
	OSS_STATUS_ConnectionFailed,
	OSS_STATUS_AbortedByCallback,
	OSS_STATUS_PartialFile,
	OSS_STATUS_InvalidParameter,
	OSS_STATUS_NoToken,
	OSS_STATUS_OpenFileFailed,
	OSS_STATUS_EmptyFile,

	/**
	* Errors from the oss service
	**/
	OSS_STATUS_AccessDenied,
	OSS_STATUS_AccountProblem,
	OSS_STATUS_AmbiguousGrantByEmailAddress,
	OSS_STATUS_BadDigest,
	OSS_STATUS_BucketAlreadyExists,
	OSS_STATUS_BucketAlreadyOwnedByYou,
	OSS_STATUS_BucketNotEmpty,
	OSS_STATUS_CredentialsNotSupported,
	OSS_STATUS_CrossLocationLoggingProhibited,
	OSS_STATUS_EntityTooSmall,
	OSS_STATUS_EntityTooLarge,
	OSS_STATUS_ExpiredToken,
	OSS_STATUS_IllegalVersioningConfigurationException,
	OSS_STATUS_IncompleteBody,
	OSS_STATUS_IncorrectNumberOfFilesInPostRequest,
	OSS_STATUS_InlineDataTooLarge,
	OSS_STATUS_InvalidAccessKeyId,
	OSS_STATUS_InvalidAddressingHeader,
	OSS_STATUS_InvalidArgument,
	OSS_STATUS_InvalidBucketName,
	OSS_STATUS_InvalidKey,
	OSS_STATUS_InvalidBucketState,
	OSS_STATUS_InvalidDigest,
	OSS_STATUS_InvalidLocationConstraint,
	OSS_STATUS_InvalidObjectState,
	OSS_STATUS_InvalidPart,
	OSS_STATUS_InvalidPartOrder,
	OSS_STATUS_InvalidPayer,
	OSS_STATUS_InvalidPolicyDocument,
	OSS_STATUS_InvalidRange,
	OSS_STATUS_InvalidRedirectLocation,
	OSS_STATUS_InvalidRequest,
	OSS_STATUS_InvalidSecurity,
	OSS_STATUS_InvalidSOAPRequest,
	OSS_STATUS_InvalidStorageClass,
	OSS_STATUS_InvalidTargetBucketForLogging,
	OSS_STATUS_InvalidToken,
	OSS_STATUS_InvalidURI,
	OSS_STATUS_MalformedACLError,
	OSS_STATUS_MalformedPolicy,
	OSS_STATUS_MalformedPOSTRequest,
	OSS_STATUS_MalformedXML,
	OSS_STATUS_MaxMessageLengthExceeded,
	OSS_STATUS_MaxPostPreDataLengthExceededError,
	OSS_STATUS_MetadataTooLarge,
	OSS_STATUS_MethodNotAllowed,
	OSS_STATUS_MissingAttachment,
	OSS_STATUS_MissingContentLength,
	OSS_STATUS_MissingRequestBodyError,
	OSS_STATUS_MissingSecurityElement,
	OSS_STATUS_MissingSecurityHeader,
	OSS_STATUS_NoLoggingStatusForKey,
	OSS_STATUS_NoSuchBucket,
	OSS_STATUS_NoSuchKey,
	OSS_STATUS_NoSuchLifecycleConfiguration,
	OSS_STATUS_NoSuchUpload,
	OSS_STATUS_NoSuchVersion,
	OSS_STATUS_NotImplemented,
	OSS_STATUS_NotSignedUp,
	OSS_STATUS_NotSuchBucketPolicy,
	OSS_STATUS_OperationAborted,
	OSS_STATUS_PermanentRedirect,
	OSS_STATUS_PreconditionFailed,
	OSS_STATUS_Redirect,
	OSS_STATUS_RestoreAlreadyInProgress,
	OSS_STATUS_RequestIsNotMultiPartContent,
	OSS_STATUS_RequestTimeout,
	OSS_STATUS_RequestTimeTooSkewed,
	OSS_STATUS_RequestTorrentOfBucketError,
	OSS_STATUS_SignatureDoesNotMatch,
	OSS_STATUS_ServiceUnavailable,
	OSS_STATUS_SlowDown,
	OSS_STATUS_TemporaryRedirect,
	OSS_STATUS_TokenRefreshRequired,
	OSS_STATUS_TooManyBuckets,
	OSS_STATUS_UnexpectedContent,
	OSS_STATUS_UnresolvableGrantByEmailAddress,
	OSS_STATUS_UserKeyMustBeSpecified,
	OSS_STATUS_InsufficientStorageSpace,
	OSS_STATUS_NoSuchWebsiteConfiguration,
	OSS_STATUS_NoSuchBucketPolicy,
	OSS_STATUS_NoSuchCORSConfiguration,
	OSS_STATUS_InArrearOrInsufficientBalance,
	OSS_STATUS_NoSuchTagSet,
	OSS_STATUS_ErrorUnknown,
	/*
	* The following are HTTP errors returned by oss without enough detail to
	* distinguish any of the above OSS_STATUS_error conditions
	*/
	OSS_STATUS_HttpErrorMovedTemporarily,
	OSS_STATUS_HttpErrorBadRequest,
	OSS_STATUS_HttpErrorForbidden,
	OSS_STATUS_HttpErrorNotFound,
	OSS_STATUS_HttpErrorConflict,
	OSS_STATUS_HttpErrorUnknown,

	/*
	* posix new add errors
	*/
	OSS_STATUS_QuotaTooSmall,

	/*
	* oss-meta errors
	*/
	OSS_STATUS_MetadataNameDuplicate,


	OSS_STATUS_BUTT
};

enum oss_storage_class_format
{
	no_need_storage_class,
	default_storage_class,
	storage_class
};

//
struct image_process_configure
{
	image_process_mode image_process_mode;
	char* cmds_stylename;
};

//
struct oss_get_conditions
{
	uint64_t start_byte;
	uint64_t byte_count;
	int64_t if_modified_since;
	int64_t if_not_modified_since;
	char* if_match_etag;
	char* if_not_match_etag;
	image_process_configure* image_process_config;
};

// 
struct grant_domain_config
{
	char* domain;
	oss_grant_domain grant_domain;
};

// 
struct oss_name_value
{
	char* name;
	char* value;
};

// 
struct file_object_config
{
	int auto_split;
	char* file_name;
	void (*print_process_callback)(uint64_t remain_bytes, int progress_rate);
};

// 
struct oss_put_properties
{
	char* content_type;
	char* md5;
	char* cache_control;
	char* content_disposition_filename;
	char* content_encoding;
	char* website_redirect_location;
	oss_get_conditions* get_conditions;
	uint64_t start_byte;
	uint64_t byte_count;
	int64_t expires;
	oss_canned_acl canned_acl;
	oss_az_redundancy az_redundancy;
	grant_domain_config* domain_config;
	int meta_data_count;
	oss_name_value* meta_data;
	file_object_config* file_object_config;
	metadata_action_indicator metadata_action;
};


struct server_side_encryption_params
{
	oss_encryption_type encryption_type;
	char* kms_server_side_encryption;
	char* kms_key_id;
	char* ssec_customer_algorithm;
	char* ssec_customer_key;
	char* des_ssec_customer_algorithm;
	char* des_ssec_customer_key;
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


struct oss_options
{
	oss_bucket_context bucket_options;
	oss_http_request_option request_options;
	temp_auth_configure* temp_auth;
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




//
struct oss_get_conditions
{
	uint64_t start_byte;
	uint64_t byte_count;
	int64_t if_modified_since;
	int64_t if_not_modified_since;
	char* if_match_etag;
	char* if_not_match_etag;
	image_process_configure* image_process_config;
};

struct oss_cors_conf
{
	char* origin;
	char* requestMethod[100];
	unsigned int rmNumber;
	char* requestHeader[100];
	unsigned int rhNumber;
};

struct oss_response_properties
{
	const char* request_id;

	const char* request_id2;

	const char* content_type;

	uint64_t content_length;

	const char* server;

	const char* etag;

	const char* expiration;

	const char* website_redirect_location;

	const char* version_id;

	int64_t last_modified;

	int meta_data_count;

	const oss_name_value* meta_data;

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

	const char* oss_version;

	const char* restore;

	const char* oss_object_type;

	const char* oss_next_append_position;

	const char* oss_head_epid;

	const char* reserved_indicator;
};


struct oss_error_details
{
	const char* message;

	const char* resource;

	const char* further_details;

	int extra_details_count;

	oss_name_value* extra_details;
};


/***************************response handle function*******************************************/
typedef oss_status(oss_response_properties_callback)(const oss_response_properties* properties,void* callback_data);
typedef int (oss_put_object_data_callback)(int buffer_size, char* buffer, void* callback_data);
typedef int (oss_append_object_data_callback)(int buffer_size, char* buffer, void* callback_data);
typedef int (oss_modify_object_data_callback)(int buffer_size, char* buffer, void* callback_data);
typedef oss_status(oss_get_object_data_callback)(int buffer_size, const char* buffer, void* callback_data);
typedef void (oss_response_complete_callback)(oss_status status, const oss_error_details* error_details, void* callback_data);


/**************************response handler struct**********************************************/
struct oss_response_handler
{
	oss_response_properties_callback* properties_callback;
	oss_response_complete_callback* complete_callback;
};


struct oss_put_object_handler
{
	oss_response_handler response_handler;
	oss_put_object_data_callback* put_object_data_callback;
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

// 
struct temp_auth_configure
{
	long long int expires;
	void (*temp_auth_callback)(char* temp_auth_url, char* temp_auth_headers, void* callback_data);
	void* callback_data;
};

// 
struct oss_options
{
	oss_bucket_context bucket_options;
	oss_http_request_option request_options;
	temp_auth_configure* temp_auth;
};


