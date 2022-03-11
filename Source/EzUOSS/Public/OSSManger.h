// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

// #include "CoreMinimal.h"
#include "OSSType.h"



#define OBS_INIT_WINSOCK         1
#define OBS_INIT_ALL                        (OBS_INIT_WINSOCK)
#define OBS_MAX_DELETE_OBJECT_NUMBER  1000
#define OBS_MAX_DELETE_OBJECT_DOC 1024000

#define ARRAY_LENGTH_4 4
#define ARRAY_LENGTH_16 16
#define ARRAY_LENGTH_32 32
#define ARRAY_LENGTH_50 50
#define ARRAY_LENGTH_64 64
#define ARRAY_LENGTH_512 512
#define ARRAY_LENGTH_1024 1024
#define ARRAY_LENGTH_2014 2014


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

    /**
    * Errors from the obs service
    **/
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
    /*
    * The following are HTTP errors returned by obs without enough detail to
    * distinguish any of the above OBS_STATUS_error conditions
    */
    OBS_STATUS_HttpErrorMovedTemporarily,
    OBS_STATUS_HttpErrorBadRequest,
    OBS_STATUS_HttpErrorForbidden,
    OBS_STATUS_HttpErrorNotFound,
    OBS_STATUS_HttpErrorConflict,
    OBS_STATUS_HttpErrorUnknown,

    /*
    * posix new add errors
    */
    OBS_STATUS_QuotaTooSmall,

    /*
    * obs-meta errors
    */
    OBS_STATUS_MetadataNameDuplicate,


    OBS_STATUS_BUTT
};


enum obs_uri_style
{
    OBS_URI_STYLE_VIRTUALHOST = 0,
    OBS_URI_STYLE_PATH = 1
};

enum obs_protocol
{
    OBS_PROTOCOL_HTTPS = 0,
    OBS_PROTOCOL_HTTP = 1
};

enum obs_storage_class
{
    OBS_STORAGE_CLASS_STANDARD = 0, /* STANDARD */
    OBS_STORAGE_CLASS_STANDARD_IA = 1, /* STANDARD_IA */
    OBS_STORAGE_CLASS_GLACIER = 2, /* GLACIER */
    OBS_STORAGE_CLASS_BUTT
};

enum image_process_mode
{
    obs_image_process_invalid_mode,
    obs_image_process_cmd,
    obs_image_process_style
};

enum obs_canned_acl
{
    OBS_CANNED_ACL_PRIVATE = 0,  //used by s3 and obs api
    OBS_CANNED_ACL_PUBLIC_READ = 1,  //used by s3 and obs api
    OBS_CANNED_ACL_PUBLIC_READ_WRITE = 2,  //used by s3 and obs api
    OBS_CANNED_ACL_AUTHENTICATED_READ = 3,  //only used by s3 api
    OBS_CANNED_ACL_BUCKET_OWNER_READ = 4,  //only used by s3 api
    OBS_CANNED_ACL_BUCKET_OWNER_FULL_CONTROL = 5,  //only used by s3 api
    OBS_CANNED_ACL_LOG_DELIVERY_WRITE = 6,  //only used by s3 api
    OBS_CANNED_ACL_PUBLIC_READ_DELIVERED = 7,  //only used by obs api
    OBS_CANNED_ACL_PUBLIC_READ_WRITE_DELIVERED = 8,  //only used by obs api
    OBS_CANNED_ACL_BUTT
};

enum obs_az_redundancy
{
    OBS_REDUNDANCY_1AZ = 0,
    OBS_REDUNDANCY_3AZ = 1,  //only used by obs api
    OBS_REDUNDANCY_BUTT
};


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


enum obs_grantee_type
{
    OBS_GRANTEE_TYPE_HUAWEI_CUSTOMER_BYEMAIL = 0, // only used by s3 api
    OBS_GRANTEE_TYPE_CANONICAL_USER = 1, // used by both of s3 and obs api
    OBS_GRANTEE_TYPE_ALL_OBS_USERS = 2, // only used by s3 api
    OBS_GRANTEE_TYPE_ALL_USERS = 3, // used by both of s3 and obs api
    OBS_GRANTEE_TYPE_LOG_DELIVERY = 4, // only used by s3 api
    OBS_GRANTEE_TYPE_BUTT
};

enum obs_permission
{
    OBS_PERMISSION_READ = 0,
    OBS_PERMISSION_WRITE = 1,
    OBS_PERMISSION_READ_ACP = 2,
    OBS_PERMISSION_WRITE_ACP = 3,
    OBS_PERMISSION_FULL_CONTROL = 4,
    OBS_PERMISSION_BUTT
};

enum obs_tier
{
    OBS_TIER_NULL = 0,
    OBS_TIER_STANDARD,
    OBS_TIER_EXPEDITED,
    OBS_TIER_BULK,
};

enum part_upload_status
{
    UPLOAD_NOTSTART,
    UPLOADING,
    UPLOAD_FAILED,
    UPLOAD_SUCCESS,
    STATUS_BUTT
};

enum obs_smn_filter_rule_enum
{
    OBS_SMN_FILTER_NULL = 0,
    OBS_SMN_FILTER_PREFIX,
    OBS_SMN_FILTER_SUFFIX
};

enum obs_smn_event_enum
{
    SMN_EVENT_NULL = 0,
    SMN_EVENT_OBJECT_CREATED_ALL,
    SMN_EVENT_OBJECT_CREATED_PUT,
    SMN_EVENT_OBJECT_CREATED_POST,
    SMN_EVENT_OBJECT_CREATED_COPY,
    SMN_EVENT_OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD,
    SMN_EVENT_OBJECT_REMOVED_ALL,
    SMN_EVENT_OBJECT_REMOVED_DELETE,
    SMN_EVENT_OBJECT_REMOVED_DELETE_MARKER_CREATED,
    SMN_EVENT_REDUCED_REDUNDANCY_LOST_OBJECT
};

enum download_status
{
    DOWNLOAD_NOTSTART,
    DOWNLOADING,
    DOWNLOAD_FAILED,
    DOWNLOAD_SUCCESS,
    COMBINE_SUCCESS,
    DOWN_STATUS_BUTT
};

enum obs_use_api
{
    OBS_USE_API_S3 = 0,
    OBS_USE_API_OBS = 1
};

enum obs_certificate_conf
{
    OBS_NO_CERTIFICATE,
    OBS_DEFAULT_CERTIFICATE,
    OBS_DEFINED_CERTIFICATE
};

enum obs_encryption_type
{
    OBS_ENCRYPTION_KMS,
    OBS_ENCRYPTION_SSEC
};

enum obs_object_delivered
{
    OBJECT_DELIVERED_TRUE = 0,				// Default value is true.
    OBJECT_DELIVERED_FALSE = 1
};

enum obs_bucket_delivered
{
    BUCKET_DELIVERED_FALSE = 0,				// Default value is false.
    BUCKET_DELIVERED_TRUE = 1
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


// in general.c ======= start
#define CERTIFICATE_SIZE 2048
#define CERTIFICATE_NAME "/client.pem"
#define PATH_LENGTH 1024

char g_ca_info[CERTIFICATE_SIZE] = { 0 };
obs_protocol g_protocol = OBS_PROTOCOL_HTTPS;
// in general.c ======= end


// struct obs_request_context obs_request_context;

struct tag_obs_create_bucket_params
{
    obs_canned_acl    canned_acl;
    obs_az_redundancy az_redundancy;
    const char* location_constraint;
};


struct obs_acl_grant
{
    obs_grantee_type grantee_type;
    union
    {
        struct
        {
            char email_address[OBS_MAX_GRANTEE_EMAIL_ADDRESS_SIZE];
        } huawei_customer_by_email; // only used by s3 api
        struct
        {
            char id[OBS_MAX_GRANTEE_USER_ID_SIZE];
            char display_name[OBS_MAX_GRANTEE_DISPLAY_NAME_SIZE]; // only used by s3 api
        } canonical_user;
    } grantee;
    obs_permission permission;
    obs_bucket_delivered bucket_delivered; // only used by obs api
};

struct obs_acl_group
{
    int acl_grant_count;
    obs_acl_grant* acl_grants;
};

struct obs_object_info
{
    char* key;
    char* version_id;
};

struct obs_delete_object_info
{
    unsigned int keys_number;
    int quiet;
};

struct manager_acl_info
{
    obs_object_info object_info;
    char* owner_id;
    char* owner_display_name;
    int* acl_grant_count_return;
    obs_object_delivered object_delivered; // only used by obs api
    obs_acl_grant* acl_grants;
};


struct obs_upload_part_info
{
    unsigned int part_number;
    char* upload_id;
};

struct obs_complete_upload_Info
{
    unsigned int part_number;
    char* etag;
};

struct list_part_info
{
    char* upload_id;
    unsigned int max_parts;
    unsigned int part_number_marker;
};


struct obs_name_value
{
    char* name;
    char* value;
};

struct obs_error_details
{
    const char* message;

    const char* resource;

    const char* further_details;

    int extra_details_count;

    obs_name_value* extra_details;
};

struct obs_response_properties
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

struct obs_list_objects_content
{
    const char* key;
    int64_t last_modified;
    const char* etag;
    uint64_t size;
    const char* owner_id;
    const char* owner_display_name;
    const char* storage_class;
    const char* type;
};

struct obs_version
{

    const char* key;
    const char* version_id;
    const char* is_latest;
    int64_t last_modified;
    const char* etag;
    uint64_t size;
    const char* owner_id;
    const char* owner_display_name;
    const char* storage_class;
    const char* is_delete;
};

struct obs_list_versions
{
    const char* bucket_name;
    const char* prefix;
    const char* key_marker;
    const char* delimiter;
    const char* max_keys;
    obs_version* versions;
    int versions_count;
    const char** common_prefixes;
    int common_prefixes_count;
};


struct obs_list_parts
{
    unsigned int part_number;
    int64_t last_modified;
    const char* etag;
    uint64_t size;
    const char* storage_class;
};

struct obs_list_multipart_upload
{
    const char* key;
    const char* upload_id;
    const char* initiator_id;
    const char* initiator_display_name;
    const char* owner_id;
    const char* owner_display_name;
    const char* storage_class;
    int64_t    initiated;
};

struct obs_lifecycle_transtion
{
    const char* date;
    const char* days;
    obs_storage_class storage_class;
};

struct obs_lifecycle_noncurrent_transtion
{
    const char* noncurrent_version_days;
    obs_storage_class storage_class;
};

struct obs_lifecycle_conf
{
    const char* date;
    const char* days;
    const char* id;
    const char* prefix;
    const char* status;
    const char* noncurrent_version_days;
    obs_lifecycle_transtion* transition;
    unsigned int transition_num;
    obs_lifecycle_noncurrent_transtion* noncurrent_version_transition;
    unsigned int noncurrent_version_transition_num;

};

struct obs_bucket_cors_conf
{
    const char* id;
    const char** allowed_method;
    unsigned int allowed_method_number;
    const char** allowed_origin;
    unsigned int allowed_origin_number;
    const char** allowed_header;
    unsigned int allowed_header_number;
    const char* max_age_seconds;
    const char** expose_header;
    unsigned int expose_header_number;
};

struct obs_uploaded_parts_total_info
{
    int  is_truncated;
    unsigned int nextpart_number_marker;
    char* initiator_id;
    char* initiator_display_name;
    char* owner_id;
    char* owner_display_name;
    char* sorage_class;
    int  parts_count;
};

struct obs_copy_destination_object_info
{
    char* destination_bucket;
    char* destination_key;
    char* version_id;
    int64_t* last_modified_return;
    int etag_return_size;
    char* etag_return;
};

struct _obs_upload_file_configuration
{
    char* upload_file;
    uint64_t part_size;
    char* check_point_file;
    int enable_check_point;
    int task_num;
};

struct _obs_download_file_configuration
{
    char* downLoad_file;
    uint64_t part_size;
    char* check_point_file;
    int enable_check_point;
    int task_num;
};

struct _obs_upload_file_part_info
{
    int part_num;
    uint64_t start_byte;
    uint64_t part_size;
    part_upload_status status_return;
};

struct _obs_download_file_part_info
{
    int part_num;
    uint64_t start_byte;
    uint64_t part_size;
    download_status status_return;
};

struct obs_set_bucket_redirect_all_conf
{
    const char* host_name;
    const char* protocol;
};

struct obs_delete_objects
{
    const char* key;
    const char* code;
    const char* message;
    const char* delete_marker;
    const char* delete_marker_version_id;
};

struct bucket_website_routingrule
{
    const char* key_prefix_equals;
    const char* http_errorcode_returned_equals;
    const char* protocol;
    const char* host_name;
    const char* replace_key_prefix_with;
    const char* replace_key_with;
    const char* http_redirect_code;
};

struct obs_set_bucket_website_conf
{
    const char* suffix;
    const char* key;
    bucket_website_routingrule* routingrule_info;
    int routingrule_count;
};

struct obs_smn_filter_rule
{
    obs_smn_filter_rule_enum name;
    char* value;
};


struct obs_smn_topic_configuration
{
    char* topic;
    char* id;
    obs_smn_filter_rule* filter_rule;
    unsigned int filter_rule_num;
    obs_smn_event_enum* event;
    unsigned int event_num;
};


struct obs_smn_notification_configuration
{
    obs_smn_topic_configuration* topic_conf;
    unsigned int topic_conf_num;
};


/***************************response handle function*******************************************/

typedef obs_status (obs_response_properties_callback)(const obs_response_properties* properties,
    void* callback_data);

typedef obs_status(obs_list_service_callback)(const char* owner_id,
    const char* owner_display_name,
    const char* bucket_name,
    int64_t creation_date_seconds,
    void* callback_data);

typedef void (obs_response_complete_callback)(obs_status status,
    const obs_error_details* error_details, void* callback_data);

typedef int (obs_put_object_data_callback)(int buffer_size, char* buffer,
    void* callback_data);


typedef int (obs_append_object_data_callback)(int buffer_size, char* buffer,
    void* callback_data);
typedef int(obs_modify_object_data_callback)(int buffer_size, char* buffer,
    void* callback_data);

typedef obs_status (obs_get_object_data_callback)(int buffer_size, const char* buffer,
    void* callback_data);


typedef obs_status (obs_list_service_obs_callback)(const char* owner_id,
    const char* bucket_name,
    int64_t creation_date_seconds,
    const char* location,
    void* callback_data);

typedef obs_status (obs_get_bucket_storage_policy)(const char* storage_class_policy,
    void* callback_data);

typedef obs_status (obs_get_bucket_websiteconf_callback) (const char* hostname, const char* protocol,
    const char* suffix, const char* key, const bucket_website_routingrule* routingrule,
    int webdatacount, void* callback_data);


typedef int (obs_upload_data_callback)(int buffer_size, char* buffer, void* callback_data);

typedef obs_status (obs_complete_multi_part_upload_callback)(const char* location,
    const char* bucket,
    const char* key,
    const char* etag,
    void* callback_data);

typedef obs_status (obs_list_parts_callback_ex)(obs_uploaded_parts_total_info* uploaded_parts,
    obs_list_parts* parts, void* callback_data);
typedef void (obs_upload_file_callback)(obs_status status, char* result_message, int part_count_return,
    _obs_upload_file_part_info* upload_info_list, void* callback_data);

typedef obs_status (obs_list_objects_callback)(int is_truncated, const char* next_marker,
    int contents_count, const obs_list_objects_content* contents,
    int common_prefixes_count, const char** common_prefixes,
    void* callback_data);


typedef obs_status (obs_list_multipart_uploads_callback)(int is_truncated, const char* next_marker,
    const char* next_uploadId_marker, int uploads_count,
    const obs_list_multipart_upload* uploads, int common_prefixes_count,
    const char** common_prefixes, void* callback_data);

typedef obs_status (obs_list_versions_callback)(int is_truncated, const char* next_key_marker,
    const char* next_versionid_marker, const obs_list_versions* versions,
    void* callback_data);

typedef obs_status (get_lifecycle_configuration_callback) (obs_lifecycle_conf* bucket_lifecycle_conf,
    unsigned int blcc_number, void* callback_data);

typedef void (obs_download_file_callback)(obs_status status, char* result_message,
    int part_count_return, _obs_download_file_part_info* download_info_list,
    void* callback_data);

typedef obs_status (get_cors_configuration_callback)(obs_bucket_cors_conf* bucket_cors_conf,
    unsigned int bcc_number, void* callback_data);

typedef obs_status (obs_delete_object_data_callback)(int contents_count,
    obs_delete_objects* contents, void* callback_data);

typedef obs_status (obs_smn_callback)(obs_smn_notification_configuration* notification_conf,
    void* callback_data);

/**************************response handler struct**********************************************/

struct obs_response_handler
{
    obs_response_properties_callback* properties_callback;
    obs_response_complete_callback* complete_callback;
};

struct obs_list_objects_handler
{
    obs_response_handler response_handler;
    obs_list_objects_callback* list_Objects_callback;
};


struct obs_list_versions_handler
{
    obs_response_handler response_handler;
    obs_list_versions_callback* list_versions_callback;
};

struct obs_list_multipart_uploads_handler
{
    obs_response_handler response_handler;
    obs_list_multipart_uploads_callback* list_mulpu_callback;
};

struct obs_put_object_handler
{
    obs_response_handler response_handler;
    obs_put_object_data_callback* put_object_data_callback;
};
struct obs_append_object_handler
{
    obs_response_handler response_handler;
    obs_append_object_data_callback* append_object_data_callback;
};

struct obs_modify_object_handler
{
    obs_response_handler response_handler;
    obs_modify_object_data_callback* modify_object_data_callback;
};


struct obs_get_object_handler
{
    obs_response_handler response_handler;
    obs_get_object_data_callback* get_object_data_callback;
};

struct obs_lifecycle_handler
{
    obs_response_handler response_handler;
    get_lifecycle_configuration_callback* get_lifecycle_callback;
};

struct obs_cors_handler
{
    obs_response_handler response_handler;
    get_cors_configuration_callback* get_cors_callback;
};


struct obs_upload_handler
{
    obs_response_handler response_handler;
    obs_upload_data_callback* upload_data_callback;
};

struct obs_complete_multi_part_upload_handler
{
    obs_response_handler response_handler;
    obs_complete_multi_part_upload_callback* complete_multipart_upload_callback;
};

struct obs_list_parts_handler
{
    obs_response_handler response_handler;
    obs_list_parts_callback_ex* list_parts_callback_ex;
};

struct obs_upload_file_response_handler
{
    obs_response_handler response_handler;
    obs_upload_file_callback* upload_file_callback;
};
struct __obs_download_file_response_handler
{
    obs_response_handler response_handler;
    obs_download_file_callback* download_file_callback;
};

struct obs_delete_object_handler
{
    obs_response_handler response_handler;
    obs_delete_object_data_callback* delete_object_data_callback;
};

struct obs_get_bucket_websiteconf_handler
{
    obs_response_handler response_handler;
    obs_get_bucket_websiteconf_callback* get_bucket_website_conf_callback;
};

struct obs_smn_handler
{
    obs_response_handler response_handler;
    obs_smn_callback* get_smn_callback_func;
};


/**************************return struct*******************************************/
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

enum obs_auth_switch
{
    OBS_NEGOTIATION_TYPE = 0,
    OBS_OBS_TYPE = 1,
    OBS_S3_TYPE = 2
};

enum metadata_action_indicator
{
    OBS_NO_METADATA_ACTION = 0,
    OBS_REPLACE = 1,
    OBS_REPLACE_NEW = 2
};

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

struct image_process_configure
{
    image_process_mode image_process_mode;
    char* cmds_stylename;
};

struct obs_get_conditions
{
    uint64_t start_byte;
    uint64_t byte_count;
    int64_t if_modified_since;
    int64_t if_not_modified_since;
    char* if_match_etag;
    char* if_not_match_etag;
    image_process_configure* image_process_config;
};

struct file_object_config
{
    int auto_split;
    char* file_name;
    void (*print_process_callback)(uint64_t remain_bytes, int progress_rate);
};

struct grant_domain_config
{
    char* domain;
    obs_grant_domain grant_domain;
};



struct obs_put_properties
{
    char* content_type;
    char* md5;
    char* cache_control;
    char* content_disposition_filename;
    char* content_encoding;
    char* website_redirect_location;
    obs_get_conditions* get_conditions;
    uint64_t start_byte;
    uint64_t byte_count;
    int64_t expires;
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


typedef obs_status(obs_get_bucket_storage_policy_callback)(const char* storage_class_policy,
    void* callback_data);

struct obs_get_bucket_storage_class_handler
{
    obs_response_handler response_handler;
    obs_get_bucket_storage_policy_callback* get_bucket_sorage_class_callback;
};

typedef obs_status(obs_get_bucket_tagging_callback)(int tagging_count,
    obs_name_value* tagging_list, void* callback_data);

struct obs_get_bucket_tagging_handler
{
    obs_response_handler response_handler;
    obs_get_bucket_tagging_callback* get_bucket_tagging_callback;
};


struct obs_list_service_handler
{
    obs_response_handler response_handler;
    obs_list_service_callback* listServiceCallback;
};


 struct obs_list_service_obs_handler
 {
     obs_response_handler response_handler;
     obs_list_service_obs_callback* listServiceCallback;
 };



struct bucket_logging_message
{
    char* target_bucket;
    int  target_bucket_size;
    char* target_prefix;
    int  target_prefix_size;
    obs_acl_grant* acl_grants;
    int* acl_grant_count;
    char* agency;
    int  agency_size;
};


/****************************init handle *****************************************************/
obs_status obs_initialize(int win32_flags);

void obs_deinitialize();

void init_obs_options(obs_options* options);

/*************************************bucket handle**************************************/

void list_bucket(const obs_options* options, obs_list_service_handler* handler,
	void* callback_data);