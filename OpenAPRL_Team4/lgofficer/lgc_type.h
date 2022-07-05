#ifndef LGC_TYPE
#define LGC_TYPE

#define MAX_PAYLOAD_LEN		256
#define MAX_USR_ID_LENGTH	20
#define MAX_USR_PW_LENGTH	20
#define MAX_USR_OTP_LENGTH	6
#define MIN_USR_ID_LENGTH   8
#define MIN_USR_PW_LENGTH   8

#define FILE_ALERT_LOG		"alert.log"
#define FILE_ALERT_LOG_ENCRYPTED "alert_enc.log"
#define FILE_ALERT_LOG_DECRYPTED "alert_dec.log"

typedef enum
{
	LGC_ST_START_IDX = 0,
	LGC_ST_INITIALIZING = 0,
	LGC_ST_CONNECTING,
	LGC_ST_CONNECTION_DONE,
	LGC_ST_PENDING,
	LGC_ST_AUTHENTICATING,
	LGC_ST_SVC_READY,
	LGC_ST_SVC_RUNNING,
	LGC_ST_DISCONNECT,
	LGC_ST_DISCONNECTED,
	LGC_ST_DESTROY,
	LGC_ST_MAX,
} lgc_state_e;

typedef enum
{
	LGC_SUCCESS,
	LGC_FAILURE,
} res_e;

typedef enum
{
	LGC_CMD_LOGIN = 1,
	LGC_CMD_LIC_QUERY = 2,
} lgc_cmd_e;

typedef enum
{
	SK_EVT_RECV_HEADER,
	SK_EVT_RECV_PAYLOAD,
	SK_EVT_RECV_DISCONNECTED,
} sk_evt_e;

typedef enum
{
	INFO_T_END,
	INFO_T_FRAME,
}info_type_e;

struct packet_payload
{
	int cmd_id; /* lgc_cmd_e */
	int payload_len; /* length of command */
	char payload[MAX_PAYLOAD_LEN];
};

enum class Mode { mNone, mLive_Video, mPlayback_Video, mImage_File };
enum class VideoResolution { rNone, r640X480, r1280X720 };
enum class VideoSaveMode { vNone, vNoSave, vSave, vSaveWithNoALPR };
enum class ResponseMode { ReadingHeader, ReadingMsg };

struct demoMode_s {
	Mode vMode;
	VideoSaveMode vSaveMode;
	VideoResolution vRes;
};

enum class AlertT { mGen, mViolation, mNet };

#endif