typedef struct {
	char			remote_host[MAX_PATH];
	DWORD			inact_exp;
	DWORD			hard_exp;
	DWORD			failed;
	DWORD			has_granting;
	char			pszUser[SF_MAX_USERNAME];
	char			pszPassword[SF_MAX_PASSWORD];
	char			appid[PBC_APP_ID_LEN];
	char			s_cookiename[64];
	char			force_reauth[4];
	char			AuthType;
	char			default_url[1024];
	char			timeout_url[1024];
	char			user[PBC_USER_LEN];
	char			appsrvid[PBC_APPSRV_ID_LEN];
	char			appsrv_port[6];
	char			uri[1024];		              // *** size ??
	char			args[4096];                   // ***
	char			method[8];		              // ***
	char			handler;
	DWORD			session_reauth;
	DWORD			logout_action;
	char			Error_Page[MAX_PATH];
	char			Enterprise_Domain[1024];
	char			Login_URI[1024];
    pbc_cookie_data *cookie_data;
	DWORD			Set_Server_Values;
	DWORD			legacy;
	char			*g_certfile;
	char			*s_keyfile;
	char			*s_certfile;
	char			*crypt_keyfile;
	int				serial_s_sent;
	char			server_hostname[MAX_PATH];
	char			instance_id[MAX_INSTANCE_ID+1];
	char			strbuff[MAX_REG_BUFF];  //temporary buffer for libpbc_config_getstring calls

} pubcookie_dir_rec;

#define pid_t int
#define snprintf _snprintf


