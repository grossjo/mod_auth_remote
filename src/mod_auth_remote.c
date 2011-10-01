/*
 * mod_auth_remote - Remote authentication module for apache httpd 2.2
 *
 * saju.pillai@gmail.com
 * heavily modified by athir@nuaimi.com
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include <apr_strings.h>
#include <apr_uri.h>
#include <apr_base64.h>
#include <apr_md5.h>
#include <apr_time.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <ap_provider.h>
#include <mod_auth.h>

#define NOT_CONFIGURED  -42

#define TWENTY_MINS     1200          //in seconds
#define FOUR_HOURS      14400         //in seconds

#define DEFAULT_TIMEOUT 5000000       //5 sec - in microseconds


// data & data structures

typedef struct {
  // apr_pool_t *module_pool;         /* pool that has lifespan that matches module */

  const char *remote_server;       /* hostname/ip for the remote server */
  const char *remote_path;         /* the protected resource on the remote server */
  int remote_port;                 /* the remote port of the authenticating server */

  apr_hash_t *sessions;            /* hash of logged in users along wit their timeout */
  int session_life;                /* the duration for which the session should live */

  apr_time_t cleanup_interval;     /* how often we need to clean hash of user sessions */
  apr_time_t last_cleanup;         /* time we last cleaned old strings in session hash */

} auth_remote_config_rec;

module AP_MODULE_DECLARE_DATA auth_remote_module;

//config

static void *create_auth_remote_server_config(apr_pool_t *pool, server_rec *server) 
{
  //allocate config structure
  auth_remote_config_rec *conf = apr_palloc(pool, sizeof(auth_remote_config_rec));

  // conf->module_pool= pool;                     //used during session cleanup

  conf->remote_port = NOT_CONFIGURED;
  conf->remote_server = NULL;
  conf->remote_path = NULL;

  conf->sessions = apr_hash_make( pool);
  conf->session_life = TWENTY_MINS;         //default to 20 min timeout for sessions

  conf->last_cleanup = apr_time_sec(apr_time_now());
  conf->cleanup_interval = FOUR_HOURS;      // default to 4 hours

  return conf;
}

static const char *auth_remote_parse_url( cmd_parms *cmd, void *config, const char *arg)
{
  //dir config
  // auth_remote_config_rec *conf = config;
  auth_remote_config_rec *conf = ap_get_module_config( cmd->server->module_config, &auth_remote_module) ;

  apr_uri_t uri;
  apr_status_t rv = apr_uri_parse(cmd->pool, arg, &uri);
  if (rv != APR_SUCCESS )
    return "AuthRemoteURL should an URL or path to the authenticating server";
  
  if (!uri.scheme) {
    conf->remote_path = arg;
  } 
  else {    
    if (strncmp(uri.scheme , "http", 4))
      return "AuthRemoteURL must be a http uri";
    
    conf->remote_server = uri.hostname;
    conf->remote_port = uri.port ? uri.port : 80;
    if (!uri.path)
      conf->remote_path = "/";
    else {
      conf->remote_path = uri.path;
      if (uri.query) 
        conf->remote_path = apr_pstrcat(cmd->pool, conf->remote_path, "?", uri.query, NULL);
      if (uri.fragment)
        conf->remote_path = apr_pstrcat(cmd->pool, conf->remote_path, "#", uri.fragment, NULL);
    }
  }
    
  ap_log_error( APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "remote URL set to %s//%s:%d", conf->remote_server, 
                conf->remote_path, conf->remote_port);

  return NULL;
}

static const char *auth_remote_parse_timeout(cmd_parms *cmd, void *config, const char *arg)
{
  // auth_remote_config_rec *conf = config;
  auth_remote_config_rec *conf = ap_get_module_config( cmd->server->module_config, &auth_remote_module) ;

  apr_time_t timeout;
  timeout= atoi( arg);
  if (timeout == 0)
    return "AuthSessionTimeout must be a number (>0)";

  //set new timeout
  conf->session_life = timeout;
  ap_log_error( APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "session timeout set to %" APR_TIME_T_FMT " seconds", timeout);

  return NULL;
}

static const char *auth_remote_parse_cleanup( cmd_parms *cmd, void *config, const char *arg)
{
  // auth_remote_config_rec *conf = config;
  auth_remote_config_rec *conf = ap_get_module_config( cmd->server->module_config, &auth_remote_module) ;

  //how many seconds before need to cleanup user session hash
  conf->cleanup_interval= atoi(arg);
  if (conf->cleanup_interval == 0)
    return "AuthRemoteSessionCleanupInterval must be a number (> 0)";
    
  ap_log_error( APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "session cleanup interval set to %" APR_TIME_T_FMT " seconds", 
                conf->cleanup_interval);
    
  return NULL;
}

static const command_rec auth_remote_cmds[] = 
{
  /* accepts a full url, superceedes AuthRemotePort and AuthRemoteServer */
  AP_INIT_TAKE1("AuthRemoteURL", auth_remote_parse_url, NULL, OR_AUTHCFG,
                "remote server path or full url to authenticate against"),

  AP_INIT_TAKE1("AuthRemoteSessionTimeout", auth_remote_parse_timeout, NULL, OR_AUTHCFG,
                "how long user stays logged in - in seconds"),

  AP_INIT_TAKE1("AuthRemoteSessionCleanupInterval", auth_remote_parse_cleanup, NULL, OR_AUTHCFG, 
                "how ofter (in seconds) user session hash should be cleaned up"),

  {NULL}
};


static authn_status do_remote_auth(request_rec *r, const char *user, const char *passwd, 
                                   auth_remote_config_rec *conf)
{  
  /* we were not configured */
  if (conf->remote_port == NOT_CONFIGURED) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "remote_auth was not configured");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  apr_status_t rv;
  apr_socket_t *rsock;

  rv = apr_socket_create( &rsock, APR_INET, SOCK_STREAM, APR_PROTO_TCP, r->pool);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to create socket");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  rv = apr_socket_timeout_set(rsock, DEFAULT_TIMEOUT);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to set timeout on socket");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  apr_sockaddr_t *addr;
  rv = apr_sockaddr_info_get( &addr, conf->remote_server, APR_INET, (apr_port_t)conf->remote_port, 
                             0, r->pool);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to setup sockaddr for %s:%d", 
                  conf->remote_server, conf->remote_port);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  /* the base64 encoded Authorization header */
  apr_size_t rz;
  char *user_pass, *b64_user_pass, *req;
  unsigned char *rbuf;

  user_pass = apr_pstrcat( r->pool, user, ":", passwd, NULL);
  b64_user_pass = apr_palloc( r->pool, apr_base64_encode_len(strlen(user_pass)) + 1);
  apr_base64_encode(b64_user_pass, user_pass, strlen(user_pass));

  /* the http request for the remote end */
  req = apr_psprintf(r->pool, "HEAD %s HTTP/1.0%sAuthorization: Basic %s%s%s", conf->remote_path, 
                     CRLF, b64_user_pass, CRLF, CRLF);

  /* send the request to the remote server */
  rv = apr_socket_connect(rsock, addr);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "failed to connect to remote server %s:%d", 
                  conf->remote_server, conf->remote_port);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  rz = strlen(req);
  rv = apr_socket_send(rsock, (const char *)req, &rz);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "write() to remote server failed");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /* read the response from the remote end, 20 bytes should be enough parse the remote server's intent */
  rbuf = apr_palloc(r->pool, rz);
  rz = 20;
  rv = apr_socket_recv(rsock, (char *)rbuf, &rz);
  apr_socket_close(rsock);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "recv() from remote server failed");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  if (rz < 13) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "non HTTP reply from remote server");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
 
  //see if got 200 response
  if (apr_toupper(rbuf[0]) == 'H' && apr_toupper(rbuf[1]) == 'T' && apr_toupper(rbuf[2]) == 'T' 
      && apr_toupper(rbuf[3]) == 'P') {
    if (rbuf[8] == ' ' && rbuf[9] == '2') {
      //TODO: want to get account flags here:  subscription_expired & over_bandwidth
      //      stores in notes table for other modules to do a redirect if required

      return AUTH_GRANTED;      
    }
    else {
      ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "unexpected return code from AUTH server");
    }
  }
  
  //possible negative return codes
  //401 - unauthorized - this is all we should really see
  //403 - forbidden
  //404 - not found

  return AUTH_DENIED;
}

static int cleanup_old_sessions( auth_remote_config_rec *conf, request_rec *r)
{

  unsigned int count;
  count= apr_hash_count( conf->sessions);
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "currently %d sessions in hash (active and timedout)", count);
   
  ap_log_rerror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, r, "cleaning up expired sessions");
  //hash only grows when new users are seen
  //as each user key is 40 bytes + 4 bytes for timeout, 
  //server should not run out of memory any time soon (1K users = 44K memory)
  //as a result, will not do cleanup

  return 1;
}

static authn_status check_authn(request_rec *r, const char *user, const char *passwd)
{
  // auth_remote_config_rec *conf = ap_get_module_config(r->per_dir_config, &auth_remote_module);
  auth_remote_config_rec *conf = ap_get_module_config(r->server->module_config, &auth_remote_module);

  ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, "received AUTH request for user %s", user);

  authn_status remote_status = AUTH_DENIED;     //default to denied
  apr_time_t now = apr_time_sec(apr_time_now());

  // unsigned int count= apr_hash_count( conf->sessions);

  //before we check user credentials, see if we need to cleanup hash of session
  if (now > (conf->last_cleanup + conf->cleanup_interval)) {
    cleanup_old_sessions( conf, r);
    conf->last_cleanup= now;
  }

  //ok now validate user credentials
  apr_time_t *session_start;
  session_start= (apr_time_t *) apr_hash_get( conf->sessions, user, APR_HASH_KEY_STRING);
  
  //if NULL, need to fall below to do_remote_auth
  if (session_start) {
    //get current time   
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "found session for user %s", user);
    if ((now - (*session_start)) < conf->session_life) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "session valid for user %s", user);
      return AUTH_GRANTED;        
    }

    //else
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "session expired for %s", user);
  }
  else {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "no session found for user %s", user);
  }    
  //need to validate user & password with remote server 
  remote_status = do_remote_auth(r, user, passwd, conf);
  if (remote_status == AUTH_GRANTED) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, "backend authorized user %s", user);

    if (session_start == NULL) {
      // session_start= (apr_time_t *) apr_palloc( r->server->process->pool, sizeof(now));
      apr_pool_t *pool= apr_hash_pool_get(conf->sessions);
      char *key= apr_pstrdup( pool, user);
      session_start= (apr_time_t *) apr_palloc( pool, sizeof(now));
      *session_start= now;
      apr_hash_set( conf->sessions, key, APR_HASH_KEY_STRING, session_start);
      ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, "created new session for user %s", user);
;
    }
    else {
      //reset session start time to now
      *session_start= now;        
      ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, "updated session for user %s", user);
    } 
  }
      
  return remote_status;
}

static const authn_provider auth_remote_provider =
{
  &check_authn,
  NULL
};

static void register_hooks(apr_pool_t *p)
{
  ap_register_provider(p, AUTHN_PROVIDER_GROUP, "remote", "0", &auth_remote_provider);
}

module AP_MODULE_DECLARE_DATA auth_remote_module = 
  {
    STANDARD20_MODULE_STUFF,
    NULL,                                 //per dir config
    NULL,
    create_auth_remote_server_config,     //per srv config
    NULL,
    auth_remote_cmds,
    register_hooks
  };
