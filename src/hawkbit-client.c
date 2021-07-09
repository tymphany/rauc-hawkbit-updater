/**
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2018-2020 Prevas A/S (www.prevas.com)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @file hawkbit-client.c
 * @author Lasse Mikkelsen <lkmi@prevas.dk>
 * @date 19 Sep 2018
 * @brief Hawkbit client
 *
 * Implementation of the hawkBit DDI API.
 *
 * @see https://github.com/rauc/rauc-hawkbit
 * @see https://www.eclipse.org/hawkbit/apis/ddi_api/
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <curl/curl.h>
#include <glib.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <json-glib/json-glib.h>
#include <libgen.h>
#include <bits/types/struct_tm.h>
#include <gio/gio.h>
#include <syslog.h>

#include "config-file.h"
#include "json-helper.h"
#ifdef WITH_SYSTEMD
#include "sd-helper.h"
#endif

#include <sys/time.h>
//#include <stdio.h>

#include "hawkbit-client.h"

#define MAX_RETRY_ON_ZERO_RESPONSE (3)
#define FILE_DOWNLOAD_CHECKPOINTS_NUM         (100)
#define FILE_DOWNLOAD_DONE_ALL_IN_ALL_PERCENT (75)
#define FILE_DOWNLOAD_CHECKPOINTS_PERCENT_STEP           (100 / FILE_DOWNLOAD_CHECKPOINTS_NUM)
#define FILE_DOWNLOAD_ALL_IN_ALL_PERCENT_PER_CHECKPOINT (FILE_DOWNLOAD_DONE_ALL_IN_ALL_PERCENT / FILE_DOWNLOAD_CHECKPOINTS_NUM)
#define MAX_TIME (0xFFFFFFFF)
#define WAIT_DOWNLOAD_FINISH_MAX_TIME (60 * 60 * 2)
#define CHECK_INTERVALS_SEC (30)
#define MIN_INTERVAL_BETWEEN_CHECKS_SEC (60 * 60 * 24)
#define APPARENTLY_CRASHED_LAST_ATTEMPT (60 * 60 * 2)

//#define PRINT_REQUESTS
//#define SKIP_DOWNLOAD

#define REMOVE_BUNLDE_AFTER_OTA
#define REMOVE_TEMP_FILES_AFTER_OTA
#define REPORT_FINAL_STATE

typedef enum {
    US_INIT        = 0,
    US_DOWNLOAD    = 1,
    US_DONE_REBOOT = 2,
    US_DONE_FAILED = 3,
} UPGRADE_STATE;

volatile UPGRADE_STATE upgradeState = US_INIT;

gchar   currentVersion[20] = "0.0.0";

/**
 * @brief String representation of HTTP methods.
 */
static const char *HTTPMethod_STRING[] = {
        "GET", "HEAD", "PUT", "POST", "PATCH", "DELETE"
};

static struct config *hawkbit_config = NULL;
static GSourceFunc software_ready_cb;
//static gchar * volatile action_id = NULL;
static size_t downloadStart = 0;

static const char *rootCAcert = "-----BEGIN CERTIFICATE-----\n\rMIICOzCCAeGgAwIBAgIUdo8hZE5NgzUy5XY+qS9aZH3qOCAwCgYIKoZIzj0EAwIw\n\rajEfMB0GA1UEAwwWVHltcGhhbnlDb2RlU2lnblJvb3RDQTEeMBwGA1UECwwVUHJv\n\rZHVjdCBDeWJlcnNlY3VyaXR5MRowGAYDVQQKDBFSaXZpYW4gQXV0b21vdGl2ZTEL\n\rMAkGA1UEBhMCVVMwIBcNMjEwNTI3MjI0NDM5WhgPMjA3MTA1MTUyMjQ0MzhaMGox\n\rHzAdBgNVBAMMFlR5bXBoYW55Q29kZVNpZ25Sb290Q0ExHjAcBgNVBAsMFVByb2R1\n\rY3QgQ3liZXJzZWN1cml0eTEaMBgGA1UECgwRUml2aWFuIEF1dG9tb3RpdmUxCzAJ\n\rBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVmgrLHJPZ3hb4ws6\n\r01qH6bVZSTKG8Tq2znRbk/M8VdPNuczpMztr/SBOMN2ObTv1upQUUrHKrWX5eaXA\n\r9StZi6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTet/qCqaU8YM4p\n\rNW+Kr2hO+jauUDAdBgNVHQ4EFgQU3rf6gqmlPGDOKTVviq9oTvo2rlAwDgYDVR0P\n\rAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCICfsbAb0j1Rdw4eplAWUefQR/Nuc\n\rfT04svna4j9L6fO+AiEAyGxdPhyT0hH+Ix1Q0xPhcGD953dpIfPTqTkzV0HqvrA=\n\r-----END CERTIFICATE-----";

static const char *PpCertFile   = "/persist/rauc-hawkbit-updater/certs/client.crt";
static const char *PpCACertFile = "/persist/rauc-hawkbit-updater/certs/3rdparty_infra_cert_chain.pem";
static const char *PpKeyName    = "/persist/rauc-hawkbit-updater/certs/client.key";

static const char *FpCertFile   = "/etc/rauc-hawkbit-updater/ota_access/client.crt";
static const char *FpCACertFile = "/etc/rauc-hawkbit-updater/ota_access/3rdparty_infra_cert_chain.pem";
static const char *FpKeyName    = "/etc/rauc-hawkbit-updater/ota_access/client.key";

static const char *pCertFile;
static const char *pCACertFile;
static const char *pKeyName;
static const char *pRootCA;

static const char *pKeyType = "PEM";

static gboolean checkPoints[FILE_DOWNLOAD_CHECKPOINTS_NUM] = {FALSE};

static gboolean feedback_progress(const gchar *url, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, GError **error, const gchar *finalResult);

char * lastStrstr(const char * haystack,const char * needle){
    char * temp = haystack;
	char * before = 0;
	
    while (temp = strstr(temp,needle)){ 
		before = temp++;
    }

    return before;
}

static gboolean removeRootCA() {
	remove("/persist/rauc-hawkbit-updater/temp/rootCA.crt");
	return TRUE;
}

static gboolean createRootCA() {
	FILE *fp;
	size_t fsize;
	char cert[4096];
//	char rootCert[2048];
	const char *d = "-----BEGIN CERTIFICATE-----";
	char *p;

	fp = fopen("/persist/rauc-hawkbit-updater/temp/rootCA.crt", "w+");
	if(fp != NULL) {

	   fprintf(fp,"%s",rootCAcert);
   	   fclose(fp);
	}

	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("dos2unix /persist/rauc-hawkbit-updater/temp/rootCA.crt");
	system(msg);
}

static gboolean check_keys_certs()
{
	if ((access(PpCertFile, 0)   == 0) 
	&&  (access(PpCACertFile, 0) == 0) 
	&&  (access(PpKeyName, 0)    == 0))
	{
		pCertFile   = PpCertFile;
		pCACertFile = PpCACertFile;
		pKeyName    = PpKeyName;
		syslog(LOG_NOTICE, "All necessary certs and keys are present in persist");
		return TRUE;
	} 
	else if ((access(FpCertFile, 0)   == 0) 
	&&       (access(FpCACertFile, 0) == 0) 
	&&       (access(FpKeyName, 0)    == 0))
	{
		pCertFile   = FpCertFile;
		pCACertFile = FpCACertFile;
		pKeyName    = FpKeyName;
		syslog(LOG_NOTICE, "All necessary certs and keys are present in file system");
		return TRUE;
	}
	else {
		syslog(LOG_NOTICE, "Some certs or keys are missing");
		return FALSE;
	}
}

size_t get_time_legacy() {
    FILE *fp;
	size_t time;
    fp = popen("/etc/initscripts/board-operation/get_time.sh", "r");
    if(fp != NULL) {
        char temp[128];
        fread(temp, sizeof(temp), 1, fp);
		time = atoi(temp);
    }

	return time;
}

size_t get_time() {
	struct timeval current_time;
	gettimeofday(&current_time, NULL);

	return current_time.tv_sec;	
}

static void recordLastFailedTime(char * message)
{
	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("date > /persist/rauc-hawkbit-updater/temp/lastFailed");
	system(msg);

	msg = g_strdup_printf("echo %s >> /persist/rauc-hawkbit-updater/temp/lastFailed", message);
	system(msg);
}

static void recordLastCheckTime()
{
	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("echo %d > /persist/rauc-hawkbit-updater/temp/lastCheck", get_time());

	system(msg);
}

static gboolean attempt_done()
{
	remove("/persist/rauc-hawkbit-updater/temp/attemptStart");
	return TRUE;
}

static gboolean attempt_start()
{
	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("echo %d > /persist/rauc-hawkbit-updater/temp/attemptStart", get_time());

	system(msg);
	return TRUE;
}

static gboolean if_in_progress()
{
	size_t attemptStart = 0;
	size_t now = 0;
	char * temp = NULL;
	FILE * fp;
	size_t len = 0;
	ssize_t read;

	g_autofree gchar *msg = NULL;

	if( access("/persist/rauc-hawkbit-updater/temp/attemptStart", 0 ) == 0 ) {

		fp = fopen("/persist/rauc-hawkbit-updater/temp/attemptStart", "r");
		if (fp == NULL){
			syslog(LOG_ERR, "cannot open now file");
			return FALSE;
		}

		if ((read = getline(&temp, &len, fp)) != -1) {
			attemptStart = atoi(temp);
			syslog(LOG_NOTICE, "attemptStart |%d|", attemptStart);
		}

		fclose(fp);

		now = get_time();

		if ((now - attemptStart) > APPARENTLY_CRASHED_LAST_ATTEMPT) {
			syslog(LOG_NOTICE, "Previous attempt apparently hanged");
			return FALSE;
		}
		else {
			syslog(LOG_NOTICE, "Previous attempt is in progress, seconds past (%d)", (now - attemptStart));
			return TRUE;
		}
	}

	syslog(LOG_NOTICE, "Previous attempt is not in progress");
	return FALSE;
}

static gboolean if_already_time()
{
	FILE * fp;
	size_t lastCheck = 0;
	size_t now = 0;
	char * temp = NULL;
	size_t len = 0;
	ssize_t read;
	g_autofree gchar *msg = NULL;

	if( access("/persist/rauc-hawkbit-updater/temp/lastCheck", 0 ) == 0 ) {

		syslog(LOG_NOTICE, "We have ota check history");

		fp = fopen("/persist/rauc-hawkbit-updater/temp/lastCheck", "r");
		if (fp == NULL){
			syslog(LOG_ERR, "Cannot open ota last check even though it exists"); 
			return TRUE;
		}

		if ((read = getline(&temp, &len, fp)) != -1) {
			lastCheck = atoi(temp);
			syslog(LOG_NOTICE, "Last|%d|", lastCheck);
		}

		fclose(fp);
	}
	else {
		syslog(LOG_NOTICE, "We do not have last check time stamp");
		return TRUE;
	}
	
	now = get_time();

	syslog(LOG_NOTICE, "Seconds since last check passed %d", (now - lastCheck));

	if ((now - lastCheck) > MIN_INTERVAL_BETWEEN_CHECKS_SEC)
	{
		syslog(LOG_NOTICE, "It is time already");
		return TRUE;
	}
	else
	{
		syslog(LOG_NOTICE, "It is not time yet");
		return FALSE;
	}

}

static void send_wait_for_reboot_message()
{
	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("adk-message-send 'system_mode_management {name:\"ota::Wait4Reboot\"}'");
	//sprintf(buf, "echo %s > signed_digest_base64", artifact->signedDigest);
	system(msg);
	sleep(2);
}

static void send_ota_fully_done_message()
{
	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("adk-message-send 'system_mode_management {name:\"ota::FullyDone\"}'");
	//sprintf(buf, "echo %s > signed_digest_base64", artifact->signedDigest);
	system(msg);
}

static void update_current_version()
{
	FILE *f = fopen("/etc/sw-version.conf", "rb");
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, 1, fsize, f);
	fclose(f);

	string[fsize] = 0;

	syslog(LOG_NOTICE, "Current version %s", string);

	//return G_SOURCE_CONTINUE;

	sprintf(currentVersion, "%s", string);
}

static gboolean reset_fail_attempts()
{
	remove("/persist/rauc-hawkbit-updater/temp/fails");
	return TRUE;
}

static size_t set_fail_attempts(size_t attempts)
{
	g_autofree gchar *msg;

	remove("/persist/rauc-hawkbit-updater/temp/fails");
	msg = g_strdup_printf("echo \"%d\" > /persist/rauc-hawkbit-updater/temp/fails", attempts);
	system(msg);
	syslog(LOG_NOTICE, "Set fails attemps count to %d", attempts);
	return 0;
}

static size_t get_fail_attempts()
{
	if( access("/persist/rauc-hawkbit-updater/temp/fails", 0 ) == 0 ) {

		syslog(LOG_NOTICE, "We have fail hystory");

		FILE * fp;
		char * fails = NULL;
		size_t failsCount = 0;
		size_t len = 0;
		ssize_t read;

		fp = fopen("/persist/rauc-hawkbit-updater/temp/fails", "r");
		if (fp == NULL){
			syslog(LOG_ERR, "Cannot open fails file even though it exists");
			return failsCount;
		}

		if ((read = getline(&fails, &len, fp)) != -1) {
			failsCount = atoi(fails);
			syslog(LOG_NOTICE, "Current fails count |%s|%d|", fails, failsCount);
		}
		else {
			syslog(LOG_ERR, "Cannot read fails count");
			return failsCount;
		}
		fclose(fp);

		return failsCount;
	}
	else {
		syslog(LOG_NOTICE, "We do not have fail history");
		return 0;
	}
}

static gboolean if_wait_for_last_step()
{
	if( access("/persist/rauc-hawkbit-updater/temp/inprogress", 0 ) == 0 ) {

		syslog(LOG_NOTICE, "Update is still in progress");

		FILE * fp;
		char * version = NULL;
		char * statusUrl = NULL;
		size_t len = 0;
		ssize_t read;
		int retry = 0;

		fp = fopen("/persist/rauc-hawkbit-updater/temp/inprogress", "r");
		if (fp == NULL){
			syslog(LOG_ERR, "Cannot open inprogress file even though it exists");
			recordLastFailedTime("Cannot open inprogress file even though it exists");
			return TRUE;
		}

		if ((read = getline(&version, &len, fp)) != -1) {
			//printf("Retrieved line of length %zu:\n", read);
			syslog(LOG_NOTICE, "Current SW version: %s       Inprogress SW version: %s", currentVersion, version);

			if (0 == strcmp(version, currentVersion)){
				syslog(LOG_NOTICE, "Update has been finalized, we report to server that it is done");

				if ((read = getline(&statusUrl, &len, fp)) != -1) {

					//printf("Retrieved line of length %zu:\n", read);
					statusUrl[strlen(statusUrl)-1] = '\0';

					while ((++retry <= MAX_RETRY_ON_ZERO_RESPONSE) && (FALSE == feedback_progress(statusUrl, "SUCCESS",   100, "", "", "", "", NULL, "SUCCESS"))){
						syslog(LOG_ERR, "Could not reach back end[%d], try again in 6 seconds", retry);
						sleep(6);
					}

					if (retry > MAX_RETRY_ON_ZERO_RESPONSE)	{
						recordLastFailedTime("Cannot report last step to backend");
						syslog(LOG_ERR, "Try limit reached");
					}
					else {
						remove("/persist/rauc-hawkbit-updater/temp/inprogress");
						recordLastFailedTime("Last step is done, and reported to backend");
						syslog(LOG_ERR, "Successfully reported final step to back-end");
						send_ota_fully_done_message();
					}
				}
				else {
					syslog(LOG_ERR, "Cannot read statusUrls");
					recordLastFailedTime("Cannot read statusUrls");
				}
			}
			else {
				syslog(LOG_NOTICE, "Update has not been finilized, pending for reboot as a last step");
				recordLastFailedTime("Update has not been finilized, pending for reboot as a last step");
			}
		}
		else {
			syslog(LOG_ERR, "Cannot read expected inprogress sw version");
			recordLastFailedTime("Cannot read expected inprogress sw version");
		}
		fclose(fp);

		return TRUE;
	}
	else {
		syslog(LOG_NOTICE, "We are not waiting for reboot to finilize previous upgrade");
		return FALSE;
	}
}

/**
 * @brief Get available free space
 *
 * @param[in] path Path
 * @return If error -1 else free space in bytes
 */
static goffset get_available_space(const char* path, GError **error)
{
        struct statvfs stat;
        g_autofree gchar *npath = g_strdup(path);
        char *rpath = dirname(npath);
        if (statvfs(rpath, &stat) != 0) {
                // error happend, lets quit
                g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "Failed to calculate free space: %s", g_strerror(errno));
                return -1;
        }

        // the available free space is f_bsize * f_bavail
        return (goffset) stat.f_bsize * (goffset) stat.f_bavail;
}

/**
 * @brief Curl callback used for writting software bundle file
 *        and calculate hawkbit checksum.
 *
 * @see   https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 */

static size_t curl_write_to_file_cb(void *ptr, size_t size, size_t nmemb, struct get_binary *data)
{
		//syslog(LOG_NOTICE, "curl_write_to_file_cb: size:%d, nmemb:%d\n", size, nmemb);

        size_t written = fwrite(ptr, size, nmemb, data->fp);

        double percentage;

        data->written += written;
        if (data->checksum) {
                g_checksum_update(data->checksum, ptr, written);
        }

		percentage = (double) data->written / data->filesize * 100;

        //syslog(LOG_NOTICE, "bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);

		for (int ii = (FILE_DOWNLOAD_CHECKPOINTS_NUM-1); ii >= 0; ii--)
		{
			if (!checkPoints[ii] && (percentage > (ii+1) * FILE_DOWNLOAD_CHECKPOINTS_PERCENT_STEP))
			{
				checkPoints[ii] = TRUE;

				syslog(LOG_NOTICE, "bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);
				//char buf[100];
				//sprintf(buf, "Bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);

				g_autofree gchar *msg = g_strdup_printf("Bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);

				// The downloading is done is 80% of all in all progress
				feedback_progress(data->status, "DOWNLOADING", (ii + 1) * (FILE_DOWNLOAD_ALL_IN_ALL_PERCENT_PER_CHECKPOINT), "downloadDetails", msg, "", "", NULL, "");
				break;
			}
		}

        return written;
}


/**
 * @brief download software bundle to file.
 *
 * @param[in]  download_url   URL to Software bundle
 * @param[in]  file           File the software bundle should be written to.
 * @param[in]  filesize       Expected file size
 * @param[out] checksum       Calculated checksum
 * @param[out] http_code      Return location for the http_code, can be NULL
 * @param[out] error          Error
 */
static gboolean get_binary(const gchar* download_url, const gchar* file, gint64 filesize, struct get_binary_checksum *checksum, glong *http_code, GError **error, gchar* status)
{
        FILE *fp = fopen(file, "wb");
        if (fp == NULL) {
                g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
                            "Failed to open file for download: %s", file);
                return FALSE;
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
                fclose(fp);
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "Unable to start libcurl easy session");
                return FALSE;
        }

        struct get_binary gb = {
                .fp       = fp,
                .filesize = filesize,
                .written  = 0,
                .checksum = (checksum != NULL ? g_checksum_new(checksum->checksum_type) : NULL),
                .status   = status
        };

        curl_easy_setopt(curl, CURLOPT_URL, download_url);
 //       curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
 //       curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
        //curl_easy_setopt(curl, CURLOPT_USERAGENT, HAWKBIT_USERAGENT);
   //     curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, hawkbit_config->connect_timeout);
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, DEFAULT_CURL_DOWNLOAD_BUFFER_SIZE);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_file_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &gb);
   //     curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, hawkbit_config->ssl_verify ? 1L : 0L);
   //     curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, hawkbit_config->ssl_verify ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

   //curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        /* abort if slower than 100 bytes/sec during 60 seconds */
  //      curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
  //      curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 100L);
        // Setup request headers
        struct curl_slist *headers = NULL;
/*
        headers = curl_slist_append(headers, "Accept: application/octet-stream");
        if (hawkbit_config->auth_token) {
                g_autofree gchar* auth_token = g_strdup_printf("Authorization: TargetToken %s", hawkbit_config->auth_token);
                headers = curl_slist_append(headers, auth_token);
        } else if (hawkbit_config->gateway_token) {
                g_autofree gchar* gateway_token = g_strdup_printf("Authorization: GatewayToken %s", hawkbit_config->gateway_token);
                headers = curl_slist_append(headers, gateway_token);
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
*/
        CURLcode res = curl_easy_perform(curl);

        if (http_code)
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);

		syslog(LOG_NOTICE, ">>>>>>>>Get Binary Response status code: %d, result[%d]", &http_code, res);

        if (res == CURLE_OK) {
                if (gb.checksum) { // if checksum enabled then return the value
                        checksum->checksum_result = g_strdup(g_checksum_get_string(gb.checksum));
                        g_checksum_free(gb.checksum);
                }
        } else {
                g_set_error(error,
                            G_IO_ERROR,                    // error domain
                            G_IO_ERROR_FAILED,             // error code
                            "HTTP request failed: %s",     // error message format string
                            curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        fclose(fp);
        return (res == CURLE_OK);
}

/**
 * @brief Curl callback used for writting rest response to buffer.
 */
static size_t curl_write_cb(void *content, size_t size, size_t nmemb, void *data)
{
        struct rest_payload *p = (struct rest_payload *) data;
        size_t real_size = size * nmemb;

        p->payload = (gchar *) g_realloc(p->payload, p->size + real_size + 1);
        if (p->payload == NULL) {
                syslog(LOG_ERR, "Failed to expand buffer");
                return -1;
        }

        // copy content to buffer
        memcpy(&(p->payload[p->size]), content, real_size);
        p->size += real_size;
        p->payload[p->size] = '\0';

        return real_size;
}

/**
 * @brief Make REST request.
 *
 * @param[in]  method             HTTP Method ex. GET
 * @param[in]  url                URL used in HTTP REST request
 * @param[in]  jsonRequestBody    REST request body. If NULL, no body is sent.
 * @param[out] jsonResponseParser REST response
 * @param[out] error              Error
 * @return HTTP Status code (Standard codes: 200 = OK, 524 = Operation timed out, 401 = Authorization needed, 403 = Authentication failed )
 */

static gint rest_request(enum HTTPMethod method, const gchar* url, JsonBuilder* jsonRequestBody, JsonParser** jsonResponseParser, GError** error, gboolean progressReport)
{
        gchar *postdata = NULL;
        struct rest_payload fetch_buffer;

        CURL *curl = curl_easy_init();
        if (!curl) return -1;

#ifdef PRINT_REQUESTS
        syslog(LOG_NOTICE, "[%s]: method[%s] url[%s]", __FUNCTION__, HTTPMethod_STRING[method], url);
#endif
        // init response buffer
        fetch_buffer.payload = g_malloc0(DEFAULT_CURL_REQUEST_BUFFER_SIZE);
        if (fetch_buffer.payload == NULL) {
                syslog(LOG_ERR, "Failed to expand buffer");
                curl_easy_cleanup(curl);
                return -1;
        }
        fetch_buffer.size = 0;

		// setup CURL options
		curl_easy_setopt(curl, CURLOPT_URL, url);
		//curl_easy_setopt(curl, CURLOPT_USERAGENT, HAWKBIT_USERAGENT);
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, HTTPMethod_STRING[method]);
		//curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, hawkbit_config->connect_timeout);
		//curl_easy_setopt(curl, CURLOPT_TIMEOUT, hawkbit_config->timeout);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &fetch_buffer);
		//curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
#ifdef PRINT_REQUESTS
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#else
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
#endif
		/* set the file with the certs vaildating the server */
		curl_easy_setopt(curl, CURLOPT_CAINFO, pCACertFile);

		/* set the cert for client authentication */
		curl_easy_setopt(curl, CURLOPT_SSLCERT, pCertFile);


		/* if we use a key stored in a crypto engine,
		we must set the key type to "ENG" */
		curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, pKeyType);

		/* set the private key (file or ID in engine) */
		curl_easy_setopt(curl, CURLOPT_SSLKEY, pKeyName);

		curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.61.0");

        if (jsonRequestBody) {
                // Convert request into a string
                JsonGenerator *generator = json_generator_new();
                json_generator_set_root(generator, json_builder_get_root(jsonRequestBody));
                gsize length;
                postdata = json_generator_to_data(generator, &length);
                g_object_unref(generator);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
#ifdef PRINT_REQUESTS
                syslog(LOG_NOTICE, ">>>>>>Request body: %s\n", postdata);
#endif
        }

        // Setup request headers
        struct curl_slist *headers = NULL;
        //headers = curl_slist_append(headers, "Accept: application/json");

		if (!progressReport)
		{
			char buf[100];
			sprintf(buf, "ota-current-version:%s", currentVersion);
			//headers = curl_slist_append(headers, "ota-current-version:2.2.2");
			headers = curl_slist_append(headers, buf);
		}
		else
		{
			 headers = curl_slist_append(headers, "Content-Type: application/json");
		}
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        glong http_code = 0;

        CURLcode res = curl_easy_perform(curl);

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		static int countMe;
		if (0 == http_code) {
			syslog(LOG_NOTICE, ">>>>>>>>[%d]ZERO_RESPONSE_REST[%s]Response status code: %d, fetch_buffer.size[%d]", ++countMe, HTTPMethod_STRING[method], http_code, fetch_buffer.size);
		} else {
			syslog(LOG_NOTICE, ">>>>>>>>REST[%s]Response status code: %d, fetch_buffer.size[%d]", HTTPMethod_STRING[method], http_code, fetch_buffer.size);
		}
		//syslog(LOG_NOTICE, "res[%d] http_code: %ld  fetch_buffer.size[%d]\n", res, http_code, fetch_buffer.size);

        if (res == CURLE_OK && http_code == 200) {
                if (jsonResponseParser && fetch_buffer.size > 0) {
                        JsonParser *parser = json_parser_new_immutable();
                        if (json_parser_load_from_data(parser, fetch_buffer.payload, fetch_buffer.size, error)) {
                                *jsonResponseParser = parser;
                        } else {
                                g_object_unref(parser);
                                syslog(LOG_ERR, "Failed to parse JSON response body. status: %ld\n", http_code);
                        }
                }
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
                // libcurl was able to complete a TCP connection to the origin server, but did not receive a timely HTTP response.
                http_code = 524;
                g_set_error(error,
                            1,                    // error domain
                            http_code,
                            "HTTP request timed out: %s (%d)",
                            curl_easy_strerror(res), res);
        } else {
                g_set_error(error,
                            1,                    // error domain
                            http_code,
                            "HTTP request failed: %s (%d)",
                            curl_easy_strerror(res), res);
        }

        //syslog(LOG_NOTICE, "Response body: %s\n", fetch_buffer.payload);

        g_free(fetch_buffer.payload);
        g_free(postdata);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return http_code;
}

/**
 * @brief Build JSON status request.
 * @see https://www.eclipse.org/hawkbit/rest-api/rootcontroller-api-guide/#_post_tenant_controller_v1_controllerid_deploymentbase_actionid_feedback
 */
static void json_build_status(JsonBuilder *builder, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, const gchar *finalResult)
{
        GHashTableIter iter;
        gpointer key, value;

        // Get current time in UTC
        time_t current_time;
        struct tm time_info;
        char timeString[16];
        time(&current_time);
        gmtime_r(&current_time, &time_info);
        strftime(timeString, sizeof(timeString), "%Y%m%dT%H%M%S", &time_info);

        // build json status
        json_builder_begin_object(builder);
			json_builder_set_member_name(builder, "states");
			json_builder_begin_array(builder);
				json_builder_begin_object(builder);
			        json_builder_set_member_name(builder, "state");
			        json_builder_add_string_value(builder, state);
			        json_builder_set_member_name(builder, "timestamp");
			        json_builder_add_int_value(builder, current_time);
			        json_builder_set_member_name(builder, "progress");
			        json_builder_add_int_value(builder, progress);
					if (0 != strcmp(finalResult,"")) {
#ifdef REPORT_FINAL_STATE
						json_builder_set_member_name(builder, "final");
			        	json_builder_add_string_value(builder, finalResult);
#endif
					}
					json_builder_set_member_name(builder, "details");
					json_builder_begin_object(builder);
						if (0 != strcmp(value1_name,"")) {
					        json_builder_set_member_name(builder,  value1_name);
					        json_builder_add_string_value(builder, value1);
						}
						if (0 != strcmp(value2_name,"")) {
					        json_builder_set_member_name(builder,  value2_name);
					        json_builder_add_string_value(builder, value2);
						}
					json_builder_end_object(builder);
				json_builder_end_object(builder);

			json_builder_end_array(builder);
		json_builder_end_object(builder);
}

/**
 * @brief Build JSON status request.
 * @see https://www.eclipse.org/hawkbit/rest-api/rootcontroller-api-guide/#_post_tenant_controller_v1_controllerid_deploymentbase_actionid_feedback
 */
static void json_build_status_ex(JsonBuilder *builder, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, const gchar *value3_name, const gchar *value3, const gchar *finalResult)
{
        GHashTableIter iter;
        gpointer key, value;

        // Get current time in UTC
        time_t current_time;
        struct tm time_info;
        char timeString[16];
        time(&current_time);
        gmtime_r(&current_time, &time_info);
        strftime(timeString, sizeof(timeString), "%Y%m%dT%H%M%S", &time_info);

        // build json status
        json_builder_begin_object(builder);
			json_builder_set_member_name(builder, "states");
			json_builder_begin_array(builder);
				json_builder_begin_object(builder);
			        json_builder_set_member_name(builder, "state");
			        json_builder_add_string_value(builder, state);
			        json_builder_set_member_name(builder, "timestamp");
			        json_builder_add_int_value(builder, current_time);
			        json_builder_set_member_name(builder, "progress");
			        json_builder_add_int_value(builder, progress);
					if (0 != strcmp(finalResult,"")) {
#ifdef REPORT_FINAL_STATE
						json_builder_set_member_name(builder, "final");
			        	json_builder_add_string_value(builder, finalResult);
#endif
					}
					json_builder_set_member_name(builder, "details");
					json_builder_begin_object(builder);
						if (0 != strcmp(value1_name,"")) {
					        json_builder_set_member_name(builder,  value1_name);
					        json_builder_add_string_value(builder, value1);
						}
						if (0 != strcmp(value2_name,"")) {
					        json_builder_set_member_name(builder,  value2_name);
					        json_builder_add_string_value(builder, value2);
						}
						if (0 != strcmp(value3_name,"")) {
							json_builder_set_member_name(builder,  value3_name);
							json_builder_add_string_value(builder, value3);
						}

					json_builder_end_object(builder);
				json_builder_end_object(builder);

			json_builder_end_array(builder);
		json_builder_end_object(builder);
}

/**
 * @brief Send progress feedback to hawkBit.
 */
static gboolean feedback_progress(const gchar *url, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, GError **error, const gchar *finalResult)
{
        JsonBuilder *builder = json_builder_new();

        json_build_status(builder, state, progress, value1_name, value1, value2_name, value2, finalResult);

        int status = rest_request(PUT, url, builder, NULL, error, TRUE);
        //syslog(LOG_NOTICE, "feedback_progress: %d, URL: %s", status, url);
        g_object_unref(builder);
        return (status == 200);
}

/**
 * @brief Send progress feedback to hawkBit.
 */
static gboolean feedback_progress_ex(const gchar *url, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, const gchar *value3_name, const gchar *value3, GError **error, const gchar *finalResult)
{
        JsonBuilder *builder = json_builder_new();

        json_build_status_ex(builder, state, progress, value1_name, value1, value2_name, value2, value3_name, value3, finalResult);

        int status = rest_request(PUT, url, builder, NULL, error, TRUE);
        //syslog(LOG_NOTICE, "feedback_progress: %d, URL: %s", status, url);
        g_object_unref(builder);
        return (status == 200);
}


/**
 * @brief Get polling sleep time from hawkBit JSON response.
 */
static long json_get_version(JsonNode *root)
{
        //gchar *version = json_get_string(root, "$.metadata.version");
        gchar version[10] = "1.2.3";
        char *temp;
        char v1, v2, v3;
        if (version) {

                temp = strtok(version, ".");
                v1 = atoi(temp);
                temp = strtok(NULL, ".");
                v2 = atoi(temp);
                temp = strtok(NULL, ".");
                v3 = atoi(temp);

            //    syslog(LOG_NOTICE, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!: %d.%d.%d", v1, v2, v3);

                return v1*10000+v2*100+v3;
        }
        return 0;
}
/**
 * @brief Get version hawkBit JSON response.
 */
static long json_get_sleeptime(JsonNode *root)
{
        gchar *sleeptime_str = json_get_string(root, "$.config.polling.sleep");
        if (sleeptime_str) {
                struct tm time;
                strptime(sleeptime_str, "%T", &time);
                long poll_sleep_time = (time.tm_sec + (time.tm_min * 60) + (time.tm_hour * 60 * 60));
                //syslog(LOG_NOTICE, "sleep time: %s %ld\n", sleeptime_str, poll_sleep_time);
                g_free(sleeptime_str);
                return poll_sleep_time;
        }
        return DEFAULT_SLEEP_TIME_SEC;
}

/**
 * @brief
 */
static gchar** regex_groups(const gchar* pattern, const gchar *str, GError **error)
{
        gchar **result = NULL;
        GMatchInfo *match_info;
        GRegex *regex = g_regex_new(pattern, 0, 0, error);
        g_regex_match(regex, str, 0, &match_info);
        if (g_match_info_matches(match_info))
        {
                result = g_match_info_fetch_all(match_info);
        }
        g_match_info_free(match_info);
        g_regex_unref(regex);
        return result;
}

/**
 * @brief Build API URL
 *
 * @param path[in] a printf()-like format string describing the API path
 * @param ... The arguments to be insterte in path
 *
 * @return a newly allocated full API URL
 */
__attribute__((__format__(__printf__, 1, 2)))
static gchar* build_api_url(const gchar *path, ...)
{
        g_autofree gchar *buffer;
        va_list args;

        va_start(args, path);
        buffer = g_strdup_vprintf(path, args);
        va_end(args);

        return g_strdup_printf("%s://%s%s", hawkbit_config->ssl ? "https" : "http", hawkbit_config->server, buffer);
}

static void process_artifact_cleanup(struct artifact *artifact)
{
        if (artifact == NULL)
                return;
        g_free(artifact->response_id);
        g_free(artifact->state);
        g_free(artifact->status);
        g_free(artifact->action);

        g_free(artifact->artifact_id);
        g_free(artifact->sha256);
		//g_free(artifact->size);
		g_free(artifact->name);
		g_free(artifact->downloadUrl);
		g_free(artifact->filetype);
		g_free(artifact->signedDigest);
		g_free(artifact->signingCertificate);
		g_free(artifact->signingIntermediateCA);
		g_free(artifact->version);
        g_free(artifact);
}

static void process_deployment_cleanup()
{
#ifdef REMOVE_BUNLDE_AFTER_OTA
    if (g_file_test(hawkbit_config->bundle_download_location, G_FILE_TEST_EXISTS)) {
            if (g_remove(hawkbit_config->bundle_download_location) != 0) {
                    syslog(LOG_ERR, "Failed to delete file: %s", hawkbit_config->bundle_download_location);
            }
    }
#endif

#ifdef REMOVE_TEMP_FILES_AFTER_OTA
		g_autofree gchar *msg = NULL;

		msg = g_strdup_printf("rm /persist/rauc-hawkbit-updater/temp/signed_digest_base64");
		system(msg);
		msg = g_strdup_printf("rm /persist/rauc-hawkbit-updater/temp/signingCertificate.crt");
		system(msg);
		msg = g_strdup_printf("rm /persist/rauc-hawkbit-updater/temp/signingIntermediateCA.crt");
		system(msg);

		msg = g_strdup_printf("rm /persist/rauc-hawkbit-updater/temp/code_signing_certificate_public_key.pem");
		system(msg);
		msg = g_strdup_printf("rm /persist/rauc-hawkbit-updater/temp/signature.bin");
		system(msg);
		msg = g_strdup_printf("rm /persist/rauc-hawkbit-updater/temp/ota.raucb.bin.sha256");
		system(msg);

		sleep(1);
#endif

}

static gpointer download_thread(gpointer data)
{
        struct on_new_software_userdata userdata = {
			.file = hawkbit_config->bundle_download_location,
        };

        GError *error = NULL;
        g_autofree gchar *msg = NULL;
        struct artifact *artifact = data;
		gint fails;

		syslog(LOG_NOTICE, "Start downloading: %s\n\r", artifact->downloadUrl);

        // setup checksum
        struct get_binary_checksum checksum = { .checksum_result = NULL, .checksum_type = G_CHECKSUM_SHA256 };

        feedback_progress(artifact->status, "DOWNLOADING", 2, "info", "About to start downloading", "", "", NULL, "");

        // Download software bundle (artifact)
        gint64 start_time = g_get_monotonic_time();
        gint status = 0;

#ifndef SKIP_DOWNLOAD		
        gboolean res = get_binary(artifact->downloadUrl, hawkbit_config->bundle_download_location,
                                  artifact->size, &checksum, &status, &error, artifact->status);
#else
		gboolean res = TRUE;
#endif
        gint64 end_time = g_get_monotonic_time();

        if (!res) {
                msg = g_strdup_printf("Download failed: %s Status: %d", error->message, status);
                g_clear_error(&error);
                syslog(LOG_ERR, "%s", msg);
                feedback_progress(artifact->status, "SILENT_FAILURE", 6, "failureDetails", msg, "", "", NULL, "");
				recordLastFailedTime("download fail");
                goto down_error;
        }

		syslog(LOG_NOTICE, "Binary downloading res[%s]",(res) ? "SUCCESS" : "FAIL");

        // notify hawkbit that download is complete
        msg = g_strdup_printf("Download complete %.2f MB/s",
                              (artifact->size / ((double)(end_time - start_time) / 1000000)) / (1024 * 1024));

        syslog(LOG_NOTICE, "%s", msg);

		feedback_progress(artifact->status, "DOWNLOADED", 75, "details", "File was fully downloaded", "", "", NULL, "");

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 80, "details", "Starting file validating procedure", "", "", NULL, "");

#ifndef SKIP_DOWNLOAD	
        // validate checksum
        if (g_strcmp0(artifact->sha256, checksum.checksum_result)) {
			g_autofree gchar *msgDetails = NULL;

            msgDetails = g_strdup_printf(
            "Software: %s V%s. Invalid checksum: %s expected %s",
            artifact->name, artifact->version,
            checksum.checksum_result,
            artifact->sha256);

			fails = get_fail_attempts();

			if (fails >=2) {
				msg = g_strdup_printf("CRC check failed and we reached an attempts limit. Stop campaign.");
				reset_fail_attempts();
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "moreDetails", msgDetails, NULL, "FAIL");
			} else {
				msg = g_strdup_printf("CRC check failed but we will try again");
				set_fail_attempts(fails+1);
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "moreDetails", msgDetails, NULL, "");
			}
            syslog(LOG_ERR, "%s", msg);
			recordLastFailedTime("CRC fail");
            goto down_error;
        }
#endif

		msg = g_strdup_printf("Checksum check passed");
		syslog(LOG_NOTICE, "%s",msg);

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 83, "details", msg, "", "", NULL, "");

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	0. Save certificates and asignature to file system
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		msg = g_strdup_printf("echo \"%s\" > /persist/rauc-hawkbit-updater/temp/signed_digest_base64", artifact->signedDigest);
		system(msg);
		msg = g_strdup_printf("echo \"%s\" > /persist/rauc-hawkbit-updater/temp/signingCertificate.crt", artifact->signingCertificate);
		system(msg);
		msg = g_strdup_printf("echo \"%s\" > /persist/rauc-hawkbit-updater/temp/signingIntermediateCA.crt", artifact->signingIntermediateCA);
		system(msg);

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	1. Validating the authenticity of signingCertificate against signingIntermediateCA
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		msg = g_strdup_printf("openssl verify -partial_chain -verbose -CAfile /persist/rauc-hawkbit-updater/temp/signingIntermediateCA.crt /persist/rauc-hawkbit-updater/temp/signingCertificate.crt");

		FILE *fp;
		char result[1024];
		
		fp = popen(msg, "r");

		fgets(result, sizeof(result), fp);

		pclose(fp);

		if (0 != strncmp(result, "/persist/rauc-hawkbit-updater/temp/signingCertificate.crt: OK", strlen("/persist/rauc-hawkbit-updater/temp/signingCertificate.crt: OK"))){
			fails = get_fail_attempts();

			if (fails >=2) {
				msg = g_strdup_printf("Validating the authenticity of signingCertificate against signingIntermediateCA failed and we have reached an attempts limit. Stop campaign.");
				reset_fail_attempts();
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "signingCertificate", artifact->signingCertificate, NULL, "FAIL");
			} else {
				msg = g_strdup_printf("Validating the authenticity of signingCertificate against signingIntermediateCA failed but we will try again");
				set_fail_attempts(fails+1);
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "signingCertificate", artifact->signingCertificate, NULL, "");
			}
			syslog(LOG_ERR, "%s", msg);
			recordLastFailedTime("Validating the authenticity of signingCertificate against signingIntermediateCA failed");
			goto down_error;
		}

		msg = g_strdup_printf("Validating the authenticity of signingCertificate against signingIntermediateCA SUCCESS");
		syslog(LOG_NOTICE, "%s",msg);

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 83, "details", msg, "", "", NULL, "");

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	2. Verify rootCA included in signingIntermediateCA (it is the first cert in the chain (at the top)) against rootCA pinned in firmware. This is just a string comparison.
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	createRootCA();

	msg = g_strdup_printf("openssl verify -verbose -CAfile /persist/rauc-hawkbit-updater/temp/rootCA.crt /persist/rauc-hawkbit-updater/temp/signingIntermediateCA.crt");

	fp = popen(msg, "r");
	
	fgets(result, sizeof(result), fp);
	
	pclose(fp);

	removeRootCA();

	if (0 != strncmp(result, "/persist/rauc-hawkbit-updater/temp/signingIntermediateCA.crt: OK", strlen("/persist/rauc-hawkbit-updater/temp/signingIntermediateCA.crt: OK"))){
		fails = get_fail_attempts();
	
		if (fails >=2) {
			msg = g_strdup_printf("Validating the authenticity of signingIntermediateCA against rootCA failed and we have reached an attempts limit. Stop campaign.");
			reset_fail_attempts();
			feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "signingIntermediateCertificate", artifact->signingIntermediateCA, NULL, "FAIL");
		} else {
			msg = g_strdup_printf("Validating the authenticity of signingIntermediateCA against rootCA failed but we will try again");
			set_fail_attempts(fails+1);
			feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "signingIntermediateCertificate", artifact->signingIntermediateCA, NULL, "");
		}
		syslog(LOG_ERR, "%s", msg);
		recordLastFailedTime("Verify rootCA included in signingIntermediateCA failed");
		goto down_error;
	}
	
	msg = g_strdup_printf("Validating the authenticity of signingIntermediateCA against rootCA SUCCESS");
	syslog(LOG_NOTICE, "%s",msg);
	
	feedback_progress(artifact->status, "VALIDATING_PACKAGE", 83, "details", msg, "", "", NULL, "");

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	3. signingCertificate.crt -> code_signing_certificate_public_key.pem
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	msg = g_strdup_printf("openssl x509 -pubkey -noout -in /persist/rauc-hawkbit-updater/temp/signingCertificate.crt > /persist/rauc-hawkbit-updater/temp/code_signing_certificate_public_key.pem");
	system(msg);

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	4. Check signature
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		msg = g_strdup_printf("openssl dgst -sha256 -binary -out /persist/rauc-hawkbit-updater/temp/ota.raucb.bin.sha256 %s", hawkbit_config->bundle_download_location);
		system(msg);
		msg = g_strdup_printf("base64 --decode /persist/rauc-hawkbit-updater/temp/signed_digest_base64 > /persist/rauc-hawkbit-updater/temp/signature.bin");
		system(msg);
		msg = g_strdup_printf("openssl dgst -sha256 -verify /persist/rauc-hawkbit-updater/temp/code_signing_certificate_public_key.pem -signature /persist/rauc-hawkbit-updater/temp/signature.bin /persist/rauc-hawkbit-updater/temp/ota.raucb.bin.sha256");
	
		fp = popen(msg, "r");

		fgets(result, sizeof(result), fp);

		pclose(fp);;

		if (0 != strncmp(result, "Verified OK", strlen("Verified OK"))) {

			fails = get_fail_attempts();

			if (fails >=2) {
				msg = g_strdup_printf("Digital signature verification failed and we reached an attempts limit. Stop campaign.");
				reset_fail_attempts();
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "digitalSignature", artifact->signedDigest, NULL, "FAIL");
			} else {
				msg = g_strdup_printf("Digital signature verification failed but we will try again");
				set_fail_attempts(fails+1);
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", msg, "digitalSignature", artifact->signedDigest, NULL, "");
			}
			syslog(LOG_ERR, "%s", msg);
			recordLastFailedTime("Digital signature verification failed");
            goto down_error;
		}

		syslog(LOG_NOTICE, "Digital signature check SUCCESS");

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 84, "details", "Digital signature verification passed", "", "", NULL, "");
		feedback_progress(artifact->status, "INSTALLING",85, "details", "Memory bank flashing start", "", "", NULL, "");

		msg = g_strdup_printf("/etc/factory-test/r1/updateOTA.sh ota.raucb", artifact->signedDigest);

		syslog(LOG_NOTICE, "Recovery Started");

		fp = popen(msg, "r");

		fgets(result, sizeof(result), fp);

		pclose(fp);

		syslog(LOG_NOTICE, "Recovery Done");

		if (0 != strncmp(result, "OTA success", strlen("OTA success"))) {
			feedback_progress(artifact->status, "SILENT_FAILURE", 83, "failureDetails", "Flashing memory bank failed", "", "", NULL, "");
            syslog(LOG_ERR, "%s", msg);
            status = -4;
			recordLastFailedTime("Recovery failed");
            goto down_error;
		}

		feedback_progress(artifact->status, "INSTALLING",86, "details", "Memory bank flashing done", "", "", NULL, "");
		feedback_progress(artifact->status, "PENDING_REBOOT", 87, "details", "Now we wait for system reboot", "", "", NULL, "");

		reset_fail_attempts();

		//feedback_progress(artifact->status, "EXECUTING", 90, "", "", "", "", NULL, FALSE, "");
		//feedback_progress(artifact->status, "INSTALLING",95, "", "", "", "", NULL, FALSE, "");
		//feedback_progress(artifact->status, "SUCCESS",   100, "", "", "", "", NULL, TRUE, "SUCCESS");

		//sprintf(buf, "touch /persist/rauc-hawkbit-updater/temp/inprogress");

		msg = g_strdup_printf("mkdir -p /persist/rauc-hawkbit-updater/temp/");
		system(msg);

		msg = g_strdup_printf("echo \"%s\n%s\" > /persist/rauc-hawkbit-updater/temp/inprogress", artifact->version, artifact->status);
		//sprintf(buf, "echo \"%s\n%s\" > /persist/rauc-hawkbit-updater/temp/inprogress", artifact->version, artifact->status);
		system(msg);

		msg = g_strdup_printf("echo \"\" > /data/ota-successed");
		system(msg);

		recordLastFailedTime("successfully flashed");

        g_free(checksum.checksum_result);
        process_artifact_cleanup(artifact);
		process_deployment_cleanup();
		upgradeState = US_DONE_REBOOT;
        return NULL;
down_error:
        g_free(checksum.checksum_result);
        process_artifact_cleanup(artifact);
        process_deployment_cleanup();
		upgradeState = US_DONE_FAILED;
        return NULL;
}


static gboolean process_deployment(JsonNode *req_root, GError **error)
{
        GError *ierror = NULL;
        struct artifact *artifact = NULL;

		JsonArray *json_artifacts = json_get_array(req_root, "$.artifacts");

        JsonNode *json_artifact = json_array_get_element(json_artifacts, 0);

        // get artifact information
        artifact = g_new0(struct artifact, 1);

		artifact->response_id           = json_get_string(req_root, "$.id");
		artifact->state                 = json_get_string(req_root, "$.state");
		artifact->status                = json_get_string(req_root, "$.status");
		artifact->action                = json_get_string(req_root, "$.action");
        artifact->artifact_id           = json_get_string(json_artifact, "$.id");
        artifact->sha256                = json_get_string(json_artifact, "$.sha256");
        artifact->size                  = json_get_int   (json_artifact, "$.size");
        artifact->name                  = json_get_string(json_artifact, "$.name");
        artifact->downloadUrl           = json_get_string(json_artifact, "$.downloadUrl");
        artifact->filetype              = json_get_string(json_artifact, "$.filetype");
		artifact->signedDigest          = json_get_string(json_artifact, "$.signedDigest");
		artifact->signingCertificate    = json_get_string(json_artifact, "$.signingCertificate");
		artifact->signingIntermediateCA = json_get_string(json_artifact, "$.signingIntermediateCA");
		artifact->version               = json_get_string (req_root,  "$.metadata.version");

        if (artifact->downloadUrl == NULL) {

                g_set_error(error,1,22,"Failed to parse deployment resource.");
                goto proc_error;
        }

		g_autofree gchar *msg = g_strdup_printf("New software ready for download. (Name: %s, Version: %s, Size: %d)", artifact->name, artifact->version, artifact->size);

		syslog(LOG_NOTICE, "%s", msg);

		feedback_progress_ex(artifact->status, "NOT_STARTED", 0, "info", msg, "downloadURL", artifact->downloadUrl, "currentVersion", currentVersion, NULL, "");

        // Check if there is enough free diskspace
        long freespace = get_available_space(hawkbit_config->bundle_download_location, &ierror);

		syslog(LOG_NOTICE, "[%s]: freespace available = %d", __FUNCTION__, freespace);

        if ((freespace == -1) || (freespace < artifact->size)) {
                g_autofree gchar *msg = g_strdup_printf("Not enough free space. File size: %" G_GINT64_FORMAT  ". Free space: %ld", artifact->size, freespace);
				g_propagate_error(error, ierror);
				feedback_progress(artifact->status, "SILENT_FAILURE", 0, "failureDetails", msg, "", "", NULL, "");
				syslog(LOG_ERR, "%s", msg);
                g_set_error(error, 1, 23, "%s", msg);
                goto proc_error;
        }

		//feedback_progress(artifact->status, "NOT_STARTED", 0, "", "We see new sw to download", "Our hopes", "We hope it will go smoothly", ierror, FALSE, "");

        g_thread_new("downloader", download_thread, (gpointer) artifact);
        return TRUE;

proc_error:
        // Lets cleanup processing deployment failed
        process_artifact_cleanup(artifact);
        process_deployment_cleanup();
		recordLastFailedTime("deployment fail ");
		upgradeState = US_DONE_FAILED;
        return FALSE;
}


void hawkbit_init(struct config *config, GSourceFunc on_install_ready)
{
        hawkbit_config = config;
        software_ready_cb = on_install_ready;
        curl_global_init(CURL_GLOBAL_ALL);
}

typedef struct ClientData_ {
        GMainLoop *loop;
        gboolean res;
} ClientData;

static gboolean hawkbit_pull_cb(gpointer user_data)
{
        ClientData *data = user_data;
		static int zero_response_retry; 

		switch(upgradeState){
			case US_INIT:
				syslog(LOG_NOTICE, "OTA in init");
				break;
			case US_DOWNLOAD:
				if ((get_time() - downloadStart) > WAIT_DOWNLOAD_FINISH_MAX_TIME){
					syslog(LOG_NOTICE, "OTA done due to timeout");
					attempt_done();
					recordLastFailedTime("timeout ");
		            data->res = 0;
		            g_main_loop_quit(data->loop);
		            return G_SOURCE_REMOVE;					
				}
				else {
					syslog(LOG_NOTICE, "OTA in progress for [%d] sec", (get_time() - downloadStart));
					return G_SOURCE_CONTINUE;
				}
				break;
			case US_DONE_REBOOT:
				syslog(LOG_NOTICE, "OTA is done, need to reboot");
				attempt_done();
				send_wait_for_reboot_message();
	            data->res = 0;				
	            g_main_loop_quit(data->loop);
	            return G_SOURCE_REMOVE;
				break;
			case US_DONE_FAILED:
				syslog(LOG_NOTICE, "OTA is done, no need to reboot");
				attempt_done();
	            data->res = 0;				
	            g_main_loop_quit(data->loop);
	            return G_SOURCE_REMOVE;
				break;

			default:
				break;

		}

        // build hawkBit get tasks URL
        //g_autofree gchar *get_tasks_url = build_api_url("/%s/controller/v1/%s", hawkbit_config->tenant_id, hawkbit_config->controller_id);
        g_autofree gchar *get_tasks_url = build_api_url("/v1/campaigns/speaker/deployment");
        GError *error = NULL;
        JsonParser *json_response_parser = NULL;

//		syslog(LOG_NOTICE, "Checking for new software...get_tasks_url[%s]",get_tasks_url);

	//	g_autofree gchar get_tasks_url_new[200];
	//	strcpy(get_tasks_url_new, "-v --cacert 3rdparty_infra_cert_chain.pem --cert client.crt --key client.key  https://172.16.69.103/v1/campaigns/speaker/deployment");
	//	syslog(LOG_NOTICE, "Checking for new software...get_tasks_url[%s]",get_tasks_url_new);

		size_t fails;

		fails = get_fail_attempts();

		syslog(LOG_NOTICE, "So far fails count[%d]",fails);

///////////////////////////////////////////////
		update_current_version();

		if (FALSE == check_keys_certs()){
			data->res = 13;
			recordLastFailedTime("cert Missing ");
			g_main_loop_quit(data->loop);
			return G_SOURCE_REMOVE;	
		}

		if (TRUE == if_wait_for_last_step()){
			data->res = 10;
			//recordLastFailedTime("waiting for last step ");
			g_main_loop_quit(data->loop);
			return G_SOURCE_REMOVE;
		}

		if (TRUE == if_in_progress()) {
			data->res = 11;
			recordLastFailedTime("previous is in progress ");
			g_main_loop_quit(data->loop);
			return G_SOURCE_REMOVE;
		}

		if (FALSE == if_already_time()){
			data->res = 12;
			recordLastFailedTime("not time yet ");
			g_main_loop_quit(data->loop);
			return G_SOURCE_REMOVE;
		}

		syslog(LOG_NOTICE, "Checking for new software...get_tasks_url[%s]",get_tasks_url);

		int status = rest_request(GET, get_tasks_url, NULL, &json_response_parser, &error, FALSE);

        if (200 == status) {
			syslog(LOG_NOTICE, "Response status code: %d", status);
			attempt_start();
			recordLastCheckTime();

            if (json_response_parser) {
                // json_root is owned by the JsonParser and should never be modified or freed.
                JsonNode *json_root = json_parser_get_root(json_response_parser);
                g_autofree gchar *str = json_to_string(json_root, TRUE);
                syslog(LOG_NOTICE, "Deployment response: %s\n", str);

                // get hawkbit sleep time (how often should we check for new software)
                //hawkbit_interval_check_sec = json_get_sleeptime(json_root);
                //long version = json_get_version(json_root);
                //syslog(LOG_NOTICE, "version = %d", version);

				upgradeState = US_DOWNLOAD;
				downloadStart = get_time();
                process_deployment(json_root, &error);
                g_object_unref(json_response_parser);
            }
			else{
				recordLastFailedTime("could not parse jason ");
				upgradeState = US_DONE_FAILED;
			}

            if (error) {
                    syslog(LOG_NOTICE, "process_deployment Error: %s", error->message);
            }
        }else if (204 == status) { // successfully connected back-end, no update needed.
            syslog(LOG_NOTICE, "Response status code: %d", status);
			recordLastCheckTime();
            if (error) {
                syslog(LOG_NOTICE, "HTTP Error: %s", error->message);
            }
			recordLastFailedTime("successful check, no update needed ");
			upgradeState = US_DONE_FAILED;

        } else if (0 == status) {
            syslog(LOG_NOTICE, "Response status code: %d", status);
            if (error) {
                syslog(LOG_NOTICE, "HTTP Error: %s", error->message);
            }
			if (++zero_response_retry >= MAX_RETRY_ON_ZERO_RESPONSE) {
				recordLastFailedTime("Could not connect to backend");
	        	upgradeState = US_DONE_FAILED;
			}
        } else { // could not successfully connect to back-end, need to try again.
			syslog(LOG_NOTICE, "Response status code: %d", status);
			recordLastFailedTime("Could not connect to backend");
        	upgradeState = US_DONE_FAILED;
        }
        g_clear_error(&error);

        return G_SOURCE_CONTINUE;
}

int hawkbit_start_service_sync()
{
        GMainContext *ctx;
        ClientData cdata;
        GSource *timeout_source = NULL;
        int res = 0;

        ctx = g_main_context_new();
        cdata.loop = g_main_loop_new(ctx, FALSE);
		
		openlog ("rauc", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

        timeout_source = g_timeout_source_new(6000);   // pull every second
        g_source_set_name(timeout_source, "Add timeout");
        g_source_set_callback(timeout_source, (GSourceFunc) hawkbit_pull_cb, &cdata, NULL);
        g_source_attach(timeout_source, ctx);
        g_source_unref(timeout_source);

#ifdef WITH_SYSTEMD


        GSource *event_source = NULL;
        sd_event *event = NULL;
        res = sd_event_default(&event);
        if (res < 0)
                goto finish;
        // Enable automatic service watchdog support
        res = sd_event_set_watchdog(event, TRUE);
        if (res < 0)
                goto finish;

        event_source = sd_source_new(event);
        if (!event_source) {
                res = -ENOMEM;
                goto finish;
        }

        // attach systemd source to glib mainloop
        res = sd_source_attach(event_source, cdata.loop);
        if (res < 0)
                goto finish;

        sd_notify(0, "READY=1\nSTATUS=Init completed, start polling HawkBit for new software.");
#endif

        g_main_loop_run(cdata.loop);

        res = cdata.res;

#ifdef WITH_SYSTEMD
        sd_notify(0, "STOPPING=1\nSTATUS=Stopped polling HawkBit for new software.");
#endif

#ifdef WITH_SYSTEMD
finish:
        g_source_unref(event_source);
        g_source_destroy(event_source);
        sd_event_set_watchdog(event, FALSE);
        event = sd_event_unref(event);
#endif
        g_main_loop_unref(cdata.loop);
        g_main_context_unref(ctx);
        if (res < 0)
                g_warning("Failure: %s\n", strerror(-res));

        return res;
}



