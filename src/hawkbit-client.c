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

#include "config-file.h"
#include "json-helper.h"
#ifdef WITH_SYSTEMD
#include "sd-helper.h"
#endif

#include "hawkbit-client.h"

#define FILE_DOWNLOAD_CHECKPOINTS_NUM         (10)
#define FILE_DOWNLOAD_DONE_ALL_IN_ALL_PERCENT (75)
#define FILE_DOWNLOAD_CHECKPOINTS_PERCENT_STEP           (100 / FILE_DOWNLOAD_CHECKPOINTS_NUM)
#define FILE_DOWNLOAD_ALL_IN_ALL_PERCENT_PER_CHECKPOINT (FILE_DOWNLOAD_DONE_ALL_IN_ALL_PERCENT / FILE_DOWNLOAD_CHECKPOINTS_NUM)
#define MAX_TIME (0xFFFFFFFF)
#define CHECK_INTERVALS_SEC (30)
#define MIN_INTERVAL_BETWEEN_CHECKS_SEC 1//(60 * 60 * 24)
#define APPARENTLY_CRASHED_LAST_ATTEMPT (60 * 60 * 24)

gboolean volatile if_attempt_done = FALSE;

gboolean run_once = FALSE;
gboolean volatile force_check_run = FALSE;

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
static long sleep_time_sec = 0;
static long last_run_sec = 0;

static const char *pCertFile   = "/etc/rauc-hawkbit-updater/ota_access/client.crt";
static const char *pCACertFile = "/etc/rauc-hawkbit-updater/ota_access/3rdparty_infra_cert_chain.pem";

static const char *pKeyName = "/etc/rauc-hawkbit-updater/ota_access/client.key";
static const char *pKeyType = "PEM";

static gboolean checkPoints[FILE_DOWNLOAD_CHECKPOINTS_NUM] = {FALSE};

static gboolean feedback_progress(const gchar *url, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, GError **error, const gchar *finalResult);

static void recordLastCheckTime()
{
	g_autofree gchar *msg = NULL;

	msg = g_strdup_printf("date %s > /persist/factory/rauc-hawkbit-updater/lastCheck", "+%s");

	system(msg);
}

static gboolean attempt_done()
{
	//remove("/persist/factory/rauc-hawkbit-updater/now");
	//return TRUE;
}

static gboolean ifItIsAlreadyTime()
{
	FILE * fp;
	size_t lastCheck = 0;
	size_t now_prev = 0;
	size_t now = 0;
	char * temp = NULL;
	size_t len = 0;
	ssize_t read;
	g_autofree gchar *msg = NULL;

	if( access("/persist/factory/rauc-hawkbit-updater/lastCheck", 0 ) == 0 ) {

		g_debug("We have ota check history");

		fp = fopen("/persist/factory/rauc-hawkbit-updater/lastCheck", "r");
		if (fp == NULL){
			g_critical("Cannot open ota last check even though it exists");
			return TRUE;
		}

		if ((read = getline(&temp, &len, fp)) != -1) {
			lastCheck = atoi(temp);
			g_debug("Last|%d|", lastCheck);
		}

		fclose(fp);
	}
	else {
		g_debug("We do not have last check");
		return TRUE;
	}

	if( access("/persist/factory/rauc-hawkbit-updater/now", 0 ) == 0 ) {

		fp = fopen("/persist/factory/rauc-hawkbit-updater/now", "r");
		if (fp == NULL){
			g_critical("We have last atempt not finished but cannot open ota last attempt even though it exists");
			return TRUE;
		}

		if ((read = getline(&temp, &len, fp)) != -1) {
			now_prev = atoi(temp);
			g_debug("We have last atempt not finished |%d|", now_prev);
		}

		fclose(fp);
	}
	
	msg = g_strdup_printf("date %s > /persist/factory/rauc-hawkbit-updater/now", "+%s");
	system(msg);
	
	fp = fopen("/persist/factory/rauc-hawkbit-updater/now", "r");
	if (fp == NULL){
		g_critical("Cannot open now even though it exists");
		return TRUE;
	}
	
	if ((read = getline(&temp, &len, fp)) != -1) {
		now = atoi(temp);
		g_debug("We have last atempt not finished |%d|", now);
	}
	
	fclose(fp);

	g_debug("Seconds since last check passed %d", now - lastCheck);

	g_debug("now[%d], now_prev[%d], lastCheck[%d]", now, now_prev, lastCheck);

	if ((now - lastCheck > MIN_INTERVAL_BETWEEN_CHECKS_SEC) && ((0 == now_prev) || ((now - now_prev) > APPARENTLY_CRASHED_LAST_ATTEMPT)))
	{
		g_debug("It is time already");
		return TRUE;
	}
	else
	{
		g_debug("It is not time yet");
		return FALSE;
	}

}

static void send_wait_for_reboot_message()
{
	g_autofree gchar *msg = NULL;

	//adk-message-send 'connectivity_wifi_enable {}'

	msg = g_strdup_printf("adk-message-send 'system_mode_management {name:\"ota::Wait4Reboot\"}'");
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

	g_debug("Current version %s", string);

	//return G_SOURCE_CONTINUE;

	sprintf(currentVersion, "%s", string);
}

static gboolean get_certificate_against_chain_check_result()
{
	FILE *f = fopen("/etc/rauc-hawkbit-updater/code_signing_cert_against_intermediate_result", "rb");
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, 1, fsize, f);
	fclose(f);

	string[fsize] = 0;

	return (0 == strncmp(string, "signingCertificate.crt: OK", strlen("signingCertificate.crt: OK")));
}

static gboolean get_signature_check_result()
{
	FILE *f = fopen("/etc/rauc-hawkbit-updater/sig_check_result", "rb");
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, 1, fsize, f);
	fclose(f);

	string[fsize] = 0;

	return (0 == strncmp(string, "Verified OK", strlen("Verified OK")));
}

static gboolean get_recovery_result()
{
	FILE *f = fopen("/etc/rauc-hawkbit-updater/recovery_result", "rb");
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, 1, fsize, f);
	fclose(f);

	string[fsize] = 0;

	return (0 == strncmp(string, "OTA success", strlen("OTA success")));
}

static gboolean reset_fail_attempts()
{
	remove("/persist/factory/rauc-hawkbit-updater/fails");
	return TRUE;
}

static size_t set_fail_attempts(size_t attempts)
{
	g_autofree gchar *msg;

	remove("/persist/factory/rauc-hawkbit-updater/fails");
	msg = g_strdup_printf("echo \"%d\" > /persist/factory/rauc-hawkbit-updater/fails", attempts);
	system(msg);
	g_debug("Set fails attemps count to %d", attempts);
	return 0;
}

static size_t get_fail_attempts()
{
	if( access("/persist/factory/rauc-hawkbit-updater/fails", 0 ) == 0 ) {

		g_debug("We have fail hystory");

		FILE * fp;
		char * fails = NULL;
		size_t failsCount = 0;
		size_t len = 0;
		ssize_t read;

		fp = fopen("/persist/factory/rauc-hawkbit-updater/fails", "r");
		if (fp == NULL){
			g_critical("Cannot open fails file even though it exists");
			exit(EXIT_FAILURE);
		}

		if ((read = getline(&fails, &len, fp)) != -1) {
			failsCount = atoi(fails);
			g_debug("Current fails count |%s|%d|", fails, failsCount);
		}
		else {
			g_critical("Cannot read fails count");
			exit(EXIT_FAILURE);
		}
		fclose(fp);

		return failsCount;
	}
	else {
		g_debug("We do not have fail history");
		return 0;
	}
}

static gboolean check_if_inprogress()
{
	if( access("/persist/factory/rauc-hawkbit-updater/inprogress", 0 ) == 0 ) {

		g_debug("Update is still in progress");

		FILE * fp;
		char * version = NULL;
		char * statusUrl = NULL;
		size_t len = 0;
		ssize_t read;

		fp = fopen("/persist/factory/rauc-hawkbit-updater/inprogress", "r");
		if (fp == NULL){
			g_critical("Cannot open inprogress file even though it exists");
			exit(EXIT_FAILURE);
		}

		if ((read = getline(&version, &len, fp)) != -1) {
			//printf("Retrieved line of length %zu:\n", read);
			g_debug("Current SW version: %s       Inprogress SW version: %s", currentVersion, version);

			if (0 == strcmp(version, currentVersion)){
				g_debug("Update has been finalized, we report to server that it is done");

				if ((read = getline(&statusUrl, &len, fp)) != -1) {
								//printf("Retrieved line of length %zu:\n", read);

								statusUrl[strlen(statusUrl)-1] = '\0';
				}
				else {
					g_critical("Cannot read statusUrls");
					exit(EXIT_FAILURE);
				}

				feedback_progress(statusUrl, "SUCCESS",   100, "", "", "", "", NULL, "SUCCESS");
				remove("/persist/factory/rauc-hawkbit-updater/inprogress");
			}
			else {
				g_debug("Update has not been finilized, pending for reboot as a last step");
			}
		}
		else {
			g_critical("Cannot read expected inprogress sw version");
			exit(EXIT_FAILURE);
		}
		fclose(fp);

		return TRUE;
	}
	else {
		g_debug("No update in progress, proceed to polling");
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
		//g_debug("curl_write_to_file_cb: size:%d, nmemb:%d\n", size, nmemb);

		GError *error = NULL;

        size_t written = fwrite(ptr, size, nmemb, data->fp);

        double percentage;

        data->written += written;
        if (data->checksum) {
                g_checksum_update(data->checksum, ptr, written);
        }

		percentage = (double) data->written / data->filesize * 100;

        g_debug("curl_write_to_file_cb: bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);

		for (int ii = 9; ii >= 0; ii--)
		{
			if (!checkPoints[ii] && (percentage > (ii+1) * FILE_DOWNLOAD_CHECKPOINTS_PERCENT_STEP))
			{
				checkPoints[ii] = TRUE;

				//char buf[100];
				//sprintf(buf, "Bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);

				g_autofree gchar *msg = g_strdup_printf("Bytes downloaded: %ld / %ld (%.2f %%)", data->written, data->filesize, (double) percentage);

				// The downloading is done is 80% of all in all progress
				feedback_progress(data->status, "DOWNLOADING", (ii + 1) * (FILE_DOWNLOAD_ALL_IN_ALL_PERCENT_PER_CHECKPOINT), "Download details", msg, "", "", error, "");
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
                g_critical("Failed to expand buffer");
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

        g_debug("[%s]: method[%s] url[%s]", __FUNCTION__, HTTPMethod_STRING[method], url);

        // init response buffer
        fetch_buffer.payload = g_malloc0(DEFAULT_CURL_REQUEST_BUFFER_SIZE);
        if (fetch_buffer.payload == NULL) {
                g_critical("Failed to expand buffer");
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
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

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
                g_debug(">>>>>>Request body: %s\n", postdata);
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

		//g_debug("res[%d] http_code: %ld  fetch_buffer.size[%d]\n", res, http_code, fetch_buffer.size);

        if (res == CURLE_OK && http_code == 200) {
                if (jsonResponseParser && fetch_buffer.size > 0) {
                        JsonParser *parser = json_parser_new_immutable();
                        if (json_parser_load_from_data(parser, fetch_buffer.payload, fetch_buffer.size, error)) {
                                *jsonResponseParser = parser;
                        } else {
                                g_object_unref(parser);
                                g_critical("Failed to parse JSON response body. status: %ld\n", http_code);
                        }
                }
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
                // libcurl was able to complete a TCP connection to the origin server, but did not receive a timely HTTP response.
                http_code = 524;
                g_set_error(error,
                            1,                    // error domain
                            http_code,
                            "HTTP request timed out: %s",
                            curl_easy_strerror(res));
        } else {
                g_set_error(error,
                            1,                    // error domain
                            http_code,
                            "HTTP request failed: %s",
                            curl_easy_strerror(res));
        }

        //g_debug("Response body: %s\n", fetch_buffer.payload);

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
						json_builder_set_member_name(builder, "final");
			        	json_builder_add_string_value(builder, finalResult);
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
 * @brief Send progress feedback to hawkBit.
 */
static gboolean feedback_progress(const gchar *url, const gchar *state, gint progress, const gchar *value1_name, const gchar *value1, const gchar *value2_name, const gchar *value2, GError **error, const gchar *finalResult)
{
        JsonBuilder *builder = json_builder_new();

        json_build_status(builder, state, progress, value1_name, value1, value2_name, value2, finalResult);

        int status = rest_request(PUT, url, builder, NULL, error, TRUE);
        //g_debug("feedback_progress: %d, URL: %s", status, url);
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

            //    g_debug("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!: %d.%d.%d", v1, v2, v3);

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
                //g_debug("sleep time: %s %ld\n", sleeptime_str, poll_sleep_time);
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
        //g_clear_pointer(action_id, g_free);
        //gpointer ptr = action_id;
        //action_id = NULL;
       // g_free(ptr);

        if (g_file_test(hawkbit_config->bundle_download_location, G_FILE_TEST_EXISTS)) {
                if (g_remove(hawkbit_config->bundle_download_location) != 0) {
                        g_critical("Failed to delete file: %s", hawkbit_config->bundle_download_location);
                }
        }
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

		g_debug("Start downloading: %s\n\r", artifact->downloadUrl);

        // setup checksum
        struct get_binary_checksum checksum = { .checksum_result = NULL, .checksum_type = G_CHECKSUM_SHA256 };

        feedback_progress(artifact->status, "DOWNLOADING", 2, "Info", "About to start downloading", "", "", error, "");

        // Download software bundle (artifact)
        gint64 start_time = g_get_monotonic_time();
        gint status = 0;
        gboolean res = get_binary(artifact->downloadUrl, hawkbit_config->bundle_download_location,
                                  artifact->size, &checksum, &status, &error, artifact->status);
        gint64 end_time = g_get_monotonic_time();

        if (!res) {
                msg = g_strdup_printf("Download failed: %s Status: %d", error->message, status);
                g_clear_error(&error);
                g_critical("%s", msg);
                feedback_progress(artifact->status, "SILENT_FAILURE", 6, "Failure details", msg, "", "", error, "");
                goto down_error;
        }

		g_debug("Binary downloading res[%s]",(res) ? "SUCCESS" : "FAIL");

        // notify hawkbit that download is complete
        msg = g_strdup_printf("Download complete %.2f MB/s",
                              (artifact->size / ((double)(end_time - start_time) / 1000000)) / (1024 * 1024));

        g_debug("%s", msg);

		feedback_progress(artifact->status, "DOWNLOADED", 75, "Details", "File was fully downloaded", "", "", error, "");

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 80, "Details", "Starting file validating procedure", "", "", error, "");

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
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", msg, "More details", msgDetails, error, "FAIL");
			} else {
				msg = g_strdup_printf("CRC check failed but we will try again");
				set_fail_attempts(fails+1);
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", msg, "More details", msgDetails, error, "");
			}
            g_critical("%s", msg);
            goto down_error;
        }


		msg = g_strdup_printf("Checksum check passed");
		g_debug("%s",msg);

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 83, "Details", msg, "", "", error, "");

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	0. Save certificates and asignature to file system
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		msg = g_strdup_printf("echo \"%s\" > signed_digest_base64", artifact->signedDigest);
		system(msg);
		msg = g_strdup_printf("echo \"%s\" > signingCertificate.crt", artifact->signingCertificate);
		system(msg);
		msg = g_strdup_printf("echo \"%s\" > signingIntermediateCA.crt", artifact->signingIntermediateCA);
		system(msg);

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	1. Validating the authenticity of signingCertificate against signingIntermediateCA
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		msg = g_strdup_printf("openssl verify -verbose -CAfile signingIntermediateCA.crt signingCertificate.crt > /etc/rauc-hawkbit-updater/code_signing_cert_against_intermediate_result");
		system(msg);

		if(!get_certificate_against_chain_check_result()) {

			fails = get_fail_attempts();

			if (fails >=2) {
				msg = g_strdup_printf("Validating the authenticity of signingCertificate against signingIntermediateCA failed and we have reached an attempts limit. Stop campaign.");
				reset_fail_attempts();
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", msg, "Signing Certificate", artifact->signingCertificate, error, "FAIL");
			} else {
				msg = g_strdup_printf("Validating the authenticity of signingCertificate against signingIntermediateCA failed but we will try again");
				set_fail_attempts(fails+1);
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", msg, "Signing Certificate", artifact->signingCertificate, error, "");
			}
			g_critical("%s", msg);
			goto down_error;
		}

		msg = g_strdup_printf("Validating the authenticity of signingCertificate against signingIntermediateCA failed but we will try again");
		g_debug("%s",msg);

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 83, "Details", msg, "", "", error, "");

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	2. Verify rootCA included in signingIntermediateCA (it is the first cert in the chain (at the top)) against rootCA pinned in firmware. This is just a string comparison.
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	//TODO

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	3. signingCertificate.crt -> code_signing_certificate_public_key.pem
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	msg = g_strdup_printf("openssl x509 -pubkey -noout -in signingCertificate.crt > code_signing_certificate_public_key.pem");
	system(msg);

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	4. Check signature
*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		msg = g_strdup_printf("openssl dgst -sha256 -binary -out ota.raucb.bin.sha256 %s", hawkbit_config->bundle_download_location);
		system(msg);
		msg = g_strdup_printf("base64 --decode signed_digest_base64 > signature.bin");
		system(msg);
		msg = g_strdup_printf("openssl dgst -sha256 -verify code_signing_certificate_public_key.pem -signature signature.bin ota.raucb.bin.sha256 > /etc/rauc-hawkbit-updater/sig_check_result");
		system(msg);

		if (!get_signature_check_result()) {

			fails = get_fail_attempts();

			if (fails >=2) {
				msg = g_strdup_printf("Digital signature verification failed and we reached an attempts limit. Stop campaign.");
				reset_fail_attempts();
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", msg, "Digital Signature", artifact->signedDigest, error, "FAIL");
			} else {
				msg = g_strdup_printf("Digital signature verification failed but we will try again");
				set_fail_attempts(fails+1);
				feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", msg, "Digital Signature", artifact->signedDigest, error, "");
			}
			g_critical("%s", msg);
            goto down_error;
		}

		g_debug("Digital signature check SUCCESS");

		g_free(checksum.checksum_result);
        process_artifact_cleanup(artifact);
		process_deployment_cleanup();

		feedback_progress(artifact->status, "VALIDATING_PACKAGE", 84, "Details", "Digital signature verification passed", "", "", error, "");
		feedback_progress(artifact->status, "INSTALLING",85, "Details", "Memory bank flashing start", "", "", error, "");

		msg = g_strdup_printf("/etc/factory-test/r1/updateOTA.sh ota.raucb > /etc/rauc-hawkbit-updater/recovery_result ", artifact->signedDigest);
		system(msg);

		if (!get_recovery_result()) {
			feedback_progress(artifact->status, "SILENT_FAILURE", 83, "Failure details", "Flashing memory bank failed", "", "", error, "");
            g_critical("%s", msg);
            status = -4;
            goto down_error;
		}

		feedback_progress(artifact->status, "INSTALLING",86, "Details", "Memory bank flashing done", "", "", error, "");
		feedback_progress(artifact->status, "PENDING_REBOOT", 87, "Details", "Now we wait for system reboot", "", "", error, "");

		//feedback_progress(artifact->status, "EXECUTING", 90, "", "", "", "", NULL, FALSE, "");
		//feedback_progress(artifact->status, "INSTALLING",95, "", "", "", "", NULL, FALSE, "");
		//feedback_progress(artifact->status, "SUCCESS",   100, "", "", "", "", NULL, TRUE, "SUCCESS");

		//sprintf(buf, "touch /etc/rauc-hawkbit-updater/inprogress");

		msg = g_strdup_printf("mkdir -p /persist/factory/rauc-hawkbit-updater/", artifact->version, artifact->status);
		system(msg);

		msg = g_strdup_printf("echo \"%s\n%s\" > /persist/factory/rauc-hawkbit-updater/inprogress", artifact->version, artifact->status);
		//sprintf(buf, "echo \"%s\n%s\" > /etc/rauc-hawkbit-updater/inprogress", artifact->version, artifact->status);
		system(msg);

		msg = g_strdup_printf("echo \"\" > /data/ota-successed");
		system(msg);

		send_wait_for_reboot_message();

        g_free(checksum.checksum_result);
        process_artifact_cleanup(artifact);
		process_deployment_cleanup();
		if_attempt_done = TRUE;
        return NULL;
down_error:
        g_free(checksum.checksum_result);
        process_artifact_cleanup(artifact);
        process_deployment_cleanup();
		if_attempt_done = TRUE;
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

//        g_debug("New software ready for download. (Name: %s, Version: %s, Size: %" G_GINT64_FORMAT ", URL: %s)\n\r", artifact->name, artifact->version, artifact->size, artifact->downloadUrl);
//        g_autofree gchar *msg = g_strdup_printf("New software ready for download. (Name: %s, Version: %s, Size: %" G_GINT64_FORMAT ", URL: %s)", artifact->name, artifact->version, artifact->size, artifact->downloadUrl);
		g_autofree gchar *msg = g_strdup_printf("New software ready for download. (Name: %s, Version: %s, Size: %d)", artifact->name, artifact->version, artifact->size);

		g_debug("%s", msg);
//		g_debug(msg);

		feedback_progress(artifact->status, "NOT_STARTED", 0, "Info", msg, "Download URL", artifact->downloadUrl, ierror, "");

        // Check if there is enough free diskspace
        long freespace = get_available_space(hawkbit_config->bundle_download_location, &ierror);

		g_debug("[%s]: freespace available = %d", __FUNCTION__, freespace);

        if ((freespace == -1) || (freespace < artifact->size)) {
                g_autofree gchar *msg = g_strdup_printf("Not enough free space. File size: %" G_GINT64_FORMAT  ". Free space: %ld", artifact->size, freespace);
				g_propagate_error(error, ierror);
				feedback_progress(artifact->status, "SILENT_FAILURE", 0, "Failure details", msg, "", "", NULL, "");
				g_critical("%s", msg);
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
		if_attempt_done = TRUE;
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
        g_debug("#####cb");
        ClientData *data = user_data;

		if (if_attempt_done){
			attempt_done();
            data->res = 0;
            g_main_loop_quit(data->loop);
            return G_SOURCE_REMOVE;
        }

        if (++last_run_sec < sleep_time_sec)
                return G_SOURCE_CONTINUE;

        last_run_sec = 0;

        // build hawkBit get tasks URL
        //g_autofree gchar *get_tasks_url = build_api_url("/%s/controller/v1/%s", hawkbit_config->tenant_id, hawkbit_config->controller_id);
        g_autofree gchar *get_tasks_url = build_api_url("/v1/campaigns/speaker/deployment");
        GError *error = NULL;
        JsonParser *json_response_parser = NULL;

//		g_debug("Checking for new software...get_tasks_url[%s]",get_tasks_url);

	//	g_autofree gchar get_tasks_url_new[200];
	//	strcpy(get_tasks_url_new, "-v --cacert 3rdparty_infra_cert_chain.pem --cert client.crt --key client.key  https://172.16.69.103/v1/campaigns/speaker/deployment");
	//	g_debug("Checking for new software...get_tasks_url[%s]",get_tasks_url_new);

		size_t fails;

//		set_fail_attempts(1);

		fails = get_fail_attempts();

		g_debug("So far fails count[%d]",fails);

//		data->res = 13;
//		g_main_loop_quit(data->loop);
//		return G_SOURCE_REMOVE;

///////////////////////////////////////////////
		update_current_version();

		if (TRUE == check_if_inprogress()){
			data->res = 13;
			g_main_loop_quit(data->loop);
			return G_SOURCE_REMOVE;
		}

		if (FALSE == ifItIsAlreadyTime()){
			data->res = 13;
			g_main_loop_quit(data->loop);
			return G_SOURCE_REMOVE;
		}

		g_debug("Checking for new software...get_tasks_url[%s]",get_tasks_url);

		int status = rest_request(GET, get_tasks_url, NULL, &json_response_parser, &error, FALSE);

        if (status == 200) {
			g_debug("Response status code: %d", status);
			recordLastCheckTime();
			sleep_time_sec = MAX_TIME;
            if (json_response_parser) {
                // json_root is owned by the JsonParser and should never be modified or freed.
                JsonNode *json_root = json_parser_get_root(json_response_parser);
                g_autofree gchar *str = json_to_string(json_root, TRUE);
                g_debug("Deployment response: %s\n", str);

                // get hawkbit sleep time (how often should we check for new software)
                //hawkbit_interval_check_sec = json_get_sleeptime(json_root);
                //long version = json_get_version(json_root);
                //g_debug("version = %d", version);

                process_deployment(json_root, &error);
                g_object_unref(json_response_parser);
            }

            if (error) {
                    g_debug("process_deployment Error: %s", error->message);
            }
        }else if (status == 204) { // successfully connected back-end, no update needed.
            g_debug("Response status code: %d", status);
			recordLastCheckTime();
            if (error) {
                g_debug("HTTP Error: %s", error->message);
            }
			if_attempt_done = TRUE;

        } else {
        	if_attempt_done = TRUE;
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

        g_debug("#####5");

        timeout_source = g_timeout_source_new(1000);   // pull every second
        g_source_set_name(timeout_source, "Add timeout");
        g_source_set_callback(timeout_source, (GSourceFunc) hawkbit_pull_cb, &cdata, NULL);
        g_source_attach(timeout_source, ctx);
        g_source_unref(timeout_source);

        g_debug("#####6");

#ifdef WITH_SYSTEMD

        g_debug("#####7");

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

        g_debug("#####8");

        g_main_loop_run(cdata.loop);
        g_debug("#####9");

        res = cdata.res;

#ifdef WITH_SYSTEMD
        sd_notify(0, "STOPPING=1\nSTATUS=Stopped polling HawkBit for new software.");
#endif

        g_debug("#####10");
#ifdef WITH_SYSTEMD
finish:
        g_debug("#####11");
        g_source_unref(event_source);
        g_source_destroy(event_source);
        sd_event_set_watchdog(event, FALSE);
        event = sd_event_unref(event);
#endif
        g_debug("#####12");
        g_main_loop_unref(cdata.loop);
        g_main_context_unref(ctx);
        if (res < 0)
                g_warning("Failure: %s\n", strerror(-res));

        g_debug("#####13");

        return res;
}

