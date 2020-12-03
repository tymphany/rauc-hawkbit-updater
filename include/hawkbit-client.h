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
 */

#ifndef __HAWKBIT_CLIENT_H__
#define __HAWKBIT_CLIENT_H__

#include <glib.h>
#include <glib/gtypes.h>
#include <stdio.h>
struct config;

#define HAWKBIT_USERAGENT                 "rauc-hawkbit-c-agent/1.0"
#define DEFAULT_CURL_REQUEST_BUFFER_SIZE  512
#define DEFAULT_SLEEP_TIME_SEC            60 * 60 * 24   // 1 day
#define DEFAULT_CURL_DOWNLOAD_BUFFER_SIZE 64 * 1024 // 64KB

extern gboolean volatile force_check_run;  /**< force software check */
extern gboolean run_once;                  /**< only run software check once and exit */

/**
 * @brief HTTP methods.
 */
enum HTTPMethod {
        GET,
        HEAD,
        PUT,
        POST,
        PATCH,
        DELETE
};

/**
 * @brief struct containing the payload and size of REST body.
 */
struct rest_payload {
        gchar *payload;               /**< string representation of payload */
        size_t size;                  /**< size of payload */
};

/**
 * @brief struct containing Curl write callback context.
 */
struct get_binary {
        FILE *fp;                     /**< filepointer to download file */
        gint64 filesize;              /**< expected file size of download file */
        gint64 written;               /**< number of bytes written to download file */
        GChecksum *checksum;          /**< checksum of download file */
		gchar* status;
};

/**
 * @brief struct containing the checksum of downloaded file.
 */
struct get_binary_checksum {
        gchar *checksum_result;       /**< checksum as string */
        GChecksumType checksum_type;  /**< checksum type. See also https://developer.gnome.org/glib/stable/glib-Data-Checksums.html#GChecksumType */
};

/**
 * @brief struct containing
 */
struct artifact {
		gchar* response_id;
		gchar* state;
		gchar* status;
		gchar* action;

		gchar* artifact_id;
        gchar* sha256;
        gint64 size;
        gchar* name;
        gchar* downloadUrl;
        gchar* filetype;
		gchar* signedDigest;

		gchar* version;
		//gboolean* forced_update;
};

/**
 * @brief struct containing the new downloaded file.
 */
struct on_new_software_userdata {
        GSourceFunc install_progress_callback;  /**< callback function to be called when new progress */
        GSourceFunc install_complete_callback;  /**< callback function to be called when installation is complete */
        gchar *file;                            /**< downloaded new software file */
};

/**
 * @brief struct containing the result of the installation.
 */
struct on_install_complete_userdata {
        gboolean install_success;               /**< status of installation */
};

void hawkbit_init(struct config *config, GSourceFunc on_install_ready);
int hawkbit_start_service_sync();
gboolean hawkbit_progress(const gchar *msg);
gboolean install_complete_cb(gpointer ptr);

#endif // __HAWKBIT_CLIENT_H__
