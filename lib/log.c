/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "log.h"

#include <string.h>

#define OSSAPIS_LOG_BUF_LEN     2048

static char osslapis_log_buf[OSSAPIS_LOG_BUF_LEN];

const char *osslapis_ossl_log_error(void)
{
    const char *file = NULL;
    const char *func = NULL;
    const char *data = NULL;
    const char *reason = NULL;
    int line = 0;

    reason = ERR_reason_error_string(ERR_get_error());
    ERR_get_error_all(&file, &line, &func, &data, NULL);
    if (data != NULL) {
        snprintf(osslapis_log_buf, sizeof(osslapis_log_buf), "%s(%s:%d %s): %s",
                reason, file, line, func, data);
    }

    return osslapis_log_buf;
}
