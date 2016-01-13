/*
 * ecr_logger.h
 *
 *  Created on: Nov 9, 2012
 *      Author: velna
 */

#ifndef ECR_LOGGER_H_
#define ECR_LOGGER_H_

#include "ecrconf.h"
#include "ecr_rollingfile.h"

#ifndef LOG_MAX_LINE_SIZE
#define LOG_MAX_LINE_SIZE	8192
#endif

#define LOG_EMERG   0   /* system is unusable */
#define LOG_ALERT   1   /* action must be taken immediately */
#define LOG_CRIT    2   /* critical conditions */
#define LOG_ERR     3   /* error conditions */
#define LOG_WARNING 4   /* warning conditions */
#define LOG_NOTICE  5   /* normal but significant condition */
#define LOG_INFO    6   /* informational */
#define LOG_DEBUG   7   /* debug-level messages */

extern ecr_rfile_t ECR_LOG_FILE[1];

#ifdef DEBUG
#define L_DEBUG(fmt, ...)		ecr_logger_message(ECR_LOG_FILE, LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LP_DEBUG(data, size)	ecr_logger_print(ECR_LOG_FILE, LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, data, size)
#else
#define L_DEBUG(fmt, ...)
#define LP_DEBUG(fmt, ...)
#endif

#define L_INFO(fmt, ...)		ecr_logger_message(ECR_LOG_FILE, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define L_WARN(fmt, ...)		ecr_logger_message(ECR_LOG_FILE, LOG_WARNING, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define L_ERROR(fmt, ...)		ecr_logger_message(ECR_LOG_FILE, LOG_ERR, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#define LP_INFO(data, size)		ecr_logger_print(ECR_LOG_FILE, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, data, size)
#define LP_WARN(data, size)		ecr_logger_print(ECR_LOG_FILE, LOG_WARNING, __FILE__, __LINE__, __FUNCTION__, data, size)
#define LP_ERROR(data, size)	ecr_logger_print(ECR_LOG_FILE, LOG_ERR, __FILE__, __LINE__, __FUNCTION__, data, size)

#define L_LOG(level, fmt, ...)	ecr_logger_message(ECR_LOG_FILE, level, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define L_PRINTF(fmt, ...)      ecr_logger_printf(ECR_LOG_FILE, fmt, ##__VA_ARGS__)

#define L_MSG(fd, fmt, ...)     ecr_logger_message(fd, LOG_INFO, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

ecr_rfile_t * ecr_logger_init(const char* log_file);

ecr_rfile_t * ecr_logger_open(const char * log_file);

void ecr_logger_close(ecr_rfile_t *rf);

void ecr_logger_message(ecr_rfile_t *rf, int level, const char* file, int line, const char* function,
        const char* format, ...);

void ecr_logger_vmessage(ecr_rfile_t *rf, int level, const char* file, int line, const char* function,
        const char* format, va_list va);

void ecr_logger_printf(ecr_rfile_t *rf, const char* format, ...);

void ecr_logger_print(ecr_rfile_t *rf, int level, const char* file, int line, const char* function, const char *data,
        size_t size);

#endif /* ECR_LOGGER_H_ */
