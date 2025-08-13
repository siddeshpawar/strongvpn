/*
 * StrongVPN Logging System
 * Simple logging interface for post-quantum VPN implementation
 */

#ifndef LOGGER_H
#define LOGGER_H

// Log levels
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3

// Logging macros
#define LOG_DEBUG(fmt, ...) log_message(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_message(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_message(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

// Function declarations
void log_init(int level);
void log_message(int level, const char* format, ...);

#endif // LOGGER_H
