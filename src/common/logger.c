/*
 * StrongVPN Logging System Implementation
 * Simple logging with timestamps for post-quantum VPN
 */

#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

static int current_log_level = LOG_LEVEL_INFO;

void log_init(int level) {
    current_log_level = level;
}

void log_message(int level, const char* format, ...) {
    if (level < current_log_level) {
        return;
    }
    
    // Level strings
    const char* level_strings[] = {
        "DEBUG", "INFO", "WARN", "ERROR"
    };
    
    // Get current time
    time_t now;
    time(&now);
    struct tm* tm_info = localtime(&now);
    
    // Print timestamp and level
    printf("[%02d:%02d:%02d %s] ", 
           tm_info->tm_hour, 
           tm_info->tm_min, 
           tm_info->tm_sec,
           level_strings[level]);
    
    // Print formatted message
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
}
