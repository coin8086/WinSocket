#include "Log.h"

Log::Level Log::level = Log::Level::Warning;

CRITICAL_SECTION Log::lock;

bool Log::init()
{
    return InitializeCriticalSectionAndSpinCount(&lock, 0);
}
