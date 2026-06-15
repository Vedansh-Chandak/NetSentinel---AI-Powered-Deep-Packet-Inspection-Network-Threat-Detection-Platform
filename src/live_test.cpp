#include "live_capture.h"

int main()
{
    LiveCapture capture;

    capture.start("en0");

    return 0;
}