#include "errors.h"
#include <cxxabi.h>   // for __cxa_demangle
#include <dlfcn.h>    // for dladdr
#include <execinfo.h> // for backtrace
#include <iostream>
#include <openssl/err.h>
#include <sstream>
#include <stdio.h>
#include <string>

using namespace std;

#ifdef DEBUG
// https://gist.github.com/fmela/591333/0e8f9f123c87c1f234cd3050b2dac9c76185bdf1
string backtrace(int skip = 1) {
    void *callstack[128];
    const int nMaxFrames = sizeof(callstack) / sizeof(callstack[0]);
    char buf[1024];
    int nFrames = backtrace(callstack, nMaxFrames);

    ostringstream trace_buf;
    for (int i = skip; i < nFrames; i++) {
        Dl_info info;
        if (dladdr(callstack[i], &info)) {
            char *demangled = NULL;
            int status;
            demangled = abi::__cxa_demangle(info.dli_sname, NULL, 0, &status);
            snprintf(buf, sizeof(buf), "%-3d %0*p %s + %zd\n", i,
                     2 + sizeof(void *) * 2, callstack[i],
                     status == 0 ? demangled : info.dli_sname,
                     reinterpret_cast<char *>(callstack[i]) -
                         reinterpret_cast<char *>(info.dli_saddr));
            free(demangled);
        } else {
            snprintf(buf, sizeof(buf), "%-3d %0*p\n", i, 2 + sizeof(void *) * 2,
                     callstack[i]);
        }
        trace_buf << buf;
    }
    if (nFrames == nMaxFrames)
        trace_buf << "  [truncated]\n";
    return trace_buf.str();
}
#endif

void handle_errors(const char *error) {
#ifdef DEBUG
    ERR_print_errors_fp(stderr);
    cerr << backtrace(2) << endl;
    if (error != nullptr) {
        throw error;
    }
#endif
    throw "Error occurred.";
}
