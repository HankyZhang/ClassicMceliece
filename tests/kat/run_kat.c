#include <stdio.h>
#include <stdlib.h>

// Provided by our KEM module
void run_kat_file(const char *req_path, const char *rsp_path);

int main(void) {
#ifdef KAT_DATA_DIR
    const char *dir = KAT_DATA_DIR;
#else
    const char *dir = getenv("KAT_DATA_DIR");
    if (!dir) dir = "tests/kat/data";
#endif
    char req_path[512];
    snprintf(req_path, sizeof(req_path), "%s/kat_kem.req", dir);
    run_kat_file(req_path, "our_kat_output.rsp");
    return 0;
}



