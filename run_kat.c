#include <stdio.h>

// Provided by our KEM module
void run_kat_file(const char *req_path, const char *rsp_path);

int main(void) {
    run_kat_file("mceliece6688128/kat_kem.req", "our_kat_output.rsp");
    return 0;
}



