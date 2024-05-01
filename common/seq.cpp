#include "seq.h"
#include "types.h"
#include <signal.h>
#include <unistd.h>

seqnum seq_num = 0;

void check_wraparound() {
    if (seq_num > (SEQ_MAX_THRESHOLD))
        kill(getpid(), SIGUSR1);
}

seqnum inc_seqnum() {
    seq_num++;
    check_wraparound();
    return seq_num;
}

unsigned char *seqnum_to_uc() { return (unsigned char *)&seq_num; }
