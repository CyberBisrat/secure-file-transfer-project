#include "types.h"

#ifndef seq_h
#define seq_h

extern seqnum seq_num;

bool is_wraparound();
seqnum inc_seqnum();
unsigned char *seqnum_to_uc();

#endif
