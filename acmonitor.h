#ifndef ACMONITOR_H
#define ACMONITOR_H

#include <time.h>

enum file_access_type{
    F_CREATE=0,
    F_OPEN=1,
    F_WRITE=2,
    F_DELETE=3
};

typedef struct entry {

	int uid; /* user id (positive integer) */
	enum file_access_type access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t timestamp; /* file access time */

	char file[260]; /* filename (string) */
	char fingerprint[16]; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

} entry;

#endif