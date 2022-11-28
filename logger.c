#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include "acmonitor.h"

#define LOG_FILE "file_logging.log"

FILE *fopen(const char *path, const char *mode) 
{
	

	// log_entry->access_type = 1;
	// printf("%d", log_entry->access_type);

	// 1. Check for access depending on mode selected, check what to write on entry
	// 2. Check if fopen, fwrite works as it is
	// 3. Implement md5 for file fingerprint using openssl library

	// Gia thn epomenh askhsh vres tropo na xrhsimopoieis mono encrypt decrypt kai na
	// kaleitai aftomata to keygen -> trekse to sto makefile apeftheias


	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);



	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	// TODO: Check cases for invalid modes
	// Create log_entry
	entry* log_entry = (entry*)malloc(sizeof(entry));
	log_entry->uid = getuid();
	memcpy(log_entry->file, path, strlen(path));

	// Get timestamp
	time_t timestamp = time(NULL);
	log_entry->timestamp = timestamp;
	log_entry->date = *localtime(&timestamp);

	if(strcmp(mode, "r")==0 || strcmp(mode, "r+")){
		log_entry->access_type = F_OPEN;
	}
	else{
		if(access(path, F_OK) == 0){
			if(strcmp(mode, "w")==0 || strcmp(mode, "w+")){
				log_entry->access_type = F_DELETE;
			}
			else{
				log_entry->access_type = F_OPEN;
			}
		}
		else{
			log_entry->access_type = F_CREATE;
		}
	}

	// TODO: Create fingerprints using MD5
	if(original_fopen_ret == NULL){
		log_entry->action_denied=1;
	}
	else{
		log_entry->action_denied=0;
		memcpy(log_entry->fingerprint, "fingerprint", strlen("fingerprint"));
	}


	printf("\nuid:%d\nfile:%s\ntimestamp:%sdate:%d-%d-%d\n", log_entry->uid,
		log_entry->file, ctime(&log_entry->timestamp),
		log_entry->date.tm_mday, log_entry->date.tm_mon+1, log_entry->date.tm_year+1900);

	// Open log file with initial fopen
	FILE* log_file = (*original_fopen)(LOG_FILE, "a");
	// ...

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	return original_fwrite_ret;
}


void add_log_entry(entry* log_entry){
	FILE *(*original_fopen)(const char*, const char*);
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	FILE* log_file = (*original_fopen)(LOG_FILE, "a");
	// if((*original_fwrite(log_entry,)))
	fclose(log_file);


	// original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
}