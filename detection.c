/*
 * Copyright (C) agile6v
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define DETECTION_TARGETS "DETECTION_TARGETS"

#define MAXPATHLEN 4096
#define DETECTION_OK 0
#define DETECTION_ERROR -1

#define PER_CPU_SHARES 1024

#define SET_SUBSYSTEM_INFO(subsystem_info, value)                              \
    subsystem_info.data = strdup(value);                                       \
    subsystem_info.len  = strlen(value);

#define DETECTION_MIN(val1, val2) ((val1 > val2) ? (val2) : (val1))

#ifdef INJECT_DEBUG
#define DEBUG_LOG(...)                                                         \
    do {                                                                       \
        fprintf(stderr, "%s@%d: ", __FILE__, __LINE__);                        \
        fprintf(stderr, __VA_ARGS__);                                          \
        fprintf(stderr, "\n");                                                 \
    } while (0)
#else
#define DEBUG_LOG(...)
#endif

#define d_string(str)                                                          \
    {                                                                          \
        sizeof(str) - 1, (char *)str                                           \
    }

typedef long (*glibc_sysconf)(int name);

typedef struct {
    int   len;
    char *data;
} d_string_t;

typedef struct {
    d_string_t root;
    d_string_t path;
    d_string_t mount_point;
} cgroup_subsystem_info;

static cgroup_subsystem_info memory_subsystem;

static d_string_t memory_limit = d_string("/memory.limit_in_bytes");
static d_string_t memory_usage = d_string("/memory.usage_in_bytes");


static void __attribute__((destructor)) _fini();

static glibc_sysconf _orig_sysconf;
static int           detection_initialized;

static long orig_sysconf(int name)
{
    if (!_orig_sysconf) {
        _orig_sysconf = (glibc_sysconf)dlsym(RTLD_NEXT, "sysconf");
    }

    return _orig_sysconf(name);
}


static int set_subsystem_path(cgroup_subsystem_info *subsystem_info,
                              char *                 cgroup_path)
{
    int  len;
    char buf[MAXPATHLEN + 1];

    if (subsystem_info->root.len != 0 && cgroup_path != NULL) {
        if (strcmp(subsystem_info->root.data, "/") == 0) {
            len = subsystem_info->mount_point.len;
            if (strcmp(cgroup_path, "/") != 0) {
                len += strlen(cgroup_path);
            }

            if (len > MAXPATHLEN) {
                DEBUG_LOG("The length of the cgroup path exceeds the maximum "
                          "length of the path (%d) ",
                          MAXPATHLEN);
                return DETECTION_ERROR;
            }

            if (strcmp(cgroup_path, "/") != 0) {
                len = sprintf(buf, "%s%s", subsystem_info->mount_point.data,
                              cgroup_path);
            } else {
                len = sprintf(buf, "%s", subsystem_info->mount_point.data);
            }

            buf[len] = '\0';

            subsystem_info->path.data = strdup(buf);
            subsystem_info->path.len  = len;

        } else if (strcmp(subsystem_info->root.data, cgroup_path) == 0) {
            subsystem_info->path = subsystem_info->mount_point;
        }
    }

    return DETECTION_OK;
}

static void detection_free(cgroup_subsystem_info *subsystem)
{
    int skip = (subsystem->mount_point.data == subsystem->path.data) ? 1 : 0;

    if (!skip && subsystem->mount_point.data != NULL) {
        free(subsystem->mount_point.data);
        subsystem->mount_point.data = NULL;
    }

    if (subsystem->path.data != NULL) {
        free(subsystem->path.data);
        subsystem->path.data = NULL;
    }

    if (subsystem->root.data != NULL) {
        free(subsystem->root.data);
        subsystem->root.data = NULL;
    }
}

static int detection_init()
{
    int   mountid;
    int   parentid;
    int   major;
    int   minor;
    char *p;
    char  buf[MAXPATHLEN];
    char  tmproot[MAXPATHLEN];
    char  tmpmount[MAXPATHLEN];
    char  fstype[MAXPATHLEN];
    FILE *mntinfo = NULL;
    FILE *cgroup  = NULL;

    if (detection_initialized) {
        return DETECTION_OK;
    }

    /*
     * parse mountinfo file
     */
    mntinfo = fopen("/proc/self/mountinfo", "r");
    if (mntinfo == NULL) {
        DEBUG_LOG("Failed to open /proc/self/mountinfo, %s", strerror(errno));
        return DETECTION_ERROR;
    }

    while ((p = fgets(buf, MAXPATHLEN, mntinfo)) != NULL) {
        fstype[0] = '\0';

        char *s = strstr(p, " - ");
        if (s == NULL || sscanf(s, " - %s", fstype) != 1 ||
            strcmp(fstype, "cgroup") != 0) {
            continue;
        }

        if (strstr(p, "memory") != NULL) {
            int matched = sscanf(p, "%d %d %d:%d %s %s", &mountid, &parentid,
                                 &major, &minor, tmproot, tmpmount);
            if (matched == 6) {
                SET_SUBSYSTEM_INFO(memory_subsystem.root, tmproot);
                SET_SUBSYSTEM_INFO(memory_subsystem.mount_point, tmpmount);
            } else {
                DEBUG_LOG(
                    "Incompatible string containing cgroup and cpuset: %s", p);
            }
        } 
    }

    if (mntinfo != NULL) {
        fclose(mntinfo);
    }

    /*
     * parse cgroup file
     */
    cgroup = fopen("/proc/self/cgroup", "r");
    if (cgroup == NULL) {
        DEBUG_LOG("Failed to open /proc/self/cgroup, %s", strerror(errno));
        return DETECTION_ERROR;
    }

    while ((p = fgets(buf, MAXPATHLEN, cgroup)) != NULL) {
        char *controller;
        char *base;

        // Skip cgroup number
        strsep(&p, ":");

        // Get controller and base
        controller = strsep(&p, ":");
        base       = strsep(&p, "\n");

        if (controller != NULL) {
            if (strstr(controller, "memory") != NULL) {
                set_subsystem_path(&memory_subsystem, base);
            } 
        }
    }

    if (cgroup != NULL) {
        fclose(cgroup);
    }

    if (memory_subsystem.root.data == NULL || memory_subsystem.root.data == NULL) {
        DEBUG_LOG("Required cgroup subsystems not found");
        return DETECTION_ERROR;
    }

    detection_initialized = 1;

    return DETECTION_OK;
}



static int read_subsystem_file(const char *filename, char *value,
                               size_t value_len)
{
    FILE *  fp;
    int     ret;
    ssize_t len;

    fp = fopen(filename, "r");
    if (!fp) {
        DEBUG_LOG("Failed to open %s\n", filename);
        return DETECTION_ERROR;
    }

    len = getline(&value, &value_len, fp);
    if (len == DETECTION_ERROR) {
        ret = DETECTION_ERROR;
    } else {
        ret = DETECTION_OK;
    }

    fclose(fp);

    return ret;
}



static int read_memory_subsystem_info(cgroup_subsystem_info *subsystem,
                                   d_string_t *filename, long *value)
{
   
    int   ret;
    char  buf[MAXPATHLEN + 1];
    char  full_path[MAXPATHLEN + 1];

    if (subsystem->path.data == NULL) {
        return DETECTION_ERROR;
    }

    if ((subsystem->path.len + filename->len) > MAXPATHLEN) {
        DEBUG_LOG("The subsystem filename exceeds normal range (%d + %d).",
                  subsystem->path.len, filename->len);
        return DETECTION_ERROR;
    }

    sprintf(full_path, "%s%s", subsystem->path.data, filename->data);

    ret = read_subsystem_file(full_path, buf, MAXPATHLEN);
    if (ret == DETECTION_ERROR) {
        DEBUG_LOG("Failed to read file : %s.", full_path);
        return ret;
    }

    *value = atoi(buf);
 

    return DETECTION_OK;
}


static void _fini()
{
    DEBUG_LOG("Detection: fini.");
    detection_free(&memory_subsystem);
}

long sysconf(int name)
{
    
    if (!(name == _SC_PHYS_PAGES || name == _SC_AVPHYS_PAGES)) {
        return orig_sysconf(name);
    }
    int ret = 0;
    ret = detection_init();
    if (ret == DETECTION_ERROR) {
         return orig_sysconf(name);
    }
    if(name == _SC_PHYS_PAGES) {
	
	long memory = 0;
	ret = read_memory_subsystem_info(&memory_subsystem, &memory_limit,
                                      &memory);

	if (ret == DETECTION_ERROR) {
            return orig_sysconf(name);
        }
	long page_size = orig_sysconf(_SC_PAGESIZE);
	long pages = orig_sysconf(_SC_PHYS_PAGES);
	if(memory > (page_size * pages)) {
		return 	pages;
	}else {
		pages = memory /page_size;	
		return pages;
	}
    } else if(name == _SC_AVPHYS_PAGES) {
	long memory_use = 0;
	long memory = 0;
	ret = read_memory_subsystem_info(&memory_subsystem, &memory_limit,
                                      &memory);
	ret = read_memory_subsystem_info(&memory_subsystem, &memory_usage,
                                      &memory_use);
	
	if (ret == DETECTION_ERROR) {
            return orig_sysconf(name);
        }
	long page_size = orig_sysconf(_SC_PAGESIZE);
	long pages = orig_sysconf(_SC_PHYS_PAGES);
	if(memory > (page_size * pages)) {
		return orig_sysconf(name);
	} else {
		pages = (memory - memory_use)/ page_size;   
		return pages;
	}
    }
    
}
