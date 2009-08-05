#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <sys/resource.h>
#include <sys/capability.h>

#ifdef DEBUGP
#  define AUDIT(x, args...) do { printf("AUDIT: " x, ##args); } while (0)
#  define DEBUG(x, args...) do { printf("DEBUG: " x, ##args); } while (0)
#  define WARNING(x, args...) do { printf("WARNING: " x, ##args); } while (0)
#  define PERROR(x) do { perror(x); _exit(1); } while (0)
#  define ERROR(x, args...) do { fprintf(stderr,"ERROR: " x, ## args); _exit(1); } while (0)
#else
#  define AUDIT(x, args...) do {  } while (0)
#  define DEBUG(x, args...) do {  } while (0)
#  define WARNING(x, args...) do { } while (0)
#  define PERROR(x) do {  } while (0)
#  define ERROR(x, args...) do {  } while (0)
#endif

#define PARENT_DIR_PERMS (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP)
#define CALLER_UID 33
#define CALLER_GID 33

#define BUFSIZE 1024

#define TARGET_MIN_UID			1000
#define TARGET_MIN_GID			1000
#define TARGET_HARDLINK_PERMITTED	0
#define TARGET_SHELL_REQUIRED		1

const cap_value_t dropping_capabilities[] = {
        CAP_AUDIT_CONTROL,	CAP_LINUX_IMMUTABLE,	CAP_SYS_BOOT,
        CAP_AUDIT_WRITE,	CAP_MAC_ADMIN,		CAP_SYS_CHROOT,
        CAP_CHOWN,		CAP_MAC_OVERRIDE,	CAP_SYS_MODULE,
        CAP_DAC_OVERRIDE,	CAP_MKNOD,		CAP_SYS_NICE,
        CAP_DAC_READ_SEARCH,	CAP_NET_ADMIN,		CAP_SYS_PACCT,
        CAP_FOWNER,		CAP_NET_BIND_SERVICE,	CAP_SYS_PTRACE,
        CAP_FSETID,		CAP_NET_BROADCAST,	CAP_SYS_RAWIO,
        CAP_IPC_LOCK,		CAP_NET_RAW,		CAP_SYS_RESOURCE,
        CAP_IPC_OWNER,		CAP_SETFCAP,		CAP_SYS_TIME,
        CAP_KILL,		CAP_SETPCAP,		CAP_SYS_TTY_CONFIG,
        CAP_LEASE,		CAP_SYS_ADMIN,
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

size_t number_of_objects(char *tab[])
{
	size_t i = 0;

	while (tab[i++])
		;

	return i;
}

char *split_basename(char *fullpath)
{
	char *c = strrchr(fullpath, '/');
	size_t len;

	if (c && *c) {
		*c = '\0';

		 len = strlen(fullpath);
		 if (!len || len > PATH_MAX)
			 ERROR("filename incorrect: len(parentdir) = %d\n", len);
		 
		 len = strlen(c+1);
		 if (!len || len > NAME_MAX)
			 ERROR("filename incorrect: len(relative) = %d\n", len);

		 return c;
	} else {
		ERROR("filename \"%s\" incorrect: malformed string?.\n", fullpath);
	}

	return NULL;
}


int check_parent_directory(char dir[], uid_t uid, gid_t gid, mode_t perms) 
{
	struct stat dirstat;
        int fd;

        DEBUG("Checking ownership and permissions of the parent directory.\n");

	fd = open(dir, O_RDONLY);
	if (fd < 0)
		PERROR("open(dir) failed");

	if (fstat(fd, &dirstat) < 0)
		PERROR("fstat(dir) failed");

	if (!S_ISDIR(dirstat.st_mode))
		ERROR("The directory is not a directory... Hmmm... Weird.\n");

	if ((dirstat.st_uid != uid) && (dirstat.st_gid != gid))
		ERROR("The directory MUST be owned by root\n");

	if ((dirstat.st_mode  & ~S_IFMT) != perms)
		ERROR("The directory MUST be %lo (and not %lo)\n", 
		      perms, dirstat.st_mode & ~S_IFMT);

	return fd;
}


int valid_shell(char *needle)
{
	size_t needle_len, haystack_len;
	int found = 0;
	char buf[BUFSIZE];
	FILE *fd;

        DEBUG("Validating the shell of the target user.\n");

        fd = fopen("/etc/shells", "r");
	if (!fd)
		PERROR("open(\"/etc/shells\") failed");

	needle_len = strlen(needle);
	while (!found && fgets(buf, sizeof buf, fd)) {
		haystack_len = strlen(buf);
		if (buf[haystack_len-1] == '\n')
			buf[haystack_len-1] = '\0';

		if (strcmp(buf, needle) == 0)
			found = 1;
	}

	if (fclose(fd) != 0)
		PERROR("close(\"/etc/shells\") failed");

	return found;
}

/* filename MUST be relative */
int check_target_relative_file(char filename[], uid_t min_uid, gid_t min_gid,
			       int hardlink_ok, int shell_required,
			       struct stat *filestat)
{
	int fd;
	struct passwd *user;

        DEBUG("Checking ownership and permissions of the target file.\n");

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		PERROR("open(target) failed");

	if (fstat(fd, filestat) < 0)
		PERROR("fstat(target) failed");

	if (!S_ISREG(filestat->st_mode))
		ERROR("Target is not a regular file.\n");

	if (!hardlink_ok && filestat->st_nlink > 1)
		ERROR("Target has a hardlink count non-null.\n");

	if (filestat->st_uid < min_uid || filestat->st_gid < min_gid)
		ERROR("Target file: invalid owner or group.\n");

	user = getpwuid(filestat->st_uid);
	if (!user)
		PERROR("getpwuid(target->owner)");

	if (shell_required && !valid_shell(user->pw_shell))
		ERROR("Target file owner has not a valid shell in /etc/passwd\n");

	return fd;
}

void drop_capabilities(void) {
        int i;
        cap_value_t cap;

        DEBUG("Dropping capabilities\n");

        for (i = 0 ; i < ARRAY_SIZE(dropping_capabilities) ; i++) {
                if (prctl(PR_CAPBSET_DROP, dropping_capabilities[i]) != 0)
                    PERROR("prctl(PR_CAPSET_DROP) failed");
        }
}

int is_the_right_owner(char *target_user, char *target_group, struct stat *stat)
{
        uid_t target_uid;
        gid_t target_gid;

        if (strspn(target_user, "0123456789") != strlen(target_user)) {
                struct passwd *p;
                /* not only digits, need to resolve an username */
                p = getpwnam(target_user);
                if (!p)
                        PERROR("getpwent(target_user) ");
                target_uid = p->pw_uid;
        } else
                target_uid = atoi(target_user);

        if (strspn(target_group, "0123456789") != strlen(target_group)) {
                struct group *g;
                /* not only digits, need to resolve an username */
                g = getgrnam(target_group);
                if (!g)
                        PERROR("getgrnam(target_group) ");
                target_gid = g->gr_gid;
        } else
                target_gid = atoi(target_group);

        return target_uid == stat->st_uid && target_gid == stat->st_gid;
}

static const char *const safe_env_lst[] =
	/* code shamelessly ripped from suexec.c 
	 * Licensed to the Apache Software Foundation 
	 */
{
    /* variable name starts with */
    "HTTP_",
    "SSL_",
    
    /* variable name is */
    "AUTH_TYPE=",
    "CONTENT_LENGTH=",
    "CONTENT_TYPE=",
    "DATE_GMT=",
    "DATE_LOCAL=",
    "DOCUMENT_NAME=",
    "DOCUMENT_PATH_INFO=",
    "DOCUMENT_ROOT=",
    "DOCUMENT_URI=",
    "GATEWAY_INTERFACE=",
    "HTTPS=",
    "LAST_MODIFIED=",
    "PATH_INFO=",
    "PATH_TRANSLATED=",
    "QUERY_STRING=",
    "QUERY_STRING_UNESCAPED=",
    "REMOTE_ADDR=",
    "REMOTE_HOST=",
    "REMOTE_IDENT=",
    "REMOTE_PORT=",
    "REMOTE_USER=",
    "REDIRECT_HANDLER=",
    "REDIRECT_QUERY_STRING=",
    "REDIRECT_REMOTE_USER=",
    "REDIRECT_STATUS=",
    "REDIRECT_URL=",
    "REQUEST_METHOD=",
    "REQUEST_URI=",
    "SCRIPT_FILENAME=",
    "SCRIPT_NAME=",
    "SCRIPT_URI=",
    "SCRIPT_URL=",
    "SERVER_ADMIN=",
    "SERVER_NAME=",
    "SERVER_ADDR=",
    "SERVER_PORT=",
    "SERVER_PROTOCOL=",
    "SERVER_SIGNATURE=",
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    NULL
};

void clean_environment(char *tainted[], char *cleaned[])
{
	size_t i, j, k;

        DEBUG("Cleaning system environment\n");

	i = j = k = 0;
	while (tainted[i]) {
		k=0;
		while (safe_env_lst[k]) {
			size_t len = strlen(safe_env_lst[k]);
			if (strncmp(tainted[i], safe_env_lst[k], len) == 0) {
				DEBUG("ENV %s allowed\n", tainted[i]);
				cleaned[j++] = tainted[i];
				break;
			}
			k++;
		}
		i++;
	}
}

void clean_file_descriptors(void)
{
        int i, fd;
        int sc_open_max = sysconf(_SC_OPEN_MAX);
        int missingfds[3];

        DEBUG("Checking existence of vital file descriptors\n");

        missingfds[0] = fcntl(STDIN_FILENO,  F_GETFL, 0) == -1;
	missingfds[1] = fcntl(STDOUT_FILENO, F_GETFL, 0) == -1;
	missingfds[2] = fcntl(STDERR_FILENO, F_GETFL, 0) == -1;

        if (missingfds[0] || missingfds[1] || missingfds[2]) {
                fd = open("/dev/null", O_RDWR, 0644);
                if (fd < 0)
                        PERROR("open(\"/dev/null\") failed");

                if (missingfds[0]) {
                        WARNING("Missing STDIN_FILENO. Opening /dev/null instead...\n");
                        if (dup2(fd, STDIN_FILENO) == -1)
                                PERROR("dup2(STDIN_FILENO) failed");
                }

                if (missingfds[1]) {
                        WARNING("Missing STDOUT_FILENO. Opening /dev/null instead...\n");
                        if (dup2(fd, STDOUT_FILENO) == -1)
                                PERROR("dup2(STDOUT_FILENO) failed");
                }

                if (missingfds[2]) {
                        WARNING("Missing STDERR_FILENO. Opening /dev/null instead...\n");
                        if (dup2(fd, STDERR_FILENO) == -1)
                                PERROR("dup2(STDERR_FILENO) failed");
                }
        }

        DEBUG("Closing all file descriptors.\n");
	for (i = STDERR_FILENO+1; i <  sc_open_max; i++)
		close(i);
}

void disable_coredump(void)
{
        struct rlimit limit;

        DEBUG("Turning off core dumps.\n");

        if (getrlimit(RLIMIT_CORE, &limit) != 0)
                PERROR("getrlimit() failed");

        limit.rlim_cur = 0;
        limit.rlim_max = 0;

        if (setrlimit(RLIMIT_CORE, &limit) != 0)
                PERROR("setrlimit() failed");
}

char * extract_interpreter(char *shebang, size_t len) {
        size_t i, start, finished = 0;

        if (len <= 3) /* '#' and '!' and maybe ' ' */ 
                ERROR("Shebang too short.\n");

        if (shebang[1] != '!') {
                ERROR("Shebang malformed.\n");
        }

        if (shebang[2] == ' ')
                start = 3;
        else
                start = 2;

        if (len < start)
                ERROR("Interpreter path not present in shebang?\n");

        i = start;
        while (i < len && finished == 0) {
                char c = shebang[i];

                if (c == '\n' || c == ' ' || c == '\0')
                        finished = i;

                i++;
        }
        shebang[finished] = '\0';

        return shebang+start;
}


int main(int argc, char *argv[], char *environ[]) {
	int fdparent, fdtarget, interpreter_needed;
	char *parentdir, *filename, dotslashfilename[NAME_MAX+2];
        char *target_user, *target_group, *target_cmdline;
	char *sep, **cleanenv;
        char buf[BUFSIZE];
        size_t n;
	struct stat target_stat;

        drop_capabilities();
        disable_coredump();
        clean_file_descriptors();

        if (getuid() != CALLER_UID || getgid() != CALLER_GID) {
                AUDIT("Runned by %d:%d instead of %d:%d, abording.\n",
                      getuid(), getgid(),
                      CALLER_UID, CALLER_GID);
                _exit(1);
        }

	/* let's begin with a cleaning of the environment */
	cleanenv = malloc((1+number_of_objects(environ))* sizeof **environ); /* +1 for PATH addition */
	if (!cleanenv)
		ERROR("malloc() environment");
	clean_environment(environ, cleanenv);

        if (argc < 3) {
                AUDIT("Usage incorrect.\n\tUsage: %s Username Groupname /bin/true\n", 
                      argv[0]);
                _exit(1);
        }

        target_user    = argv[1];
        target_group   = argv[2];
        target_cmdline = argv[3];

	sep = split_basename(target_cmdline);
	if (!sep)
		return 1;

	parentdir = target_cmdline;
	filename = sep+1;

	DEBUG("parentdir=\"%s\" filename=\"%s\"\n",
	      parentdir, filename);

	fdparent = check_parent_directory(parentdir, 0, 0, PARENT_DIR_PERMS);
	if (fdparent < 0)
		return 1;

	/* now that we validate the parent directory, we can use it! */
	if (fchdir(fdparent) != 0)
		PERROR("fchdir(parentdir)");

	if (close(fdparent) != 0)
                PERROR("close(fdparent)");;

	fdtarget = check_target_relative_file(filename, 
					      TARGET_MIN_UID, TARGET_MIN_GID,
					      TARGET_HARDLINK_PERMITTED,
					      TARGET_SHELL_REQUIRED,
					      &target_stat);
        if (fdtarget < 0)
                return 1;

        if (!is_the_right_owner(target_user, target_group, &target_stat))
                ERROR("The file is not owned by SuExecUser:SuExecGroup !\n");

	if (setgid(target_stat.st_gid) != 0)
		PERROR("setuid(target.owner)");
	if (setuid(target_stat.st_uid) != 0)
		PERROR("setgid(target.owner)");

        n = read(fdtarget, buf, sizeof buf);
        if (n < 0)
                PERROR("read(target) failed");
        if (n == 0)
                ERROR("Empty target file\n");

        if (buf[0] == '#') {
                char devfd[BUFSIZE];
                char *newargv[3], *interpreter;

                DEBUG("shellbang's emulation\n");

                interpreter = extract_interpreter(buf, n);
                if (!interpreter || *interpreter == '\0')
                        ERROR("Malformed interpreter's path\n");

                snprintf(devfd, sizeof(devfd), "/dev/fd/%d", fdtarget);
                devfd[sizeof(devfd)] = '\0';

                newargv[0] = interpreter;
                newargv[1] = devfd;
                newargv[2] = NULL;

                DEBUG("execve(\"%s\", [\"%s\", \"%s\"], cleanenv)\n", interpreter, newargv[0], newargv[1]);
                execve(interpreter, newargv, cleanenv);

        } else {
                if (close(fdtarget) != 0)
                        PERROR("close(fdtarget)");

                DEBUG("execve(\"%s\")\n", filename);
                argv[0] = filename;
                execve(filename, argv, cleanenv);
        }

        PERROR("execve() failed");

	return 1;
}
