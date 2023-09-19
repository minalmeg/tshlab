/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * The shell has 2 components - Signal Handlers and Argument Parser.
 * 
 * The argument parser either gets a built-in command or a execute command. 
 * The tsh_helper function parsers the argument into a data struct called 'token'
 * which we then use to evaluate the type of input - quit, run progrom as child process, 
 * run a background job / run a foreground job or print job
 * 
 * The Signal handlers handle different signals like SIGCHLD, SIGINT and SIGSTP
 * SIGCHLD - Monitor child process and reap them when terminated to not have any zombie processes
 * SIGINT - Handles Ctrl-C and terminates a process
 * SIGSTP - Handles Ctrl-Z and stops a process
 * 
 * @author Minal Acharya <mnachary@andrew.cmu.edu>
 */
#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif
/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
void fgjob_wait(jid_t job, sigset_t *set);
static void blk_all_signals(sigset_t *mask, sigset_t *prev);
static void unblk_all_signals(sigset_t prev);
static jid_t jid_parser(struct cmdline_tokens token);
static bool io_redirection(struct cmdline_tokens token);
/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
	int c;
	char cmdline[MAXLINE_TSH]; // Cmdline for fgets
	bool emit_prompt = true;   // Emit prompt (default)

	// Redirect stderr to stdout (so that driver will get all output
	// on the pipe connected to stdout)
	if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
		perror("dup2 error");
		exit(1);
	}

	// Parse the command line
	while ((c = getopt(argc, argv, "hvp")) != EOF) {
		switch (c) {
		case 'h': // Prints help message
			usage();
			break;
		case 'v': // Emits additional diagnostic info
			verbose = true;
			break;
		case 'p': // Disables prompt printing
			emit_prompt = false;
			break;
		default:
			usage();
		}
	}

	// Create environment variable
	if (putenv(strdup("MY_ENV=42")) < 0) {
		perror("putenv error");
		exit(1);
	}

	// Set buffering mode of stdout to line buffering.
	// This prevents lines from being printed in the wrong order.
	if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
		perror("setvbuf error");
		exit(1);
	}

	// Initialize the job list
	init_job_list();

	// Register a function to clean up the job list on program termination.
	// The function may not run in the case of abnormal termination (e.g. when
	// using exit or terminating due to a signal handler), so in those cases,
	// we trust that the OS will clean up any remaining resources.
	if (atexit(cleanup) < 0) {
		perror("atexit error");
		exit(1);
	}

	// Install the signal handlers
	Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
	Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
	Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

	Signal(SIGTTIN, SIG_IGN);
	Signal(SIGTTOU, SIG_IGN);

	Signal(SIGQUIT, sigquit_handler);

	// Execute the shell's read/eval loop
	while (true) {
		if (emit_prompt) {
			printf("%s", prompt);

			// We must flush stdout since we are not printing a full line.
			fflush(stdout);
		}

		if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
			perror("fgets error");
			exit(1);
		}

		if (feof(stdin)) {
			// End of file (Ctrl-D)
			printf("\n");
			return 0;
		}

		// Remove any trailing newline
		char *newline = strchr(cmdline, '\n');
		if (newline != NULL) {
			*newline = '\0';
		}

		// Evaluate the command line
		eval(cmdline);
	}

	return -1; // control never reaches here
}
/**
 * @brief <What does eval do?>
 *
 * Evaluates whether input cmdline is a built-in command or a program to execute
 * Also adds job to job list
 * 
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
	parseline_return parse_result;
	struct cmdline_tokens token;
	pid_t pid;
	// Parse command line
	parse_result = parseline(cmdline, &token);
	sigset_t mask, prev;
	bool FG = true;
	if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
		return;
	}
	
	// block all the signals
	blk_all_signals(&mask, &prev);

	if (token.argv[0] == NULL)
		return;
	if (token.builtin == BUILTIN_QUIT)
		exit(0);
	else if (token.builtin == BUILTIN_NONE) {

		// If there is a infile outfile, do io redirection
		if(token.infile || token.outfile){
			if(!io_redirection(token)) exit(0);
		} 
		
		if ((pid = fork()) == 0) {
			unblk_all_signals(prev);
			// changes the process group of process pid to pgid
			if (setpgid(0, 0) < 0) _exit(1);
			if(token.infile || token.outfile){
				if(!io_redirection(token)) _exit(1);
			} 
			if (execve(token.argv[0], token.argv, environ) < 0) {
				sio_printf("%s: Command not found.\n", token.argv[0]);
				unblk_all_signals(prev);
				_exit(1);
			}
		}
		if (parse_result == PARSELINE_BG)
			FG = false;
		if (FG) {
			// If it is a foregorund job, add it to list
			// And call foreground wait
			jid_t jid = add_job(pid, FG, cmdline);
			fgjob_wait(jid, &prev);
		} else {
			// If it is a background job, add it to list
			// And print in the formot tshref prints a bg job
			jid_t jid = add_job(pid, BG, cmdline);
			sio_printf("[%d] (%d) %s \n", jid, pid, cmdline);
		}
	} else if (token.builtin == BUILTIN_JOBS) {
		// List all the background jobs
		list_jobs(STDOUT_FILENO);
	}
	else if (token.builtin == BUILTIN_BG) {
		// Get the job id from the cmd
		jid_t jid = jid_parser(token);
		if (jid < 0) _exit(1);
		pid_t pid = job_get_pid(jid);
		kill(-pid, SIGCONT);
		job_set_state(jid, BG);
		sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));

	} else if (token.builtin == BUILTIN_FG) {
		jid_t jid = jid_parser(token);
		if (jid < 0)
			_exit(1);
		pid_t pid = job_get_pid(jid);
		kill(-pid, SIGCONT);
		job_set_state(jid, FG);
		fgjob_wait(jid, &prev);
	}

	// Unblock All signals
	unblk_all_signals(prev);
	return;
}

static bool io_redirection(struct cmdline_tokens token) {
	const char *infile = token.infile;
	const char *outfile = token.outfile;
	if (infile) {
		int fd = open(infile, O_RDONLY);
		if (fd < 0) {
			return false;
		}
		if (dup2(fd, STDIN_FILENO) < 0) {
			return false;
		}
		if (close(fd) < 0) {
			return false;
		}
	}
	if (outfile) {
		int fd = open(infile, O_CREAT | O_RDWR | O_TRUNC, DEF_MODE);
		if (fd < 0) {
			return false;
		}
		if (dup2(fd, STDOUT_FILENO) < 0) {
			return false;
		}
		if (close(fd) < 0) {
			return false;
		}
	}

	return true;
}

static jid_t jid_parser(struct cmdline_tokens token) {
	int token_num = token.argc;
	char **token_arg = token.argv;
	jid_t jid = -1;
	pid_t pid = -1;
	if (token_num < 2)
		return jid;
	if (token_arg[1][0] == '%') {
		jid = atoi(token_arg[1] + 1); // Convert the no. after % to int
		if (!job_exists(jid)) {
			sio_eprintf("%s: No such job\n", token_arg[1]);
			return false;
		}
	} else {
		pid = atoi(token_arg[1]);
		if (pid > 0)
			jid = job_from_pid(pid);
	}
	return jid;
}
static void blk_all_signals(sigset_t *mask, sigset_t *prev) {
	sigemptyset(mask);
	sigfillset(mask);
	sigprocmask(SIG_BLOCK, mask, prev);
	return;
}

static void unblk_all_signals(sigset_t prev) {
	sigprocmask(SIG_SETMASK, &prev, NULL);
	return;
}

void fgjob_wait(jid_t job, sigset_t *set) {
	sigset_t mask, prev;
	blk_all_signals(&mask, &prev);
	while (job == fg_job()) {
		sigsuspend(set);
	}
	unblk_all_signals(prev);
	return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Monitors child processes and reaps them if terminated using 
 * delete_job helper function or changes its job state to ST if stopped
 * 
 */
void sigchld_handler(int sig) {

	int olderrno = errno;
	sigset_t mask, prev;
	int status;
	pid_t pid;

	// WNOHANG | WUNTRACED - Return immediately, with a return value of
	// 0, if none of the children in the wait set has stopped or terminated, or
	// with a return value equal to the PID of one of the stopped or terminated
	// children.

	while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {

		// WIFEXITED  Returns true if the child terminated normally
		if (WIFEXITED(status)) {
			blk_all_signals(&mask, &prev);
			jid_t jid = job_from_pid(pid);
			delete_job(jid);
		}

		// WIFSIGNALED(status). Returns true if the child process terminated
		// because of a signal that was not caught.
		if (WIFSIGNALED(status)) {
			blk_all_signals(&mask, &prev);
			jid_t jid = job_from_pid(pid);
			delete_job(jid);

			int sig = WTERMSIG(status); // Returns the number of the signal that
										// caused the child process to terminate
			sio_printf("Job (%d) terminated by signal %d\n", pid,
					   sig);
		}

		// WIFSTOPPED(status). Returns true if the child that caused the return
		// is currently stopped.
		if (WIFSTOPPED(status)) {
			blk_all_signals(&mask, &prev);
			jid_t jid = job_from_pid(pid);
			job_set_state(jid, ST);

			int sig = WSTOPSIG(status); // Returns the number of the signal that
										// caused the child to stop
			sio_printf("Job (%d) stopped by signal %d\n", pid, sig);
		}
		unblk_all_signals(prev);
	}
	errno = olderrno;
	return;
}

/**
 * @brief Handles the Ctrl+C usecase and terminates a job
 */
void sigint_handler(int sig) {
	int olderrno = errno;
	sigset_t mask, prev;
	blk_all_signals(&mask, &prev);
	jid_t fgjob = fg_job();
	if (fgjob) {
		pid_t fgpid = job_get_pid(fgjob);
		kill(-fgpid, SIGINT);
	}
	unblk_all_signals(prev);
	errno = olderrno;
	return;
}

/**
 * @brief Handles the Ctrl+C usecase and terminates a job
 */
void sigtstp_handler(int sig) {
	int olderrno = errno;
	sigset_t mask, prev;
	blk_all_signals(&mask, &prev);
	jid_t fgjob = fg_job();
	if (fgjob) {
		pid_t fgpid = job_get_pid(fgjob);
		kill(-fgpid, SIGTSTP);
	}
	unblk_all_signals(prev);
	errno = olderrno;
	return;
}
/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
	// Signals handlers need to be removed before destroying the joblist
	Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
	Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
	Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

	destroy_job_list();
}
