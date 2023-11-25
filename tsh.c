/**
 * @file tsh.c
 * @brief Small shell program with job control. Main eval function
 * evaluates command input. Current jobs stored and modified in a
 * job_list. Three main handlers: sigchild handler, sigint handler
 * and sigstop handler. Also supports I/O redirection.
 *
 * @author Gonzalo de Hermenegildo <gdeherme@andrew.cmu.edu>
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

void unix_error(const char *error_message);
pid_t Fork(void);
pid_t Waitpid(pid_t pid, int *statusp, int options);
void perform_redirection(char *infile, char *outfile);

/*********************************
 * Wrappers for system functions
 *********************************/

/**
 * @brief A general error-reporting function.  It flushes
 * stdout, and then outputs to stderr the program name
 *
 */
void unix_error(const char *msg) { // Unix-style error
    fprintf(stderr, "%s: %s\n\n", msg, strerror(errno));
    exit(1);
}

/**
 * @brief Creates a new process by duplicating the calling process.
 * The new process is referred to as the child process.  The calling
 * process is referred to as the parent process.
 *
 */
pid_t Fork(void) {
    pid_t pid;

    if ((pid = fork()) < 0)
        unix_error("Fork error");
    return pid;
}

/**
 * @brief Suspends execution of the calling process until a
 * child specified by pid argument has changed state.
 *
 */

pid_t Waitpid(pid_t pid, int *statusp, int options) {
    pid_t temp = waitpid(pid, statusp, options);

    if (temp < 0)
        unix_error("Waitpid error");

    return (temp);
}

/**
 * @brief Function in charge of redirecting. If infile is not NULL,
 * then we redirect the stdin to the new file descriptor provided.
 * Analogously, if outfile is not NULL, we redirect the stdout
 *
 */

void perform_redirection(char *infile, char *outfile) {
    if (infile != NULL) {
        int input_fd = open(infile, O_RDONLY);
        if (errno == ENOENT) {
            sio_printf("%s: No such file or directory\n", infile);
            exit(1);
        }
        if (errno == EACCES) {
            sio_printf("%s: Permission denied\n", infile);
            exit(1);
        }

        dup2(input_fd, STDIN_FILENO);
        close(input_fd);
    }

    if (outfile != NULL) {
        int output_fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);

        if (errno == EACCES) {
            sio_printf("%s: Permission denied\n", outfile);
            exit(1);
        }

        dup2(output_fd, STDOUT_FILENO);
        close(output_fd);
    }
}

/**
 * @brief
 * Shell's main function, which initializes all variables (such as the )
 * job list and prints out the prompt, as well as takes input commands
 * from user.
 *
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
 * @brief Eval - evaluates a command line and handles errors accordingly
 *
 */
void eval(const char *cmdline) {
    // Variables needed
    parseline_return parse_result;
    struct cmdline_tokens token;

    pid_t pid;
    jid_t jid;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    // SEtting our masks
    sigset_t mask_all, /* prev_all, */ mask, prev_mask;
    sigfillset(&mask_all);

    sigemptyset(&mask);
    sigemptyset(&prev_mask);

    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Identify shell command
    switch (token.builtin) {
        // BUILTIN COMMANDS (they get interpreted immediately, i.e. no job list)
    case BUILTIN_QUIT:
        exit(0);
        break;

    case BUILTIN_JOBS:
        // block signals
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        // listing in stdout
        if (token.outfile == NULL) {
            list_jobs(STDOUT_FILENO);
        }
        // want listing jobs other than stdout
        else {
            int output_fd;
            // open file
            // error encountered
            output_fd =
                open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);

            if (errno == ENOENT) {
                sio_printf("%s: No such file or directory\n", token.outfile);
                // unblock signals
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                exit(1);
            }
            if (errno == EACCES) {
                sio_printf("%s: Permission denied\n", token.outfile);
                // unblock signals
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                /* exit(1); */
            } else { // write to file
                list_jobs(output_fd);
                close(output_fd);
            }
        }

        // unblock signals
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        break;

    case BUILTIN_BG:

        // block signals
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        // not enough arguments
        if (token.argc < 2) {
            printf("bg command requires PID or %%jobid argument\n");

            // unblock before returning
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        // Case 1: Arg is job id
        if (token.argv[token.argc - 1][0] == '%') {
            jid = atoi(token.argv[token.argc - 1] + 1);

            // check valid jid
            if (!job_exists(jid)) {
                printf("%%%d: No such job\n", jid);

                // unblock before returning
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                return;
            }

            pid = job_get_pid(jid);

        }

        // Case 2: Arg is a pid
        else if (isdigit(token.argv[token.argc - 1][0])) {
            pid = atoi(token.argv[token.argc - 1]);

            // check valid pid
            if (job_from_pid(pid) == 0) {
                printf("(%d): No such process\n", pid);
            }

            jid = job_from_pid(pid);

        }
        // input not valid
        else {
            printf("bg: argument must be a PID or %%jobid\n");

            // unblock before returning
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        if (job_get_state(jid) == ST) {
            // update process state and send SIGCONT
            job_set_state(jid, BG);
            kill(-pid, SIGCONT);

            // output
            printf("[%d] (%d) %s\n", job_from_pid(pid), pid,
                   job_get_cmdline(jid));
        }

        // unblock
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        break;

    case BUILTIN_FG:
        // block signals
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        // not enough arguments
        if (token.argc < 2) {
            printf("fg command requires PID or %%jobid argument\n");

            // unblock before returning
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        // Case 1: Arg is job id
        if (token.argv[token.argc - 1][0] == '%') {
            jid = atoi(token.argv[token.argc - 1] + 1);

            // check valid jid
            if (!job_exists(jid)) {
                printf("%%%d: No such job\n", jid);

                // unblock before returning
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                return;
            }

            pid = job_get_pid(jid);

        }

        // Case 2: Arg is a pid
        else if (isdigit(token.argv[token.argc - 1][0])) {
            pid = atoi(token.argv[token.argc - 1]);

            // check valid pid
            if (job_from_pid(pid) == 0) {
                printf("(%d): No such process\n", pid);
            }

            jid = job_from_pid(pid);

        }
        // input not valid
        else {
            printf("fg: argument must be a PID or %%jobid\n");

            // unblock before returning
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        job_set_state(jid, FG);
        kill(-pid, SIGCONT);

        while (fg_job())
            sigsuspend(&prev_mask);

        // unblock
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);

        break;

        // NON BUILT-IN COMMANDS
    case BUILTIN_NONE:
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        if ((pid = Fork()) == 0) {
            setpgid(pid, pid);

            // Redirect I/O
            perform_redirection(token.infile, token.outfile);

            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            execve(token.argv[0], token.argv, environ);

            // if here, know execve failed
            sio_printf("%s: %s\n", token.argv[0], strerror(errno));
            exit(1);
        }

        else { // WHAT PARENT DOES
            if (parse_result == PARSELINE_FG) {
                add_job(pid, FG, cmdline);
                // while loop to wait until multiple fg jobs done
                while (fg_job())
                    sigsuspend(&prev_mask);

                // unblock
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            }

            else if (parse_result == PARSELINE_BG) {
                add_job(pid, BG, cmdline);
                printf("[%d] (%d) %s\n", job_from_pid(pid), pid, cmdline);
                // unblock
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            }
        }

    default:
        break;
    }
}
/*****************
 * Signal handlers
 *****************/

/**
 * @brief Wehenever a child job terminates, the kernel will send
 * a SIGCHLD signal to the shell. This handler is in charge of reaping
 * all available zombie children.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    pid_t pid;

    int status; // to check the exis status of reaped child

    sigfillset(&mask_all);

    // pid of child that terminated
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) >
           0) { /* Reap child */
        // block all signals so handler is not interrupted
        sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

        if (WIFEXITED(status)) { // regular termination
            delete_job(
                job_from_pid(pid)); /* Delete the child from the job list */
        }

        // SIGTSTP case
        else if (WIFSTOPPED(status)) {
            printf("Job [%d] (%d) stopped by signal %d\n", job_from_pid(pid),
                   pid, WSTOPSIG(status));
            job_set_state(job_from_pid(pid), ST);
        }

        else if (WIFSIGNALED(status)) {
            printf("Job [%d] (%d) terminated by signal %d\n", job_from_pid(pid),
                   pid, WTERMSIG(status));

            delete_job(job_from_pid(pid));
        }

        // unblock all signals after handler finished
        sigprocmask(SIG_SETMASK, &prev_all, NULL);
    }

    if (pid != 0 && errno != ECHILD)
        unix_error("waitpid error");
    errno = olderrno;
}

/**
 * @brief ctrl-c from user's keyboard detected.
 * Sends SIGINT to every job in foreground process group
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    sigfillset(&mask_all);

    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    jid_t fg_job_id = fg_job(); // b4 calling, any signals that modify
                                // job list must be blocked

    // No job on foreground, ignore
    if (fg_job_id == 0) {
        sigprocmask(SIG_SETMASK, &prev_all, NULL);

        errno = olderrno;
        return;
    }

    // In this case: fg_pid == fg_pgid
    pid_t fg_pid = job_get_pid(fg_job_id);
    kill(-fg_pid, SIGINT);
    sigprocmask(SIG_SETMASK, &prev_all, NULL);

    errno = olderrno;
}

/**
 * @brief ctrl-z from user's keyboard detected.
 * Sends SIGTSTP to every job in foreground process group
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    sigfillset(&mask_all);

    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    jid_t fg_job_id = fg_job(); // b4 calling, any signals that modify
                                // job list must be blocked

    // No job on foreground, ignore
    if (fg_job_id == 0) {
        sigprocmask(SIG_SETMASK, &prev_all, NULL);

        errno = olderrno;
        return;
    }

    // In this case: fg_pid == fg_pgid
    pid_t fg_pid = job_get_pid(fg_job_id);
    kill(-fg_pid, SIGTSTP);
    sigprocmask(SIG_SETMASK, &prev_all, NULL);

    errno = olderrno;
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
