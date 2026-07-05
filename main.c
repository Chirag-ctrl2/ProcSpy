#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#define MAX_PATH 512

// Check if a string is a valid PID (numbers only)
int is_numeric(const char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) return 0;
    }
    return 1;
}

// Feature: Count how many files/sockets a process currently has open
int count_open_fds(const char *pid) {
    char path[MAX_PATH];
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    snprintf(path, sizeof(path), "/proc/%s/fd", pid);
    dir = opendir(path);
    if (!dir) return -1; // Permission denied or process died

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') count++;
    }
    closedir(dir);
    return count;
}

// Security Feature: Analyze memory maps for RWX regions (can be malware)
void analyze_memory_maps(const char *pid) {
    char path[MAX_PATH];
    char line[1024];
    int rwx_found = 0;

    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE *file = fopen(path, "r");
    if (!file) {
        printf("Cannot read memory maps (Requires root/sudo for other users' processes).\n");
        return;
    }

    printf("\n Memory Map Security Analysis:\n");
    printf("%-35s %-10s %s\n", "MEMORY ADDRESS", "PERMS", "MAPPED PATH");
    printf("------------------------------------------------------------\n");

    while (fgets(line, sizeof(line), file)) {
        char address[64], perms[10], offset[20], dev[10], inode[20];
        char mapped_path[MAX_PATH] = "[anonymous/heap/stack]";
        
        // Parse the maps file format
        sscanf(line, "%s %s %s %s %s %511[^\n]", address, perms, offset, dev, inode, mapped_path);

        // Alert on Read+Write+Execute regions (W^X violation)
        if (strcmp(perms, "rwxp") == 0 || strcmp(perms, "rwx-") == 0) {
            printf("\033[1;31m%-35s %-10s %s (WARNING: RWX REGION)\033[0m\n", address, perms, mapped_path);
            rwx_found++;
        } else if (strstr(mapped_path, ".so") != NULL) {
            // Optional: Print loaded shared libraries to detect injected .so files
            // printf("%-35s %-10s %s\n", address, perms, mapped_path);
        }
    }
    
    if (rwx_found == 0) {
        printf("No highly suspicious (RWX) memory regions detected.\n");
    } else {
        printf("Detected %d RWX region(s). This could be injected code.\n", rwx_found);
    }

    fclose(file);
}

// Feature: Deep inspect a specific process
void inspect_process(const char *pid) {
    char path[MAX_PATH];
    char cmdline[2048] = {0};

    // 1. Get exact command line used to launch it
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    FILE *cmd_file = fopen(path, "r");
    if (cmd_file) {
        size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, cmd_file);
        // /proc/pid/cmdline is null-separated, convert \0 to spaces for printing
        for (size_t i = 0; i < bytes_read; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        fclose(cmd_file);
    }

    
    printf(" DEEP INSPECTION: PID %s\n", pid);
    //printf("\n");
    printf("Command Line: %s\n", strlen(cmdline) > 0 ? cmdline : "[Kernel Thread or Zombie]");
    
    int fd_count = count_open_fds(pid);
    if (fd_count >= 0) {
        printf("Open File Descriptors: %d\n", fd_count);
    } else {
        printf("Open File Descriptors: [Access Denied]\n");
    }

    analyze_memory_maps(pid);
    //printf();
}

// Basic System Scan (similar to the previous version but optimized)
void scan_all_processes() {
    DIR *dir;
    struct dirent *entry;
    
    dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return;
    }

    printf("%-10s %-25s %-10s %-15s\n", "PID", "NAME", "STATE", "OPEN FDs");
    printf("------------------------------------------------------------------------\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && is_numeric(entry->d_name)) {
            char path[MAX_PATH], name[256] = "Unknown";
            char state = '?';
            int pid;

            snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
            FILE *stat_file = fopen(path, "r");
            
            if (stat_file) {
                if (fscanf(stat_file, "%d (%[^)]) %c", &pid, name, &state) == 3) {
                    int fds = count_open_fds(entry->d_name);
                    // Hide kernel threads (which have no user-space FDs) for a cleaner view
                    
                    printf("%-10d %-25.25s %-10c %-15d\n", pid, name, state, fds);
                    
                }
                fclose(stat_file);
            }
        }
    }
    closedir(dir);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -a          Scan all user-space processes (Default)\n");
    printf("  -p <pid>    Perform deep memory & security inspection on a specific PID\n");
    printf("  -h          Show this help message\n");
}

int main(int argc, char *argv[]) {
    int opt;
    char *target_pid = NULL;

    if (argc == 1) {
        scan_all_processes();
        return 0;
    }

    while ((opt = getopt(argc, argv, "ap:h")) != -1) {
        switch (opt) {
            case 'a':
                scan_all_processes();
                return 0;
            case 'p':
                target_pid = optarg;
                if (!is_numeric(target_pid)) {
                    printf("Error: PID must be numeric.\n");
                    return 1;
                }
                inspect_process(target_pid);
                return 0;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }
    return 0;
}
