#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include "Handlers/DBHandler.h"

int main() {
    int fd = open("example.txt", O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        perror("Error creating file");
        return 1;
    }

    write(fd, "Hello, Linux!\n", 14); // Write to the file
    close(fd); // Close the file

    printf("File created successfully.\n");
    return 0;
}