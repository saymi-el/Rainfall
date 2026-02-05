#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *auth    = NULL; // 0x8049aac
static char *service = NULL; // 0x8049ab0

int main(void)
{
    char buf[0x80]; // 128 (fgets size = 0x80)

    while (1)
    {
        printf("%p, %p \n", auth, service);

        if (fgets(buf, sizeof(buf), stdin) == NULL)
            break;

        // --- "auth " (compare sur 5 bytes) ---
        if (!strncmp(buf, "auth ", 5))
        {
            auth = (char *)malloc(4);
            *(int *)auth = 0;

            // Le binaire calcule strlen(buf+5) et n'autorise strcpy que si <= 0x1e
            if (strlen(buf + 5) <= 0x1e)
                strcpy(auth, buf + 5);

            // sinon: ignore la copie et continue
        }

        // --- "reset" (compare sur 5 bytes) ---
        else if (!strncmp(buf, "reset", 5))
        {
            free(auth);
            // IMPORTANT: le binaire ne fait PAS auth = NULL
        }

        // --- "service" (compare sur 6 bytes) ---
        else if (!strncmp(buf, "service", 6))
        {
            // IMPORTANT: pas de free(service) -> fuite
            service = strdup(buf + 7);
        }

        // --- "login" (compare sur 5 bytes) ---
        else if (!strncmp(buf, "login", 5))
        {
            // IMPORTANT: pas de check auth != NULL dans le binaire
            if (*(int *)(auth + 0x20) != 0)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }

    return 0;
}
