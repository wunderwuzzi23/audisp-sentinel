// Credits: The foundations of this prototype are from Steve Grubb's public blog post
// http://security-plus-data-science.blogspot.com/2017/04/sending-email-when-audisp-program-sees.html
//
// I just did some minor adjustments to be able to make email and notifications configurable. 
// Note the sender is currently hardcoded stil, so please update accordingly.  
// More updates to come over time. MIT License
// Johann Rehberger- WUNDERWUZZI, LLC (2019)
//

//
// Install missing dependencies for build
// sudo apt install libaudit-dev
// sudo apt install libauparse-dev

//
// Compile using: gcc -o audisp-sentinel audisp-sentinel.c -lauparse -laudit
//


#define _GNU_SOURCE
#include <stdio.h>
#include <sys/select.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <libaudit.h>
#include <auparse.h>


const char *needle = NULL;
const char *mailto = NULL;

//audisp plugins only allow to pass in 2 arguments, hence
//hardcoding the from address for simplicity
const char *mailfrom = "sentinel.messenger@outlook.com";

static void send_alert(const char *name)
{
    FILE *mail;
    mail = popen("/usr/lib/sendmail -t", "w");
    if (mail) {
        fprintf(mail, "To: %s\n", mailto);
        fprintf(mail, "From: %s\n", mailfrom);
        fprintf(mail, "Subject: [Sentinel Notification] - Audit Dispatch\n\n");
        fprintf(mail, "Account %s triggered the audit rule. Please review the event logs.\n", name);
        fprintf(mail, ".\n\n");         // Close it up...
        fclose(mail);
    }
}

static void handle_event(auparse_state_t *au,
        auparse_cb_event_t cb_event_type, void *user_data)
{
    char msg[256], *name = NULL;
    const char  *key = NULL;

    if (cb_event_type != AUPARSE_CB_EVENT_READY)
        return;

    /* create a message */
    if (!auparse_normalize(au, NORM_OPT_NO_ATTRS)) {
        if (auparse_normalize_key(au) == 1)
            key = auparse_interpret_field(au);
            if (key && strstr(needle, key)) {
                if (auparse_normalize_subject_primary(au) == 1)
                    name = strdup(auparse_interpret_field(au));

                /* send a message */
                //printf("Alert, %s triggered our rule\n", name);
                send_alert(name);
                free(name);
        }
    }
}

int main(int argc, char *argv[])
{
    auparse_state_t *au = NULL;
    char tmp[MAX_AUDIT_MESSAGE_LENGTH+1], bus[32];

    if (argc != 3) {
        fprintf(stderr, "Missing arguments: key mailto\n");
        return 1;
    }

    needle = argv[1];
    mailto = argv[2];

    /* Initialize the auparse library */
    au = auparse_init(AUSOURCE_FEED, 0);
    auparse_add_callback(au, handle_event, NULL, NULL);

    do {
        int retval;
        fd_set read_mask;

        FD_ZERO(&read_mask);
        FD_SET(0, &read_mask);

        do {
            retval = select(1, &read_mask, NULL, NULL, NULL);
        } while (retval == -1 && errno == EINTR);

        /* Now the event loop */
         if (retval > 0) {
            if (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH,
                stdin)) {
                auparse_feed(au, tmp,
                    strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH));
            }
        } else if (retval == 0)
            auparse_flush_feed(au);
        if (feof(stdin))
            break;
    } while (1);

    /* Flush any accumulated events from queue */
    auparse_flush_feed(au);
    auparse_destroy(au);

    return 0;
}
