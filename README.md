# audisp-sentinel
Audit Dispatcher Sentinel (auditd)

This is a simple audit event dispatcher plugin (prototype) which will send emails for audit events that are tagged with a certain key. For instance consider there is a watcher for an ssh key and we tag corresponding events with -k Sentinel, like:

```$ sudo auditctl  -W /home/bobby/.ssh/production_rsa -p rwxa -k Sentinel```

Then the audisp-sentinel plugin can be configured to send email notifications for any Sentinel tagged event.
Pretty straight forward, details can be configured in sentinel.conf. 

Note that the recipient is still hardcoded, so please updated accordingly before compiling.

## Compilation and References 

Install missing dependencies for build

```$ sudo apt install libaudit-dev```

```$ sudo apt install libauparse-dev```


## Compilation

```$ gcc -o audisp-sentinel audisp-sentinel.c -lauparse -laudit```

## Configuration

Create/copy the sentinel.conf file to /etc/audisp/plugins.d/
Make sure to update the email address for the recipient accordingly.
Afterwards relaunch auditd.

## Credits
The foundations for audisp-sentinel code are from Steve Grubb's public blog post:
http://security-plus-data-science.blogspot.com/2017/04/sending-email-when-audisp-program-sees.html

I just did some minor adjustments to be able to make email and notifications configurable.

## Have fun!
