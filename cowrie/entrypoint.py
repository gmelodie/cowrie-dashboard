import os
import pwd
import re

# Fix ownership of mounted volumes so the cowrie user can write to them
pw = pwd.getpwnam("cowrie")

# Ensure required runtime directories exist (var/ is a bind-mount so they may be absent)
for d in [
    "/cowrie/cowrie-git/var/log/cowrie",
    "/cowrie/cowrie-git/var/lib/cowrie",
    "/cowrie/cowrie-git/var/lib/cowrie/tty",
    "/cowrie/cowrie-git/var/lib/cowrie/downloads",
    "/cowrie/cowrie-git/var/run",
]:
    os.makedirs(d, exist_ok=True)

# A crashed twistd leaves its pidfile behind. On restart, twistd sees the file,
# checks if the recorded PID is alive — and since the new container's PID 1 is
# always alive, it aborts with "Another twistd server is running, PID 1".
for pidfile in (
    "/cowrie/cowrie-git/var/run/cowrie.pid",
    "/cowrie/cowrie-git/twistd.pid",
):
    try:
        os.remove(pidfile)
    except FileNotFoundError:
        pass

for path in [
    "/cowrie/cowrie-git/var/log/cowrie",
    "/cowrie/cowrie-git/var/lib/cowrie",
]:
    for dirpath, dirnames, filenames in os.walk(path):
        os.chown(dirpath, pw.pw_uid, pw.pw_gid)
        for fname in filenames:
            os.chown(os.path.join(dirpath, fname), pw.pw_uid, pw.pw_gid)

# Substitute ${VAR} placeholders in the config template
template = open("/tmp/cowrie.cfg.template").read()
config = re.sub(
    r"\$\{(\w+)\}",
    lambda m: os.environ.get(m.group(1), m.group(0)),
    template,
)
open("/cowrie/cowrie-git/etc/cowrie.cfg", "w").write(config)
os.chown("/cowrie/cowrie-git/etc/cowrie.cfg", pw.pw_uid, pw.pw_gid)

# Drop to the cowrie user
os.setgroups([pw.pw_gid])
os.setgid(pw.pw_gid)
os.setuid(pw.pw_uid)

os.execv(
    "/cowrie/cowrie-env/bin/twistd",
    ["/cowrie/cowrie-env/bin/twistd", "-n", "cowrie"],
)
