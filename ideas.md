Stuff what can be wrong:

- no DNS at all
- DNS pointed somewhere else
- cloud firewalls and other garbage
- nothing listening on port 80 or 443
- not redirecting HTTP to HTTPS
- no HTTPS cert
- bad HTTPS cert
- reverse proxy is not proxying
- incorrect use of virtual hosts...?
- program behind reverse proxy is not running
- program behind reverse proxy is on wrong port

Stuff that messed me up in the past:

- Amazon cloud firewall blocking traffice
- FIRST simulator binding only on 127.0.0.1 and not ::1, and Godot connecting only to ::1
    - Could you do a "diff" or "bisect" almost? This works, but this doesn't, that kind of thing
