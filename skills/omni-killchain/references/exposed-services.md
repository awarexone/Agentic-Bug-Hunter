# Exposed Services — instant $10K-$35K

> H1: Mail.ru Zeppelin $35K, Snapchat K8s API $25K, Snapchat Jenkins $15K, Mail.ru S3/MCS $15K. Single nuclei scan can find these.

---

## TARGET LIST (highest payouts when found unauthenticated)

### CI/CD
- **Jenkins**: `/script` (Groovy console), `/jnlpJars/jenkins-cli.jar`, `/asynchPeople/`, default `admin:admin`. Pre-2.46 unauth API.
- **TeamCity**: pre-auth RCE CVEs (CVE-2024-27198, CVE-2023-42793).
- **GitLab CE/EE**: many CVEs, see `rce-archetypes.md`.
- **Drone CI / Buildkite / CircleCI**: org webhooks, SSO leaks.
- **GitHub Actions**: self-hosted runner exposure.

### Container / orchestration
- **Kubernetes API**: `:6443`, `:10250` (kubelet), `:10255` (read-only kubelet, deprecated but still seen). Anonymous access? `curl https://k8s/api/v1/namespaces/default/pods`.
- **Docker daemon**: `:2375` (no TLS) -> instant RCE. `docker -H tcp://target:2375 ps`.
- **Kubelet**: `/runningpods/`, `/exec/{namespace}/{pod}/{container}`.
- **Rancher**: known CVEs, default creds.
- **Portainer**: weak default admin.

### Big data / analytics
- **Apache Zeppelin**: `:8080`, `/api/notebook`, `/#/notebook/{id}` -> note runs Python/Spark -> RCE if anonymous.
- **Apache Spark**: `:7077` (master), `:8080` (UI), submit job -> RCE.
- **Apache Hadoop YARN**: REST API job submission.
- **Apache Druid**: `:8888` console.
- **Apache Airflow**: `:8080`, DAG triggering, RCE via PythonOperator.
- **Apache NiFi**: processor configurations.
- **Jupyter Notebook**: `:8888`, `/tree`, anonymous code run.

### Search / db
- **Elasticsearch**: `:9200/_cat/indices`, `/_search?q=*` -> full data dump.
- **Kibana**: `:5601` -> dashboards may reveal everything.
- **MongoDB**: `:27017`, no-auth defaults pre-3.x. `mongo --host target --eval 'db.adminCommand({listDatabases:1})'`.
- **CouchDB**: `:5984/_all_dbs`.
- **Cassandra**: `:9042`, default no-auth.
- **Redis**: `:6379`, `INFO`, `CONFIG GET *`.
- **PostgreSQL/MySQL/MSSQL**: `:5432/:3306/:1433` with weak / default creds.

### Service mesh / proxy / monitoring
- **Consul**: `:8500/v1/kv/?recurse`, `:8500/ui/`.
- **Vault**: `:8200/v1/sys/health` -> sometimes unsealed + readable.
- **Etcd**: `:2379`, `:2380`.
- **Prometheus**: `:9090/api/v1/series` -> internal hostnames.
- **Grafana**: `:3000`, weak `admin:admin`. Several auth-bypass CVEs.
- **Sentry**: `/auth/login`, default creds.
- **Datadog/Splunk**: agent exposure (rare).

### Java / app servers
- **Spring Boot Actuator**: `/actuator/env`, `/actuator/heapdump` (RCE via Spring4Shell + Cloud Function), `/actuator/jolokia/exec/*`.
- **Tomcat Manager**: `/manager/html`, `tomcat:tomcat`, `admin:admin`. Deploy WAR -> RCE.
- **JBoss / WildFly / Glassfish**: management consoles.
- **WebLogic**: `:7001`, deser CVEs.

### Misc high-value
- **WordPress / Drupal / Joomla** with admin panel exposed + weak creds.
- **phpMyAdmin** with default creds.
- **PHPMailer / PHPInfo** at `/phpinfo.php` (info disclosure -> chains).
- **MLflow**: API exposure.
- **MinIO/S3-compatible**: anonymous bucket lists.
- **Solr**: `:8983/solr/`.
- **Memcached UDP**: amplification + dumps.
- **rsync**: `:873` anonymous.
- **TFTP**: `:69` for embedded.

### Cloud-specific exposures
- **AWS**: open S3 buckets (`<bucket>.s3.amazonaws.com`), exposed metadata, public Lambda function URLs.
- **GCP**: open GCS buckets (`storage.googleapis.com/<bucket>/`).
- **Azure**: open blob storage (`*.blob.core.windows.net`).
- **DigitalOcean Spaces**: `*.digitaloceanspaces.com`.

---

## STAGE 1 — Discovery

```bash
# Port scan
naabu -l live_hosts.txt -top-ports 5000 -rate 5000 -silent -o ports.txt
masscan -p1-65535 $IP --rate 5000 -oG masscan.gnmap

# Service identify
nmap -sV -sC -Pn -iL ports.txt -oA nmap

# Targeted nuclei
nuclei -l live_hosts.txt \
  -t exposed-panels/ \
  -t exposures/ \
  -t default-logins/ \
  -t misconfiguration/ \
  -t cves/ \
  -severity critical,high,medium

# Specific:
nuclei -t http/exposed-panels/jenkins-exposed.yaml
nuclei -t http/exposed-panels/kubernetes-mirantis.yaml
nuclei -t http/exposures/configs/spring-actuator.yaml
nuclei -t http/exposures/configs/git-config.yaml
nuclei -t http/misconfiguration/elasticsearch.yaml
```

---

## STAGE 2 — Validation steps per service

### Jenkins (no auth)
1. `/people/` -> users
2. `/jnlpJars/jenkins-cli.jar` -> tool
3. `/script` -> Groovy console -> code run

### Kubernetes API
1. `curl -k https://target:6443/version` -> exposed?
2. `curl -k https://target:6443/api/v1/namespaces` -> anonymous?
3. If yes -> probably also exposed `kubectl --insecure-skip-tls-verify` from inside

### Docker daemon
1. `docker -H tcp://target:2375 info`
2. `docker -H tcp://target:2375 run -v /:/host alpine cat /host/etc/passwd`
3. Equivalent to root on the host

### Spring Boot Actuator
1. `/actuator` -> list endpoints
2. `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops`
3. `/actuator/gateway/actuator/gateway/routes` (Spring Cloud Gateway RCE - CVE-2022-22947)

### Elasticsearch
1. `/_cat/indices?v` -> data view
2. `/_search?q=*&pretty&size=20` -> sample data
3. Check for snapshot / `/.kibana_*` / log indices

### Redis (no auth)
1. `INFO` -> server version, role
2. `CONFIG GET dir` / `CONFIG GET dbfilename` -> writeable?
3. If yes -> SSH key write / cron write -> RCE (only if program permits)

### MongoDB (no auth)
1. `db.adminCommand({listDatabases:1})`
2. `use <db>; db.<col>.findOne()` -> sample
3. Note: read-only is enough impact, do not modify

---

## STAGE 3 — Impact

For BBP, you usually don't need to fully RCE. Show:
- Unauth API access screenshot
- Sample privileged action that proves access (read users, list secrets, run benign command)
- Suggested fix (auth, network policy, IP allowlist)

Stop pivoting at first proof.

---

## VALIDATION CHECKLIST

- Confirm scope explicitly allows testing (some BBPs exclude infra)
- Hit endpoints minimally, don't enumerate all data
- Capture: HTTP request, response, screenshot, version banner
- Note default-creds vs zero-auth vs weak-cred
- Suggest fix specifically (auth, firewall, version upgrade)

---

## TOOLING

- **nuclei** with curated templates (`exposed-panels`, `exposures`, `default-logins`, `cves`)
- **shodan** queries: `org:"Target"` + service filter
- **fofa**, **zoomeye**, **censys** — same idea
- **gowitness/aquatone** — visual triage to spot login pages quickly
- **kube-hunter** — Kubernetes-specific
- **routersploit**, **metasploit** — for embedded
