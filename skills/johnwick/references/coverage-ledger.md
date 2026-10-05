# The Coverage Ledger — how "skip nothing" is enforced

The ledger is the mechanism that makes total coverage real instead of aspirational. No asset and no step
is ever "done" on a claim — only when a `coverage.jsonl` query proves it. Mirror it into the task list
(one task per asset) so progress is gated and visible.

## Run folder
```
./johnwick-runs/<target>-<YYYY-MM-DD>/
  scope.txt        # in-scope + out-of-scope, verbatim from the user
  coverage.jsonl   # one row per asset — the source of truth for "done"
  assets/  js/  api/  auth/  findings/  notes.md
```

## Row schema
```json
{"asset":"api.target.com","type":"subdomain","in_scope":true,
 "recon":"untested","js_read":"untested","authed_mapped":"untested",
 "hunted":[],"status":"untested","evidence":""}
```
Fields progress `untested → done` (or `status: covered`). `hunted[]` accumulates the classes run against
the asset (see Phase 5 checklist): `idor`, `ssrf`, `rce`, `ssti`, `xxe`, `sqli`, `smuggling`, `cache`,
`race`, `auth`, `graphql`, `bypass-403`, `web-misc`, `mass-assign`, `logic`, `mobile`. A row is `covered` only when
every class the surface exposes appears here.

## Init + enroll (Phase 0)
```bash
RUN="johnwick-runs/${TARGET}-$(date +%F)"; mkdir -p "$RUN"/{assets,js,api,auth,findings}
: > "$RUN/coverage.jsonl"
# enroll every in-scope subdomain (assets/subs.txt) as an untested row
while read a; do
  jq -cn --arg a "$a" '{asset:$a,type:"subdomain",in_scope:true,recon:"untested",
    js_read:"untested",authed_mapped:"untested",hunted:[],status:"untested",evidence:""}' \
    >> "$RUN/coverage.jsonl"
done < "$RUN/assets/subs.txt"
```

## Mark a field done (per asset)
```bash
# example: mark recon done for one asset
jq -c 'if .asset=="api.target.com" then .recon="done" else . end' coverage.jsonl > t && mv t coverage.jsonl
# append a hunt skill
jq -c 'if .asset=="api.target.com" then .hunted+=["idor"] else . end' coverage.jsonl > t && mv t coverage.jsonl
```

## Completion checks (the invariant — run at every phase gate)
```bash
# recon phase incomplete rows:
jq -c 'select(.in_scope and (.recon!="done" or .js_read!="done"))' coverage.jsonl
# authed-map incomplete:
jq -c 'select(.in_scope and .authed_mapped!="done")' coverage.jsonl
# hunt incomplete:
jq -c 'select(.in_scope and .status!="covered")' coverage.jsonl
# whole-run invariant — MUST print 0:
jq -s '[.[]|select(.in_scope and .status!="covered")]|length' coverage.jsonl
```

**The run is complete only when the whole-run invariant prints `0` and no field is `untested`.** If any
query returns rows, name them, finish them, and re-run — this is exactly the Rule-1 no-skip guarantee,
verified per `superpowers:verification-before-completion` (see [phase-gates.md](phase-gates.md)).
