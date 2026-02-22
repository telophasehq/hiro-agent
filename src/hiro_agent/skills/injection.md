# Injection & Input Validation

## What to investigate

- Map all API routes/endpoints — read every route handler
- For each endpoint: trace user input from request → processing → output/storage
- Read all database query construction — are queries parameterized?
- Check template rendering — is user input escaped before insertion?
- Read file operation code — is user input used in file paths?
- Check any subprocess/shell invocations — is user input sanitized?

## What to grep for

```
# SQL injection
SELECT.*\+|INSERT.*\+|UPDATE.*\+|DELETE.*\+
f"SELECT|f"INSERT|f"UPDATE|f"DELETE
.format(.*SELECT|.format(.*INSERT
execute(.*%|execute(.*\+|executeQuery.*\+
cursor.execute(.*f"|cursor.execute(.*format
raw(|rawQuery|$where|aggregate.*\$

# Command injection
os.system(|os.popen(|subprocess.Popen(.*shell=True
subprocess.call(.*shell=True|subprocess.run(.*shell=True
child_process.exec(|child_process.spawn(.*shell
Runtime.exec(|ProcessBuilder
exec(|eval(|Function(|compile(

# XSS
innerHTML|outerHTML|document.write(
dangerouslySetInnerHTML|v-html|[innerHTML]
|safe|mark_safe|Markup(|raw(
render_template_string|Template(.*user

# SSRF
requests.get(.*user|urllib.urlopen(.*user|fetch(.*user
http.get(.*req|HttpClient.*user|curl_exec
# Check for URL allowlisting

# Path traversal
open(.*user|readFile(.*user|os.path.join(.*user
Path(.*user|file_get_contents(.*\$
# Look for ../  sanitization

# Deserialization
pickle.loads|pickle.load|yaml.load(
ObjectInputStream|readObject(|unserialize(
BinaryFormatter|torch.load(|numpy.load(
JSON.parse(.*eval|json_decode.*exec

# XML injection
XMLParser|etree.parse|DocumentBuilder
ENTITY|DOCTYPE|xml.sax|lxml.etree
# Check for XXE protection
```

## What to look for

- SQL injection — string concatenation/f-strings in queries instead of parameterized queries
- Command injection — user input in subprocess/exec without sanitization
- XSS (reflected/stored) — user input rendered in HTML without context-specific escaping
- SSRF — user-supplied URLs fetched server-side without domain/IP allowlist validation
- Path traversal — user input in file paths without canonicalization and prefix checking
- Template injection (SSTI) — user input in template strings
- Open redirects — user-supplied redirect URLs without domain validation
- Header injection — user input in HTTP response headers (CRLF injection)
- XML external entity (XXE) — XML parsers with external entity processing enabled
- Unsafe deserialization — pickle/yaml.load/ObjectInputStream on untrusted data
- Missing Content-Type validation on file uploads
- Missing request body size limits
- Error responses that leak stack traces, internal paths, or database schema
- Mass assignment — entire request body bound to model without field allowlisting

## Cross-reference with infrastructure

- Check if a WAF is deployed that might catch injection attempts (but don't rely on it)
- Check API gateway config for request validation, body size limits
- Check if error pages are configured to hide stack traces in production
