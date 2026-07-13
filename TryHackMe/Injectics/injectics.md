# Injectics — SQLi to Twig SSTI

> **Takeaway:** Three input-handling flaws chained from a public login bypass to server-side file disclosure.

| Field | Details |
| --- | --- |
| Platform | TryHackMe |
| Category | Web application security |
| Completion date | 2026-07-13 |
| Skills practised | SQL injection, stacked queries, authentication bypass, SSTI, dependency analysis |

## Executive summary

Injectics trusted request data as SQL in both its login flow and the leaderboard edit page available to `dev`. The first flaw created a `dev` session; the second deleted the application user table and triggered a seed service that restored known default accounts. After logging in as administrator, I found that profile data was rendered as Twig source. Twig 2.14.0 and a dynamic `sort` callback provided command execution, allowing the final proof to be read from the server-side `flags/` directory.

```text
mail.log → login SQLi → dev session → stacked SQLi → account seed
→ administrator login → Twig SSTI → server-side flag read
```

## Exploitation path

### 1. Reconnaissance

RustScan identified SSH and an Apache/PHP web application. Content discovery exposed `login.php`, `dashboard.php`, `adminlogin007.php`, `flags/`, and a `mail.log` file.

![Gobuster enumeration revealing the application routes and flags directory](./evidence/Immagine%202026-07-13%20222452.png)

*Gobuster identified the public PHP endpoints and the `flags/` directory.*

The main clue was in the public page source:

![Source comments disclosing the developer email and mail log](./evidence/Immagine%202026-07-13%20222848.png)

`mail.log` provided a valid account email and documented a service that recreated default accounts when the application user table was missing or corrupt. This made the login form and database write paths the highest-priority targets.

![Mail log describing the default-account seed service](./evidence/Immagine%202026-07-13%20222942.png)

### 2. Login SQL injection → `dev` session

The `username` parameter in `login.php` was concatenated into a MySQL query. Using the email recovered from the log, I closed the string, added an always-true condition, and commented out the password predicate:

```http
POST /login.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=<email from mail.log>' || 1=1; -- +&password=<arbitrary>&function=login
```

In form encoding, `+` supplies the whitespace required after MySQL's `--` comment marker. The server created a session as `dev`, granting access to `dashboard.php` without validating the password.

![Successful login response following the SQLi bypass](./evidence/Immagine%202026-07-13%20223240.png)

### 3. Leaderboard edit SQLi → default administrator account

From the `dev` dashboard, I reached the leaderboard edit page. Although the medal values were numeric, `gold`, `silver`, and `bronze` were submitted as text and the backend accepted stacked SQL statements.

I inserted a numeric prefix followed by a redacted `DROP TABLE` statement against the application user table. The page responded with `Error updating data`, but the secondary statement had executed. This is an important distinction: the visible update failed, while the injected side effect persisted.

![Stacked SQL statement placed in a leaderboard medal field](./evidence/Immagine%202026-07-13%20223315.png)

The missing table activated the recovery/seed service described in `mail.log`. It recreated the known default accounts, allowing administrator authentication at `adminlogin007.php`.

![InjecticsService reporting that it is restoring the deleted database table](./evidence/Immagine%202026-07-13%20223338.png)

![Administrator dashboard after logging in with the restored account](./evidence/Immagine%202026-07-13%20223541.png)

### 4. Administrator profile SSTI → flag read

The administrator profile update endpoint accepted `email`, `fname`, and `lname`. `composer.json` disclosed:

```json
"twig/twig": "2.14.0"
```

Saving the following expression in a rendered profile field produced `Welcome 49`:

```twig
{{7*7}}
```

![Arithmetic SSTI payload saved in the profile field](./evidence/Immagine%202026-07-13%20223726.png)

This confirmed that user-controlled profile data was being compiled as Twig template source. Twig 2.14.0 falls within the affected range for CVE-2022-23614. The vulnerable `sort` callback accepted a non-closure PHP function name; a diagnostic callback confirmed invocation, and an output-capable PHP function provided command execution.

![The expression is evaluated server-side and renders as Welcome 49](./evidence/Immagine%202026-07-13%20223807.png)

![Twig sort callback payload using an output-capable PHP function](./evidence/Immagine%202026-07-13%20223929.png)

The web process could access the application-relative `flags/` directory. Listing the directory and reading the discovered file through the SSTI returned the final proof.

![Redacted proof returned by reading the file through the Twig SSTI](./evidence/Immagine%202026-07-13%20224039.png)

## Lessons learned

The key was following the application’s own clues. `mail.log` did more than expose an email: it described the account-recovery behaviour that made the leaderboard injection valuable. The final stage also showed why a dependency version should guide validation, not replace it: `{{7*7}}` proved SSTI before the Twig-specific callback technique was tested.

## Tools and reference

| Tool / source | Purpose |
| --- | --- |
| RustScan and Gobuster | Service and route discovery |
| Burp Suite | Request capture, replay, and controlled validation |
| Composer manifest | Identified Twig 2.14.0 |
| [Twig CVE-2022-23614 advisory](https://github.com/twigphp/Twig/security/advisories/GHSA-5mv2-rx3q-4w2v) | Documents the affected `sort` callback behaviour; fixed in Twig 2.14.11 |
