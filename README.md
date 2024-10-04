Domain Security Scanner Tool
This Python-based tool performs a comprehensive security scan of a domain, checking for missing security headers, publicly accessible sensitive files, and directories. It also provides an optional Shodan integration for further IP analysis.

Features
Security Headers Check: Scans a domain for important security headers such as:

X-Frame-Options, X-Content-Type-Options, Content-Security-Policy
Strict-Transport-Security, X-XSS-Protection, Referrer-Policy
Permissions-Policy, Cache-Control, Set-Cookie, Expect-CT
Access-Control-Allow-Origin, Feature-Policy, Public-Key-Pins
X-Permitted-Cross-Domain-Policies
Sensitive Files and Directories Detection: Scans for publicly accessible sensitive files:

.env, config.php, wp-config.php, db.php, backup.zip, database.sql, docker-compose.yml, etc.
And sensitive directories:

admin, backup, logs, uploads, .git, .svn, cgi-bin, tmp, etc.
Shodan Integration (Optional):

Allows scanning the domain's IP using Shodan to gather information about open ports, services, vulnerabilities, and more.
Prompts the user for a Shodan API key, with an option to save the key for future use.
Multithreaded Scanning:

Utilizes multithreading for faster scans of files, directories, and headers.
Users can configure the number of threads.
Comprehensive Report Generation:

Generates a detailed JSON report containing:
Security headers found/missing
Sensitive files and directories status (found/forbidden)
Shodan scan results (if applicable)
Scan duration and timestamp.
