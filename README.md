Domain Security Scanner Tool
============================

This Python-based tool performs a comprehensive security scan of a domain, checking for missing security headers, publicly accessible sensitive files, and directories. It also provides an optional Shodan integration for further IP analysis.

Features:
---------

1. **Security Headers Check**: 
   - Scans a domain for important security headers such as:
     X-Frame-Options, X-Content-Type-Options, Content-Security-Policy,
     Strict-Transport-Security, X-XSS-Protection, Referrer-Policy,
     Permissions-Policy, Cache-Control, Set-Cookie, Expect-CT,
     Access-Control-Allow-Origin, Feature-Policy, Public-Key-Pins,
     X-Permitted-Cross-Domain-Policies.

2. **Sensitive Files and Directories Detection**:
   - Scans for publicly accessible sensitive files:
     .env, config.php, wp-config.php, db.php, backup.zip, database.sql, docker-compose.yml, etc.
   - Scans for sensitive directories:
     admin, backup, logs, uploads, .git, .svn, cgi-bin, tmp, etc.

3. **Shodan Integration (Optional)**:
   - Allows scanning the domain's IP using Shodan to gather information about open ports, services, vulnerabilities, and more.
   - Prompts the user for a Shodan API key, with an option to save the key for future use.

4. **Multithreaded Scanning**:
   - Utilizes multithreading for faster scans of files, directories, and headers.
   - Users can configure the number of threads.

5. **Comprehensive Report Generation**:
   - Generates a detailed JSON report containing:
     - Security headers found/missing
     - Sensitive files and directories status (found/forbidden)
     - Shodan scan results (if applicable)
     - Scan duration and timestamp.

Installation:
-------------

1. Clone the repository:

   git clone https://github.com/yourusername/domain-security-scanner.git
   cd domain-security-scanner

2. Install the required dependencies:

   pip install -r requirements.txt

   Ensure the following are installed:
   - requests
   - shodan
   - tqdm
   - concurrent.futures (for Python < 3.2)

3. (Optional) Install additional dependencies on Debian/Ubuntu:

   sudo apt-get install python3-dev gcc libssl-dev

Usage:
------

Run the tool using:

   python domain-scanner.py

User Prompts:
-------------

- **Domain Input**: The tool will prompt you to enter the domain to scan (e.g., https://example.com).
- **Thread Count**: You can specify the number of threads for scanning (default is 5).
- **Shodan Integration**: The tool will ask if you want to perform a Shodan scan. If yes, provide your Shodan API key, with an option to save it for future use.

Example:

   python domain-scanner
