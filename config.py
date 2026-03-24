"""Scanner configuration and constants."""

from pathlib import Path
from urllib.parse import urlparse

# Timeouts (seconds)
HTTP_TIMEOUT = 10
PORT_TIMEOUT = 2
WHOIS_TIMEOUT = 15
DNS_TIMEOUT = 10
NVD_TIMEOUT = 20
NVD_DELAY = 3  # delay between NVD API requests (rate limit: 5 req / 30s)

# Concurrency
MAX_CONCURRENT_SITES = 5
MAX_CONCURRENT_PORTS = 50
MAX_CONCURRENT_REQUESTS = 20

# Paths
REPORTS_DIR = Path("./reports")

# HTTP
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Top 100 TCP ports
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143,
    161, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544,
    548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1080, 1110, 1433, 1434, 1521, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4443,
    4848, 5000, 5001, 5050, 5060, 5101, 5190, 5357, 5432, 5631, 5666,
    5800, 5900, 5901, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 9443, 9999, 10000,
    10443, 27017, 27018,
]

# Directory bruteforce wordlist (~200 common paths)
WORDLIST = [
    # Admin panels
    "admin", "admin/login", "administrator", "wp-admin", "wp-login.php",
    "cpanel", "dashboard", "panel", "manager", "webadmin", "siteadmin",
    "controlpanel", "adminpanel", "management",
    # Sensitive files
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git", ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".hg", ".htaccess", ".htpasswd",
    "web.config", "config.php", "config.yml", "config.json",
    "configuration.php", "settings.php", "settings.py", "local_settings.py",
    "database.yml", "wp-config.php", "wp-config.php.bak",
    # Backups
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "site.zip", "www.zip", "db.sql", "dump.sql", "database.sql",
    "old", "bak", "backups", "data.sql",
    # API endpoints
    "api", "api/v1", "api/v2", "api/v3", "api/swagger", "api/docs",
    "api/health", "api/status", "graphql", "graphiql",
    "swagger", "swagger-ui", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml", "docs", "redoc",
    # Debug & development
    "debug", "test", "testing", "dev", "development",
    "phpinfo.php", "info.php", "server-info", "server-status",
    "elmah.axd", "trace.axd", "console", "terminal",
    # Frameworks
    "phpmyadmin", "pma", "adminer", "adminer.php",
    "wp-content", "wp-includes", "wp-json", "wp-cron.php",
    "artisan", "telescope", "horizon",
    "rails/info", "rails/mailers",
    # Authentication
    "login", "signin", "sign-in", "auth", "authenticate",
    "logout", "register", "signup", "sign-up",
    "forgot-password", "reset-password",
    "oauth", "oauth/authorize", "oauth/token", "sso",
    ".well-known/openid-configuration",
    # Well-known
    ".well-known/", ".well-known/security.txt",
    ".well-known/assetlinks.json", ".well-known/apple-app-site-association",
    "security.txt", "robots.txt", "sitemap.xml",
    "humans.txt", "crossdomain.xml", "manifest.json",
    "favicon.ico", "browserconfig.xml",
    # Common directories
    "assets", "static", "media", "uploads", "files",
    "images", "img", "css", "js", "fonts",
    "public", "private", "internal", "secret", "hidden",
    "tmp", "temp", "cache", "logs", "log",
    # Monitoring & health
    "health", "healthcheck", "health-check",
    "status", "ping", "ready", "alive",
    "metrics", "prometheus", "grafana", "monitoring",
    # CI/CD & DevOps
    ".github", ".gitlab-ci.yml", ".circleci",
    "Dockerfile", "docker-compose.yml", "Makefile",
    "Jenkinsfile", "Procfile", ".travis.yml", "Vagrantfile",
    # Node.js
    "node_modules", "package.json", "package-lock.json", "yarn.lock", ".npmrc",
    # Python
    "requirements.txt", "Pipfile", "pyproject.toml", "manage.py",
    # Java
    "WEB-INF", "WEB-INF/web.xml", "META-INF",
    # Misc
    "cgi-bin", "vendor", "lib", "src", "app", "application",
    "portal", "intranet", "forum", "blog", "shop", "store",
    "mail", "webmail", "email", "ftp",
    "xmlrpc.php", "install", "install.php", "setup", "setup.php",
    "readme.md", "README.md", "CHANGELOG.md", "LICENSE",
    "server", "service", "services", "soap", "wsdl",
    "ckeditor", "tinymce", "uploads/shell", "shell.php",
    "cmd", "command", "exec", "system", "temp/logs",
]

# Technology detection signatures
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "Express": "Express.js", "PHP": "PHP", "ASP.NET": "ASP.NET",
            "Next.js": "Next.js", "Nuxt": "Nuxt.js",
        },
        "Server": {
            "nginx": "Nginx", "Apache": "Apache", "Microsoft-IIS": "IIS",
            "cloudflare": "Cloudflare", "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn", "Kestrel": "Kestrel", "LiteSpeed": "LiteSpeed",
            "Caddy": "Caddy", "openresty": "OpenResty",
        },
    },
    "html": {
        "React": ("__NEXT_DATA__", "react.production", "_reactRoot"),
        "Vue.js": ("__VUE__", "vue.js", "vuejs.org"),
        "Angular": ("ng-version", "angular.io"),
        "Next.js": ("__NEXT_DATA__", "_next/static"),
        "Nuxt.js": ("__NUXT__", "_nuxt/"),
        "Svelte": ("__svelte", "svelte-"),
        "WordPress": ("wp-content", "wp-includes", "wordpress"),
        "Django": ("csrfmiddlewaretoken",),
        "Laravel": ("laravel_session",),
        "FastAPI": ("fastapi", "swagger-ui", "openapi.json"),
        "jQuery": ("jquery.min.js", "jquery/"),
        "Bootstrap": ("bootstrap.min.css", "bootstrap.min.js"),
        "Tailwind": ("tailwindcss",),
    },
}

# Security headers to check
SECURITY_HEADERS = {
    "Content-Security-Policy": {"required": True},
    "X-Content-Type-Options": {"required": True, "expected": "nosniff"},
    "X-Frame-Options": {"required": True, "expected": ["DENY", "SAMEORIGIN"]},
    "Strict-Transport-Security": {"required": True},
    "Permissions-Policy": {"required": False},
    "Referrer-Policy": {"required": True},
}


def parse_target(raw: str) -> dict:
    """Parse a raw URL/domain into structured target info."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    domain = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    port = parsed.port
    base = f"{scheme}://{domain}"
    if port and port not in (80, 443):
        base += f":{port}"
    return {"raw": raw, "url": base, "domain": domain, "scheme": scheme}
