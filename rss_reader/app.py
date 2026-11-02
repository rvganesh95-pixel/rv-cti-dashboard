from flask import Flask, render_template, jsonify, request
import feedparser
import re
import requests
import os
import json
from datetime import datetime
from dateutil import parser as dateparser
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

load_dotenv()

app = Flask(__name__)

# Horizon Scans - Threat Intelligence RSS feeds
HORIZON_FEEDS = {
    "Unit 42": "https://unit42.paloaltonetworks.com/feed/",
    "Cybersecurity News": "https://cybersecuritynews.com/feed/",
    "Trend Micro": "https://www.trendmicro.com/en_us/research.html/rss",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default",
    "Microsoft Security": "https://www.microsoft.com/en-us/security/blog/feed/",
    "SentinelOne Labs": "https://www.sentinelone.com/labs/feed/",
    "Varonis": "http://blog.varonis.com/category/varonis_news/feed",
    "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
    "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
    "Sophos": "https://news.sophos.com/en-us/feed/",
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Hackread": "https://hackread.com/feed/",
    "Infosecurity Magazine": "https://www.infosecurity-magazine.com/rss/news/",
    "The Record": "https://therecord.media/feed",
    "Security Affairs": "https://securityaffairs.com/feed",
    "SecurityWeek": "https://www.securityweek.com/feed/",
}

# Vulnerability Dashboard - Security Advisory RSS feeds
VULN_FEEDS = {
    "Palo Alto Security Advisories": "https://security.paloaltonetworks.com/rss.xml",
    "Fortinet PSIRT": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    "Cisco Security Advisories": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "Cisco Talos Blog": "https://blog.talosintelligence.com/feeds/posts/default",
    "Cisco Vulnerability Alerts": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAlert.xml",
    "VMware Security Advisories": "https://www.vmware.com/security/advisories.xml",
    "CISA Known Exploited Vulnerabilities": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "NVD CVE Feed": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    "Juniper Security Advisories": "https://supportportal.juniper.net/s/security-advisory-rss",
    "IBM Security Bulletins": "https://www.ibm.com/blogs/psirt/feed/",
    "Splunk Security Advisories": "https://advisory.splunk.com/feed.xml",
    "Microsoft Security Advisories": "https://api.msrc.microsoft.com/update-guide/rss",
    "F5 Security Advisories": "https://my.f5.com/manage/s/new-updated-rss?type=Security+Advisory",
    "F5 Labs": "https://www.f5.com/labs/rss-feeds/all.xml",
}

# NPM Supply Chain Security - Package Security RSS feeds
NPM_FEEDS = {
    "Snyk Blog": "https://snyk.io/blog/feed/",
    "GitHub Security Blog": "https://github.blog/tag/security/feed/",
    "Sonatype Blog": "https://blog.sonatype.com/rss.xml",
    "Aikido Security": "https://www.aikido.dev/blog/rss.xml",
    "Wiz Blog": "https://www.wiz.io/feed/rss.xml",
    "Socket": "https://socket.dev/api/blog/feed.atom",
    "StepSecurity": "https://www.stepsecurity.io/blog/rss.xml",
    "ReversingLabs": "https://blog.reversinglabs.com/blog/rss.xml",
    "JFrog Security Research": "https://jfrog.com/blog/tag/security-research/feed/",
}


def parse_date(date_str):
    """Parse date string to ISO format."""
    if not date_str:
        return ""
    try:
        return dateparser.parse(date_str).isoformat()
    except Exception:
        return date_str


def fetch_feed(name, url):
    """Fetch and parse a single RSS feed - only latest 10 articles."""
    try:
        feed = feedparser.parse(url)
        articles = []
        for entry in feed.entries[:10]:
            published = ""
            if hasattr(entry, "published"):
                published = entry.published
            elif hasattr(entry, "updated"):
                published = entry.updated

            tags = []
            if hasattr(entry, "tags"):
                tags = [t.get("term", "") for t in entry.tags[:3]]

            articles.append({
                "title": entry.get("title", "No title"),
                "link": entry.get("link", "#"),
                "published": published,
                "published_iso": parse_date(published),
                "summary": entry.get("summary", "")[:300],
                "source": name,
                "tags": tags,
            })
        return {"name": name, "url": url, "articles": articles, "error": None}
    except Exception as e:
        return {"name": name, "url": url, "articles": [], "error": str(e)}


def fetch_all_feeds(feed_dict):
    """Fetch all RSS feeds concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(fetch_feed, name, url): name
            for name, url in feed_dict.items()
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda x: x["name"])
    return results


@app.route("/")
def index():
    return render_template("horizon.html")


@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html")


@app.route("/npm")
def npm():
    return render_template("npm.html")


@app.route("/ransomware")
def ransomware():
    return render_template("ransomware.html")


@app.route("/api/ransomware/victims")
def ransomware_victims():
    """Fetch recent ransomware victims from ransomware.live API."""
    sector = request.args.get("sector", "")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        url = "https://data.ransomware.live/victims.json"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Filter by sector if specified
        if sector:
            data = [v for v in data if v.get("activity", "").lower() == sector.lower()]
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ransomware/groups")
def ransomware_groups():
    """Fetch list of ransomware groups."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resp = requests.get("https://data.ransomware.live/groups.json", headers=headers, timeout=30)
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/adversaries")
def adversaries():
    return render_template("adversaries.html")


# --- APT Groups Storage (in-memory, persisted to JSON file) ---
APT_GROUPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apt_groups.json")


def load_apt_groups():
    """Load APT groups from JSON file."""
    if os.path.exists(APT_GROUPS_FILE):
        with open(APT_GROUPS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_apt_groups(groups):
    """Save APT groups to JSON file."""
    with open(APT_GROUPS_FILE, "w", encoding="utf-8") as f:
        json.dump(groups, f, indent=2, ensure_ascii=False)


@app.route("/api/apt-groups", methods=["GET"])
def get_apt_groups():
    """Get all saved APT groups."""
    return jsonify(load_apt_groups())


@app.route("/api/apt-groups", methods=["POST"])
def add_apt_group():
    """Save a new APT group report."""
    data = request.get_json()
    groups = load_apt_groups()
    data["id"] = str(len(groups) + 1)
    data["created_at"] = datetime.now().isoformat()
    groups.append(data)
    save_apt_groups(groups)
    return jsonify({"message": "APT group saved", "id": data["id"]}), 201


@app.route("/api/apt-groups/<group_id>", methods=["DELETE"])
def delete_apt_group(group_id):
    """Delete an APT group report."""
    groups = load_apt_groups()
    groups = [g for g in groups if g.get("id") != group_id]
    save_apt_groups(groups)
    return jsonify({"message": "Deleted"})


@app.route("/api/apt-groups/generate-report", methods=["POST"])
def generate_apt_report():
    """Generate APT group report from URLs using AI."""
    data = request.get_json()
    urls = data.get("urls", [])
    token = data.get("token", "").strip()

    if not urls:
        return jsonify({"error": "At least one URL is required"}), 400

    if not token:
        token = os.environ.get("OPENAI_API_KEY", "")
    if not token:
        return jsonify({"error": "OpenAI API key is required"}), 400

    # Fetch content from all URLs
    all_text = ""
    citations = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    for url in urls:
        url = url.strip()
        if not url:
            continue
        try:
            resp = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.decompose()
            page_text = soup.get_text(separator=" ", strip=True)
            all_text += f"\n\n--- Source: {url} ---\n{page_text[:5000]}"
            citations.append(url)
        except Exception:
            citations.append(f"{url} (failed to fetch)")

    if not all_text.strip():
        return jsonify({"error": "Could not extract content from any of the URLs"}), 400

    # Send to OpenAI API
    system_prompt = """You are a cybersecurity threat intelligence analyst. Generate a comprehensive APT group report based on the provided intelligence sources.

Return a JSON object with these exact fields:
{
  "name": "APT group name",
  "aliases": ["list", "of", "known", "aliases"],
  "type": "e.g., Nation state actor sponsored by...",
  "origin": "Country of origin",
  "sponsor": "Sponsoring entity",
  "motivation": "Primary motivation",
  "specialty": "Key capabilities/techniques",
  "first_seen": "Date first observed",
  "last_seen": "Date last observed",
  "target_sectors": ["list", "of", "sectors"],
  "target_locations": ["list", "of", "countries"],
  "executive_summary": "2-3 paragraph executive summary",
  "key_points": ["point 1", "point 2", "point 3", "point 4", "point 5"],
  "assessment": "Assessment paragraph about this group",
  "target_rationale": "Why this group is important, what makes them significant",
  "diamond_model": {
    "adversary": "Description of the adversary",
    "victim": "Description of victims and notable attacks",
    "capabilities": "Tools, malware, and techniques used",
    "infrastructure": "C2 servers, delivery systems, support infrastructure"
  },
  "ttps": ["TTP 1", "TTP 2", "TTP 3"],
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3", "recommendation 4", "recommendation 5"]
}

Return ONLY the JSON object, no explanations."""

    user_prompt = f"""Based on the following intelligence sources, generate a comprehensive APT group threat intelligence report.

Intelligence Sources:
{all_text[:12000]}

Generate the report as a JSON object."""

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()
        content = result["choices"][0]["message"]["content"]

        # Extract JSON
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)

        report = json.loads(content)
        report["citations"] = citations
        report["intelligence_cutoff_date"] = datetime.now().strftime("%Y-%m-%d")

        return jsonify(report)

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("error", {}).get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"AI API error: {error_msg}"}), 502
    except json.JSONDecodeError:
        return jsonify({"error": "Failed to parse AI response"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/knowledgegraph")
def knowledgegraph():
    return render_template("knowledgegraph.html")


@app.route("/api/knowledgegraph/generate", methods=["POST"])
def generate_knowledgegraph():
    """Generate knowledge graph triples from input text using Claude Sonnet via GitHub Models."""
    data = request.get_json()
    input_text = data.get("text", "").strip()

    if not input_text:
        return jsonify({"error": "Text input is required"}), 400

    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not github_token:
        return jsonify({"error": "GITHUB_TOKEN environment variable is not set"}), 500

    # Chunk text if too long (max ~3000 words per chunk)
    words = input_text.split()
    chunk_size = 3000
    chunks = []
    for i in range(0, len(words), chunk_size):
        chunks.append(" ".join(words[i:i + chunk_size]))

    all_triples = []

    system_prompt = """You are a knowledge graph extraction expert. Your task is to extract structured knowledge from the given text as subject-predicate-object triples.

Rules:
- Extract entities (people, organizations, technologies, concepts, events, locations) as subjects/objects
- Use clear, concise relationship labels as predicates (e.g., "invented", "is part of", "located in", "caused", "uses")
- Keep entity names concise but specific
- Return ONLY a JSON array of objects with "subject", "predicate", and "object" fields
- Extract as many meaningful relationships as possible
- Do not include any explanation, just the JSON array"""

    user_prompt_template = """Extract all knowledge graph triples (subject-predicate-object) from the following text. Return ONLY a valid JSON array.

Text:
```
{text}
```"""

    try:
        for chunk in chunks:
            user_prompt = user_prompt_template.format(text=chunk)

            resp = requests.post(
                "https://models.inference.ai.azure.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 4096,
                },
                timeout=90,
            )
            resp.raise_for_status()
            result = resp.json()
            content = result["choices"][0]["message"]["content"]

            # Extract JSON from response (handle markdown code blocks)
            content = content.strip()
            if content.startswith("```"):
                content = re.sub(r"^```(?:json)?\s*", "", content)
                content = re.sub(r"\s*```$", "", content)

            triples = json.loads(content)

            # Validate triples
            for t in triples:
                if isinstance(t, dict) and "subject" in t and "predicate" in t and "object" in t:
                    all_triples.append({
                        "subject": str(t["subject"]).strip(),
                        "predicate": str(t["predicate"]).strip(),
                        "object": str(t["object"]).strip(),
                    })

        return jsonify({
            "triples": all_triples,
            "count": len(all_triples),
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("error", {}).get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"OpenAI API error: {error_msg}"}), 502
    except json.JSONDecodeError:
        return jsonify({"error": "Failed to parse LLM response as JSON"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/feeds/add", methods=["POST"])
def add_feed():
    """Add a new RSS feed."""
    data = request.get_json()
    name = data.get("name", "").strip()
    url = data.get("url", "").strip()
    dashboard = data.get("dashboard", "horizon")
    feed_dict = HORIZON_FEEDS if dashboard == "horizon" else NPM_FEEDS if dashboard == "npm" else VULN_FEEDS
    if not name or not url:
        return jsonify({"error": "Name and URL are required"}), 400
    if name in feed_dict:
        return jsonify({"error": "A feed with that name already exists"}), 409
    # Validate the feed URL by attempting to parse it
    try:
        feed = feedparser.parse(url)
        if feed.bozo and not feed.entries:
            return jsonify({"error": "Invalid or unreachable RSS feed URL"}), 400
    except Exception:
        return jsonify({"error": "Failed to fetch the feed"}), 400
    feed_dict[name] = url
    return jsonify({"message": f"Feed '{name}' added successfully", "name": name, "url": url}), 201


@app.route("/api/feeds/remove", methods=["POST"])
def remove_feed():
    """Remove an RSS feed."""
    data = request.get_json()
    name = data.get("name", "").strip()
    dashboard = data.get("dashboard", "horizon")
    feed_dict = HORIZON_FEEDS if dashboard == "horizon" else NPM_FEEDS if dashboard == "npm" else VULN_FEEDS
    if not name or name not in feed_dict:
        return jsonify({"error": "Feed not found"}), 404
    del feed_dict[name]
    return jsonify({"message": f"Feed '{name}' removed"}), 200


@app.route("/api/feeds/list")
def list_feeds():
    """List all configured feeds."""
    dashboard = request.args.get("dashboard", "horizon")
    feed_dict = HORIZON_FEEDS if dashboard == "horizon" else NPM_FEEDS if dashboard == "npm" else VULN_FEEDS
    return jsonify({"feeds": [{"name": k, "url": v} for k, v in feed_dict.items()]})


@app.route("/api/feeds")
def api_feeds():
    """API endpoint to fetch all feeds, returns unified sorted list."""
    dashboard = request.args.get("dashboard", "horizon")
    feed_dict = HORIZON_FEEDS if dashboard == "horizon" else NPM_FEEDS if dashboard == "npm" else VULN_FEEDS
    feeds = fetch_all_feeds(feed_dict)
    # Flatten all articles into one list sorted by date (newest first)
    all_articles = []
    feed_stats = []
    for feed in feeds:
        feed_stats.append({
            "name": feed["name"],
            "count": len(feed["articles"]),
            "error": feed["error"],
        })
        all_articles.extend(feed["articles"])

    # Sort by published_iso descending
    all_articles.sort(key=lambda x: x.get("published_iso", ""), reverse=True)

    return jsonify({
        "articles": all_articles,
        "stats": feed_stats,
        "total": len(all_articles),
        "fetched_at": datetime.now().isoformat(),
    })


# IOC and NPM package extraction patterns
IOC_PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.|\[?\.\]?)){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv4_defanged": re.compile(
        r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\[\.\]){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|dev|xyz|top|info|biz|ru|cn|tk|ml|ga|cf|gq|cc|pw|club|online|site|live|me)\b'
    ),
    "url": re.compile(
        r'https?://[^\s<>"\')\]}{,]+', re.IGNORECASE
    ),
}

NPM_PACKAGE_PATTERNS = [
    # Scoped packages like @scope/package
    re.compile(r'@[a-z0-9][\w\-\.]*\/[a-z0-9][\w\-\.]*', re.IGNORECASE),
    # Common npm package references in security contexts
    re.compile(
        r'(?:npm\s+(?:package|install|i)\s+|'
        r'(?:malicious|compromised|fake|backdoored)\s+(?:npm\s+)?package\s+[`"\']?)'
        r'([a-z0-9@][\w\-\.\/]*)',
        re.IGNORECASE,
    ),
    # Package names in backticks or code blocks that look like npm packages
    re.compile(r'`([a-z][a-z0-9\-\.]{1,50})`'),
]

# Common false positives to filter out - legitimate/well-known domains
DOMAIN_FALSE_POSITIVES = {
    # Social media & content platforms
    "github.com", "twitter.com", "linkedin.com", "facebook.com",
    "youtube.com", "reddit.com", "medium.com", "wordpress.com",
    "instagram.com", "tiktok.com", "discord.com", "slack.com",
    "substack.com", "hashnode.dev", "dev.to",
    # Major tech companies
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "oracle.com", "ibm.com", "intel.com", "cisco.com",
    "cloudflare.com", "akamai.com", "fastly.com",
    "amazonaws.com", "azure.com", "cloud.google.com",
    # Security vendors & tools (legitimate)
    "tenable.com", "nessus.org", "qualys.com", "rapid7.com",
    "crowdstrike.com", "sentinelone.com", "paloaltonetworks.com",
    "fortinet.com", "checkpoint.com", "fireeye.com", "mandiant.com",
    "trendmicro.com", "symantec.com", "mcafee.com", "kaspersky.com",
    "sophos.com", "eset.com", "bitdefender.com", "avast.com",
    "snyk.io", "socket.dev", "aikido.dev", "wiz.io",
    "sonarqube.com", "veracode.com", "checkmarx.com",
    "darktrace.com", "lacework.com", "aquasec.com",
    "hackerone.com", "bugcrowd.com", "synack.com",
    "virustotal.com", "shodan.io", "censys.io",
    "mitre.org", "nist.gov", "cisa.gov", "nvd.nist.gov",
    "owasp.org", "sans.org", "cve.org",
    "splunk.com", "elastic.co", "datadog.com", "sumo.com",
    "recordedfuture.com", "threatintelligenceplatform.com",
    "malwarebytes.com", "cylance.com", "carbonblack.com",
    "greenbone.net", "openvas.org", "nuclei.projectdiscovery.io",
    "intruder.io", "pentest-tools.com", "acunetix.com",
    "invicti.com", "portswigger.net", "burpsuite.net",
    # Dev tools & hosting
    "npmjs.com", "npmjs.org", "pypi.org", "rubygems.org",
    "docker.com", "hub.docker.com", "kubernetes.io",
    "gitlab.com", "bitbucket.org", "sourceforge.net",
    "stackoverflow.com", "stackexchange.com",
    "readthedocs.io", "readthedocs.org", "docs.io",
    "netlify.com", "vercel.com", "heroku.com", "render.com",
    "digitalocean.com", "linode.com", "vultr.com",
    # Common legitimate domains
    "example.com", "example.org", "example.net",
    "mozilla.org", "w3.org", "ietf.org", "iana.org",
    "wikipedia.org", "wikimedia.org", "archive.org",
    "apache.org", "nginx.com", "nginx.org",
    "letsencrypt.org", "digicert.com", "comodo.com",
    "godaddy.com", "namecheap.com", "cloudflare.net",
    "jquery.com", "bootstrapcdn.com", "cdnjs.com",
    "unpkg.com", "jsdelivr.net", "fonts.googleapis.com",
    "recaptcha.net", "gstatic.com", "googlesyndication.com",
    "doubleclick.net", "adsense.com",
    # News & blogs
    "techcrunch.com", "wired.com", "arstechnica.com",
    "zdnet.com", "theverge.com", "bleepingcomputer.com",
    "theregister.com", "securityweek.com", "threatpost.com",
    "darkreading.com", "infosecurity-magazine.com",
    "securityaffairs.com", "hackernews.com", "thehackernews.com",
    "csoonline.com", "scmagazine.com", "cyberscoop.com",
}

NPM_FALSE_POSITIVES = {
    "the", "and", "for", "this", "that", "with", "from", "not", "are",
    "was", "were", "been", "have", "has", "its", "can", "will",
    "npm", "npx", "node", "js", "json", "html", "css", "api",
    "http", "https", "www", "com", "org", "net", "dev",
}


def extract_iocs_from_text(text):
    """Extract IOCs and NPM packages from article text."""
    iocs = {
        "ipv4": [],
        "hashes": [],
        "cves": [],
        "domains": [],
        "urls": [],
        "npm_packages": [],
    }

    # Create a normalized version of text for domain/URL extraction (handle defanging)
    normalized_text = text.replace("[.]", ".").replace("[dot]", ".").replace("hxxp", "http")

    # Extract IPv4 addresses (both normal and defanged like 1.2.3[.]4)
    ips = set(IOC_PATTERNS["ipv4"].findall(text))
    # Also extract defanged IPs specifically
    defanged_ips = set(IOC_PATTERNS["ipv4_defanged"].findall(text))
    # Normalize defanged IPs: replace [.] with .
    normalized_defanged = {ip.replace("[.]", ".").replace("[dot]", ".") for ip in defanged_ips}
    ips = ips | normalized_defanged
    # Filter out common non-IOC IPs
    ips_clean = set()
    for ip in ips:
        clean_ip = ip.replace("[.]", ".").replace("[dot]", ".")
        if not clean_ip.startswith(("0.", "127.", "255.", "10.", "192.168.", "172.16.")):
            ips_clean.add(clean_ip)
    iocs["ipv4"] = sorted(ips_clean)

    # Extract hashes
    sha256 = set(IOC_PATTERNS["sha256"].findall(text))
    sha1 = set(IOC_PATTERNS["sha1"].findall(text)) - sha256
    md5 = set(IOC_PATTERNS["md5"].findall(text)) - sha1 - sha256
    hashes = []
    for h in sorted(sha256):
        hashes.append({"type": "SHA256", "value": h})
    for h in sorted(sha1):
        hashes.append({"type": "SHA1", "value": h})
    for h in sorted(md5):
        hashes.append({"type": "MD5", "value": h})
    iocs["hashes"] = hashes

    # Extract CVEs
    cves = set(IOC_PATTERNS["cve"].findall(text))
    iocs["cves"] = sorted(cves, reverse=True)

    # Extract domains (use normalized text to catch defanged domains like example[.]com)
    domains = set(IOC_PATTERNS["domain"].findall(normalized_text.lower()))
    # Filter out known legitimate domains and their subdomains
    filtered_domains = set()
    for d in domains:
        # Check if domain or any parent domain is in the false positives list
        is_legit = False
        for fp in DOMAIN_FALSE_POSITIVES:
            if d == fp or d.endswith("." + fp):
                is_legit = True
                break
        if not is_legit:
            filtered_domains.add(d)
    iocs["domains"] = sorted(filtered_domains)

    # Extract suspicious URLs (use normalized text for hxxp:// defanged URLs)
    urls = set(IOC_PATTERNS["url"].findall(normalized_text))
    # Only keep URLs that aren't from well-known legitimate sites
    suspicious_urls = []
    for url in urls:
        lower_url = url.lower()
        if not any(fp in lower_url for fp in DOMAIN_FALSE_POSITIVES):
            suspicious_urls.append(url.rstrip(".,;:)]}"))
    iocs["urls"] = sorted(set(suspicious_urls))[:20]

    # Extract NPM packages
    npm_packages = set()

    # Scoped packages
    scoped = NPM_PACKAGE_PATTERNS[0].findall(text)
    for pkg in scoped:
        npm_packages.add(pkg.lower())

    # Packages mentioned in security context
    context_matches = NPM_PACKAGE_PATTERNS[1].findall(text)
    for pkg in context_matches:
        pkg_clean = pkg.strip("`\"' ").lower()
        if len(pkg_clean) > 2 and pkg_clean not in NPM_FALSE_POSITIVES:
            npm_packages.add(pkg_clean)

    # Packages in backticks (common in blog posts)
    backtick_matches = NPM_PACKAGE_PATTERNS[2].findall(text)
    # Only include if they look like real package names (contain hyphen or are known patterns)
    for pkg in backtick_matches:
        pkg_lower = pkg.lower()
        if (("-" in pkg_lower or pkg_lower.startswith("@"))
                and len(pkg_lower) > 3
                and pkg_lower not in NPM_FALSE_POSITIVES):
            npm_packages.add(pkg_lower)

    iocs["npm_packages"] = sorted(npm_packages)

    return iocs


@app.route("/api/extract-iocs", methods=["POST"])
def extract_iocs():
    """Fetch article content and extract IOCs and NPM packages."""
    data = request.get_json()
    url = data.get("url", "").strip()
    title = data.get("title", "")
    summary = data.get("summary", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Start with title and summary text
    full_text = f"{title} {summary} "

    # Fetch the full article content
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Remove script and style elements
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        # Try to extract only the main article body to avoid sidebar/ad content
        article_body = None
        # Common article body selectors used by major blogs (ordered specific to generic)
        selectors = [
            "#articlebody",                     # The Hacker News
            ".articlebody",                     # The Hacker News (class)
            ".post-body",                       # Blogger-based sites
            ".article-content",                 # Common pattern
            ".entry-content",                   # WordPress
            ".post-content",                    # WordPress
            "[itemprop='articleBody']",          # Schema.org markup
            ".story-body",                      # News sites
            "article",                          # Standard HTML5 article tag (last - can be small widgets)
            "main",                             # HTML5 main tag
            "#content",                         # Common ID
        ]
        for selector in selectors:
            candidate = soup.select_one(selector)
            if candidate and len(candidate.get_text(strip=True)) > 500:
                article_body = candidate
                break

        if article_body:
            # Remove any sidebar/related content within the article
            for tag in article_body.select(".sidebar, .related-posts, .recommended, .widget, aside"):
                tag.decompose()
            page_text = article_body.get_text(separator=" ", strip=True)
        else:
            # Fallback: use full page text
            page_text = soup.get_text(separator=" ", strip=True)
        full_text += page_text
    except Exception as e:
        # If we can't fetch, still extract from title/summary
        pass

    # Extract IOCs
    iocs = extract_iocs_from_text(full_text)

    # Determine if article has relevant content
    has_content = (
        len(iocs["ipv4"]) > 0
        or len(iocs["hashes"]) > 0
        or len(iocs["cves"]) > 0
        or len(iocs["domains"]) > 0
        or len(iocs["npm_packages"]) > 0
    )

    return jsonify({
        "iocs": iocs,
        "has_content": has_content,
        "source_url": url,
    })


# MITRE ATT&CK TTP keyword mapping for rule-based extraction
MITRE_TTP_RULES = [
    # Initial Access
    {"tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing", "keywords": ["phishing", "spear-phishing", "spearphishing", "phish email", "malicious email", "lure document", "social engineering email"]},
    {"tactic": "Initial Access", "technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "keywords": ["malicious attachment", "weaponized document", "macro-enabled", "infected attachment", "trojanized document", "malicious word", "malicious excel", "malicious pdf"]},
    {"tactic": "Initial Access", "technique_id": "T1566.002", "technique_name": "Spearphishing Link", "keywords": ["malicious link", "phishing link", "credential harvesting link", "click the link"]},
    {"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "keywords": ["exploit vulnerability", "remote code execution", "rce", "zero-day", "0-day", "cve-", "exploit public", "web shell", "vulnerable server", "unpatched"]},
    {"tactic": "Initial Access", "technique_id": "T1195", "technique_name": "Supply Chain Compromise", "keywords": ["supply chain", "compromised update", "trojanized package", "malicious package", "software supply chain", "dependency confusion"]},
    {"tactic": "Initial Access", "technique_id": "T1133", "technique_name": "External Remote Services", "keywords": ["vpn exploit", "rdp brute", "remote desktop", "exposed rdp", "citrix exploit", "pulse secure", "fortinet exploit"]},
    {"tactic": "Initial Access", "technique_id": "T1078", "technique_name": "Valid Accounts", "keywords": ["stolen credentials", "compromised credentials", "credential stuffing", "valid accounts", "leaked credentials", "credential theft"]},
    {"tactic": "Initial Access", "technique_id": "T1189", "technique_name": "Drive-by Compromise", "keywords": ["drive-by", "watering hole", "compromised website", "malicious redirect", "browser exploit"]},
    # Execution
    {"tactic": "Execution", "technique_id": "T1059.001", "technique_name": "PowerShell", "keywords": ["powershell", "invoke-expression", "iex", "encoded command", "powershell -enc", "powershell script"]},
    {"tactic": "Execution", "technique_id": "T1059.003", "technique_name": "Windows Command Shell", "keywords": ["cmd.exe", "command shell", "batch script", "cmd /c", "command prompt"]},
    {"tactic": "Execution", "technique_id": "T1059.005", "technique_name": "Visual Basic", "keywords": ["vbscript", "visual basic", "vba macro", "macro execution", "wscript"]},
    {"tactic": "Execution", "technique_id": "T1059.007", "technique_name": "JavaScript", "keywords": ["javascript execution", "jscript", "wscript.exe", "cscript.exe", "node.js malware"]},
    {"tactic": "Execution", "technique_id": "T1204", "technique_name": "User Execution", "keywords": ["user click", "user open", "trick the user", "social engineering", "lure the victim"]},
    {"tactic": "Execution", "technique_id": "T1203", "technique_name": "Exploitation for Client Execution", "keywords": ["browser exploit", "office exploit", "client-side exploit", "exploit kit"]},
    {"tactic": "Execution", "technique_id": "T1047", "technique_name": "WMI", "keywords": ["wmi", "wmic", "windows management instrumentation"]},
    {"tactic": "Execution", "technique_id": "T1053", "technique_name": "Scheduled Task/Job", "keywords": ["scheduled task", "cron job", "task scheduler", "schtasks"]},
    # Persistence
    {"tactic": "Persistence", "technique_id": "T1547.001", "technique_name": "Registry Run Keys", "keywords": ["registry run key", "autorun", "hkcu\\software\\microsoft\\windows\\currentversion\\run", "startup registry", "run key"]},
    {"tactic": "Persistence", "technique_id": "T1053.005", "technique_name": "Scheduled Task", "keywords": ["scheduled task persistence", "schtasks /create", "persistent scheduled task"]},
    {"tactic": "Persistence", "technique_id": "T1543.003", "technique_name": "Windows Service", "keywords": ["malicious service", "install service", "service persistence", "create service"]},
    {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation", "keywords": ["create account", "add admin", "backdoor account", "new user account"]},
    {"tactic": "Persistence", "technique_id": "T1136", "technique_name": "Create Account", "keywords": ["create new account", "net user /add", "add user"]},
    {"tactic": "Persistence", "technique_id": "T1505.003", "technique_name": "Web Shell", "keywords": ["web shell", "webshell", "china chopper", "aspx shell", "php shell"]},
    {"tactic": "Persistence", "technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "keywords": ["wmi event", "wmi persistence", "event subscription"]},
    # Privilege Escalation
    {"tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "keywords": ["privilege escalation exploit", "local privilege escalation", "lpe", "escalate privileges", "kernel exploit", "elevation of privilege"]},
    {"tactic": "Privilege Escalation", "technique_id": "T1548.002", "technique_name": "Bypass UAC", "keywords": ["bypass uac", "uac bypass", "user account control"]},
    {"tactic": "Privilege Escalation", "technique_id": "T1134", "technique_name": "Access Token Manipulation", "keywords": ["token manipulation", "token impersonation", "access token", "impersonate token"]},
    # Defense Evasion
    {"tactic": "Defense Evasion", "technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "keywords": ["obfuscated", "obfuscation", "encoded payload", "base64 encoded", "string encryption", "packed malware", "crypter"]},
    {"tactic": "Defense Evasion", "technique_id": "T1070", "technique_name": "Indicator Removal", "keywords": ["delete logs", "clear event log", "remove indicators", "anti-forensic", "cover tracks", "wipe logs"]},
    {"tactic": "Defense Evasion", "technique_id": "T1562.001", "technique_name": "Disable or Modify Tools", "keywords": ["disable antivirus", "disable defender", "kill edr", "tamper protection", "disable security", "stop security service"]},
    {"tactic": "Defense Evasion", "technique_id": "T1036", "technique_name": "Masquerading", "keywords": ["masquerade", "disguised as", "fake process name", "legitimate-looking", "renamed binary"]},
    {"tactic": "Defense Evasion", "technique_id": "T1055", "technique_name": "Process Injection", "keywords": ["process injection", "inject code", "dll injection", "process hollowing", "thread injection", "reflective dll"]},
    {"tactic": "Defense Evasion", "technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files", "keywords": ["decode payload", "deobfuscate", "decrypt payload", "unpack malware"]},
    {"tactic": "Defense Evasion", "technique_id": "T1218", "technique_name": "System Binary Proxy Execution", "keywords": ["lolbin", "living off the land", "mshta", "regsvr32", "rundll32", "certutil"]},
    {"tactic": "Defense Evasion", "technique_id": "T1497", "technique_name": "Virtualization/Sandbox Evasion", "keywords": ["sandbox evasion", "vm detection", "anti-sandbox", "anti-analysis", "detect virtual"]},
    # Credential Access
    {"tactic": "Credential Access", "technique_id": "T1003", "technique_name": "OS Credential Dumping", "keywords": ["credential dump", "mimikatz", "lsass", "hashdump", "sam database", "ntds.dit", "credential harvesting"]},
    {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force", "keywords": ["brute force", "password spray", "credential brute", "dictionary attack"]},
    {"tactic": "Credential Access", "technique_id": "T1056.001", "technique_name": "Keylogging", "keywords": ["keylogger", "keystroke logging", "keylogging", "capture keystrokes"]},
    {"tactic": "Credential Access", "technique_id": "T1539", "technique_name": "Steal Web Session Cookie", "keywords": ["steal cookie", "session hijack", "cookie theft", "browser cookie"]},
    {"tactic": "Credential Access", "technique_id": "T1555", "technique_name": "Credentials from Password Stores", "keywords": ["password store", "browser password", "credential manager", "vault", "saved password"]},
    {"tactic": "Credential Access", "technique_id": "T1528", "technique_name": "Steal Application Access Token", "keywords": ["steal token", "oauth token", "access token theft", "api key theft"]},
    # Discovery
    {"tactic": "Discovery", "technique_id": "T1082", "technique_name": "System Information Discovery", "keywords": ["system info", "systeminfo", "enumerate system", "os version", "hostname"]},
    {"tactic": "Discovery", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "keywords": ["file discovery", "directory listing", "enumerate files", "search for files"]},
    {"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery", "keywords": ["port scan", "network scan", "service discovery", "nmap", "network enumeration"]},
    {"tactic": "Discovery", "technique_id": "T1087", "technique_name": "Account Discovery", "keywords": ["enumerate accounts", "net user", "account discovery", "list users", "domain users"]},
    {"tactic": "Discovery", "technique_id": "T1018", "technique_name": "Remote System Discovery", "keywords": ["network discovery", "ping sweep", "discover hosts", "arp scan", "active directory enumeration"]},
    # Lateral Movement
    {"tactic": "Lateral Movement", "technique_id": "T1021.001", "technique_name": "Remote Desktop Protocol", "keywords": ["rdp lateral", "remote desktop", "rdp connection", "lateral movement rdp"]},
    {"tactic": "Lateral Movement", "technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "keywords": ["smb lateral", "psexec", "admin share", "windows share", "lateral smb", "c$ share"]},
    {"tactic": "Lateral Movement", "technique_id": "T1021.006", "technique_name": "Windows Remote Management", "keywords": ["winrm", "wsman", "windows remote management"]},
    {"tactic": "Lateral Movement", "technique_id": "T1570", "technique_name": "Lateral Tool Transfer", "keywords": ["copy tool", "transfer tool", "move laterally", "spread across network"]},
    {"tactic": "Lateral Movement", "technique_id": "T1210", "technique_name": "Exploitation of Remote Services", "keywords": ["exploit remote service", "eternalblue", "bluekeep", "lateral exploit"]},
    # Collection
    {"tactic": "Collection", "technique_id": "T1005", "technique_name": "Data from Local System", "keywords": ["collect data", "harvest data", "steal files", "gather information", "data collection"]},
    {"tactic": "Collection", "technique_id": "T1114", "technique_name": "Email Collection", "keywords": ["email collection", "mailbox access", "email exfil", "outlook", "exchange mailbox"]},
    {"tactic": "Collection", "technique_id": "T1113", "technique_name": "Screen Capture", "keywords": ["screenshot", "screen capture", "capture screen"]},
    {"tactic": "Collection", "technique_id": "T1560", "technique_name": "Archive Collected Data", "keywords": ["archive data", "compress data", "zip files", "rar archive", "7zip"]},
    # Command and Control
    {"tactic": "Command and Control", "technique_id": "T1071.001", "technique_name": "Web Protocols", "keywords": ["http c2", "https beacon", "web-based c2", "http callback", "command and control http"]},
    {"tactic": "Command and Control", "technique_id": "T1071.004", "technique_name": "DNS", "keywords": ["dns tunneling", "dns c2", "dns exfiltration", "dns beacon"]},
    {"tactic": "Command and Control", "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "keywords": ["download payload", "stage malware", "download tool", "retrieve payload", "fetch malware", "drop payload"]},
    {"tactic": "Command and Control", "technique_id": "T1573", "technique_name": "Encrypted Channel", "keywords": ["encrypted c2", "ssl c2", "tls communication", "encrypted channel", "encrypted traffic"]},
    {"tactic": "Command and Control", "technique_id": "T1090", "technique_name": "Proxy", "keywords": ["proxy c2", "tor network", "onion routing", "proxy chain", "socks proxy"]},
    {"tactic": "Command and Control", "technique_id": "T1219", "technique_name": "Remote Access Software", "keywords": ["cobalt strike", "teamviewer", "anydesk", "remote access tool", "rat ", "remote administration tool", "beacon"]},
    {"tactic": "Command and Control", "technique_id": "T1102", "technique_name": "Web Service", "keywords": ["telegram c2", "discord c2", "pastebin c2", "github c2", "dead drop", "cloud service c2"]},
    # Exfiltration
    {"tactic": "Exfiltration", "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "keywords": ["exfiltrate data", "data exfiltration", "exfil over c2", "steal data", "send data to c2"]},
    {"tactic": "Exfiltration", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service", "keywords": ["exfil to cloud", "upload to mega", "exfil to dropbox", "cloud exfiltration", "send to cloud storage"]},
    {"tactic": "Exfiltration", "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "keywords": ["exfil over dns", "exfil over ftp", "alternative protocol exfil"]},
    # Impact
    {"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "keywords": ["ransomware", "encrypt files", "ransom note", "file encryption", "data encrypted", "decrypt files", "ransom demand"]},
    {"tactic": "Impact", "technique_id": "T1489", "technique_name": "Service Stop", "keywords": ["stop service", "disable service", "kill process", "terminate service"]},
    {"tactic": "Impact", "technique_id": "T1490", "technique_name": "Inhibit System Recovery", "keywords": ["delete shadow", "vssadmin delete", "disable recovery", "delete backup", "bcdedit"]},
    {"tactic": "Impact", "technique_id": "T1485", "technique_name": "Data Destruction", "keywords": ["wiper", "data destruction", "destroy data", "disk wipe", "overwrite files"]},
    {"tactic": "Impact", "technique_id": "T1499", "technique_name": "Endpoint Denial of Service", "keywords": ["ddos", "denial of service", "dos attack", "flood attack"]},
    # Resource Development
    {"tactic": "Resource Development", "technique_id": "T1583", "technique_name": "Acquire Infrastructure", "keywords": ["register domain", "bulletproof hosting", "setup c2 infrastructure", "acquire server"]},
    {"tactic": "Resource Development", "technique_id": "T1588.001", "technique_name": "Malware", "keywords": ["custom malware", "develop malware", "malware family", "trojan", "backdoor", "infostealer", "stealer malware", "loader malware"]},
    {"tactic": "Resource Development", "technique_id": "T1588.005", "technique_name": "Exploits", "keywords": ["develop exploit", "weaponize exploit", "exploit development", "proof of concept exploit"]},
]


def extract_ttps_from_text(text):
    """Extract MITRE ATT&CK TTPs from text using keyword matching."""
    text_lower = text.lower()
    found_ttps = []
    seen_ids = set()

    for rule in MITRE_TTP_RULES:
        if rule["technique_id"] in seen_ids:
            continue
        for keyword in rule["keywords"]:
            if keyword in text_lower:
                # Find context around the keyword match
                idx = text_lower.find(keyword)
                start = max(0, idx - 50)
                end = min(len(text), idx + len(keyword) + 100)
                context = text[start:end].strip().replace("\n", " ")
                # Truncate context
                if len(context) > 120:
                    context = context[:120] + "..."

                found_ttps.append({
                    "tactic": rule["tactic"],
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "description": f"Matched keyword '{keyword}' — ...{context}..."
                })
                seen_ids.add(rule["technique_id"])
                break

    # Sort by tactic order
    tactic_order = [
        "Resource Development", "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Impact"
    ]
    found_ttps.sort(key=lambda x: tactic_order.index(x["tactic"]) if x["tactic"] in tactic_order else 99)
    return found_ttps


@app.route("/api/extract-ttps", methods=["POST"])
def extract_ttps():
    """Fetch article content and extract MITRE ATT&CK TTPs using keyword matching."""
    data = request.get_json()
    url = data.get("url", "").strip()
    title = data.get("title", "")
    summary = data.get("summary", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Fetch article content
    full_text = f"{title}\n\n{summary}\n\n"
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        page_text = soup.get_text(separator=" ", strip=True)
        full_text += page_text
    except Exception:
        pass

    if len(full_text.strip()) < 50:
        return jsonify({"ttps": [], "error": "Could not extract enough content from the article"}), 200

    ttps = extract_ttps_from_text(full_text)
    return jsonify({"ttps": ttps, "source_url": url})


# API configuration is loaded from environment variables to keep secrets out of source control.
VT_API_KEY = os.getenv("VT_API_KEY", "")


@app.route("/api/vt/lookup", methods=["POST"])
def vt_lookup():
    """Lookup an IOC on VirusTotal."""
    data = request.get_json()
    ioc_value = data.get("ioc", "").strip()
    ioc_type = data.get("type", "").strip()

    if not ioc_value:
        return jsonify({"error": "IOC value is required"}), 400

    headers = {"x-apikey": VT_API_KEY}
    base_url = "https://www.virustotal.com/api/v3"

    try:
        if ioc_type in ("MD5", "SHA1", "SHA256"):
            url = f"{base_url}/files/{ioc_value}"
        elif ioc_type == "ipv4":
            url = f"{base_url}/ip_addresses/{ioc_value}"
        elif ioc_type == "domain":
            url = f"{base_url}/domains/{ioc_value}"
        elif ioc_type == "url":
            # URL needs to be base64 encoded for VT API
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            url = f"{base_url}/urls/{url_id}"
        else:
            # Try as file hash by default
            url = f"{base_url}/files/{ioc_value}"

        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 200:
            vt_data = resp.json()
            attrs = vt_data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values()) if stats else 0,
                "reputation": attrs.get("reputation", "N/A"),
                "vt_link": f"https://www.virustotal.com/gui/search/{ioc_value}",
            }
            # Add type-specific info
            if ioc_type in ("MD5", "SHA1", "SHA256"):
                result["name"] = attrs.get("meaningful_name", attrs.get("name", "Unknown"))
                result["type_description"] = attrs.get("type_description", "")
            elif ioc_type == "domain":
                result["registrar"] = attrs.get("registrar", "")
                result["creation_date"] = attrs.get("creation_date", "")
            elif ioc_type == "ipv4":
                result["country"] = attrs.get("country", "")
                result["as_owner"] = attrs.get("as_owner", "")

            return jsonify(result)
        elif resp.status_code == 404:
            return jsonify({
                "found": False,
                "vt_link": f"https://www.virustotal.com/gui/search/{ioc_value}",
            })
        else:
            return jsonify({"error": f"VT API returned {resp.status_code}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vt/submit-file", methods=["POST"])
def vt_submit_file():
    """Submit a file to VirusTotal for scanning."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # 32 MB limit
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    if file_size > 32 * 1024 * 1024:
        return jsonify({"error": "File too large. Maximum size is 32 MB."}), 400

    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (file.filename, file.stream, file.content_type or "application/octet-stream")},
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()

        data = result.get("data", {})
        analysis_id = data.get("id", "")

        # Try to extract SHA256 from the analysis ID (format: u-<sha256>-<timestamp>)
        sha256 = ""
        if analysis_id and "-" in analysis_id:
            parts = analysis_id.split("-")
            if len(parts) >= 2 and len(parts[1]) == 64:
                sha256 = parts[1]

        return jsonify({
            "analysis_id": analysis_id,
            "sha256": sha256,
            "message": "File submitted successfully.",
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("error", {}).get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"VirusTotal API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vt/analysis/<analysis_id>")
def vt_analysis_result(analysis_id):
    """Check the status of a VirusTotal file analysis."""
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        result = resp.json()

        attrs = result.get("data", {}).get("attributes", {})
        status = attrs.get("status", "")

        if status != "completed":
            return jsonify({"status": status, "message": "Analysis still in progress..."}), 202

        stats = attrs.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values()) if stats else 0

        # Extract SHA256 from meta or analysis ID
        sha256 = ""
        meta = result.get("meta", {}).get("file_info", {})
        sha256 = meta.get("sha256", "")
        if not sha256 and "-" in analysis_id:
            parts = analysis_id.split("-")
            if len(parts) >= 2 and len(parts[1]) == 64:
                sha256 = parts[1]

        return jsonify({
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "total": total,
            "reputation": "N/A",
            "vt_link": f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else f"https://www.virustotal.com/gui/file-analysis/{analysis_id}",
            "name": meta.get("name", ""),
            "type_description": meta.get("type_description", ""),
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("error", {}).get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"VirusTotal API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/extract-cves", methods=["POST"])
def extract_cves_from_article():
    """Fetch article content and extract CVE numbers using regex."""
    data = request.get_json()
    url = data.get("url", "").strip()
    title = data.get("title", "")
    summary = data.get("summary", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    full_text = f"{title} {summary} "

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        page_text = soup.get_text(separator=" ", strip=True)
        full_text += page_text
    except Exception:
        pass

    # Extract CVEs
    cves = sorted(set(IOC_PATTERNS["cve"].findall(full_text)), reverse=True)
    return jsonify({"cves": cves})


@app.route("/api/cve-details", methods=["POST"])
def cve_details():
    """Lookup CVE details from NVD and Tenable."""
    data = request.get_json()
    cve_id = data.get("cve_id", "").strip().upper()

    if not cve_id or not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
        return jsonify({"error": "Valid CVE ID is required"}), 400

    source_url = data.get("source_url", "").strip()

    result = {
        "cve_id": cve_id,
        "affected_software": [],
        "cvss_scores": {},
        "vulnerability_type": "Unknown",
        "authentication_required": "Unknown",
        "exploit_availability": "Unknown",
        "exploitation_status": "Unknown",
        "attack_complexity": "Unknown",
        "description": "",
        "source_summary": "",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    # Fetch from NVD API
    try:
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        nvd_resp = requests.get(nvd_url, headers=headers, timeout=20)
        if nvd_resp.status_code == 200:
            nvd_data = nvd_resp.json()
            vulnerabilities = nvd_data.get("vulnerabilities", [])
            if vulnerabilities:
                cve_item = vulnerabilities[0].get("cve", {})

                # Description
                descriptions = cve_item.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        result["description"] = desc.get("value", "")
                        break

                # CVSS scores from NVD
                metrics = cve_item.get("metrics", {})

                # CVSS v3.1
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if cvss_v31:
                    primary = cvss_v31[0]
                    cvss_data = primary.get("cvssData", {})
                    result["cvss_scores"]["nvd"] = {
                        "score": cvss_data.get("baseScore", "N/A"),
                        "severity": cvss_data.get("baseSeverity", "N/A"),
                        "vector": cvss_data.get("vectorString", ""),
                    }
                    result["attack_complexity"] = cvss_data.get("attackComplexity", "Unknown")
                    auth = cvss_data.get("privilegesRequired", "NONE")
                    result["authentication_required"] = auth
                    result["vulnerability_type"] = cvss_data.get("attackVector", "Unknown")

                # CVSS v3.0 fallback
                if "nvd" not in result["cvss_scores"]:
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    if cvss_v30:
                        primary = cvss_v30[0]
                        cvss_data = primary.get("cvssData", {})
                        result["cvss_scores"]["nvd"] = {
                            "score": cvss_data.get("baseScore", "N/A"),
                            "severity": cvss_data.get("baseSeverity", "N/A"),
                            "vector": cvss_data.get("vectorString", ""),
                        }
                        result["attack_complexity"] = cvss_data.get("attackComplexity", "Unknown")
                        auth = cvss_data.get("privilegesRequired", "NONE")
                        result["authentication_required"] = auth

                # CVSS v2 fallback
                if "nvd" not in result["cvss_scores"]:
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    if cvss_v2:
                        primary = cvss_v2[0]
                        cvss_data = primary.get("cvssData", {})
                        result["cvss_scores"]["nvd"] = {
                            "score": cvss_data.get("baseScore", "N/A"),
                            "severity": primary.get("baseSeverity", "N/A"),
                            "vector": cvss_data.get("vectorString", ""),
                        }
                        result["attack_complexity"] = cvss_data.get("accessComplexity", "Unknown")
                        result["authentication_required"] = cvss_data.get("authentication", "Unknown")

                # Affected software (CPE)
                configurations = cve_item.get("configurations", [])
                for config in configurations:
                    nodes = config.get("nodes", [])
                    for node in nodes:
                        cpe_matches = node.get("cpeMatch", [])
                        for cpe in cpe_matches:
                            if cpe.get("vulnerable"):
                                cpe_uri = cpe.get("criteria", "")
                                # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                                parts = cpe_uri.split(":")
                                if len(parts) >= 6:
                                    vendor = parts[3].replace("_", " ").title()
                                    product = parts[4].replace("_", " ").title()
                                    version = parts[5] if parts[5] != "*" else "All versions"
                                    entry = f"{vendor} {product}"
                                    if version != "All versions":
                                        version_end = cpe.get("versionEndIncluding", cpe.get("versionEndExcluding", ""))
                                        if version_end:
                                            entry += f" (up to {version_end})"
                                        else:
                                            entry += f" {version}"
                                    if entry not in result["affected_software"]:
                                        result["affected_software"].append(entry)

                # Weakness (CWE) for vulnerability type
                weaknesses = cve_item.get("weaknesses", [])
                for weakness in weaknesses:
                    descs = weakness.get("description", [])
                    for d in descs:
                        if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                            result["vulnerability_type"] = d.get("value", "Unknown")
                            break

    except Exception:
        pass

    # Fetch CVSS from Tenable
    try:
        tenable_url = f"https://www.tenable.com/cve/{cve_id}"
        tenable_resp = requests.get(tenable_url, headers=headers, timeout=15)
        if tenable_resp.status_code == 200:
            soup = BeautifulSoup(tenable_resp.text, "html.parser")
            # Try to find CVSS score from Tenable page
            score_el = soup.find("span", class_=re.compile(r"cvss|score", re.IGNORECASE))
            if score_el:
                score_text = score_el.get_text(strip=True)
                score_match = re.search(r'(\d+\.?\d*)', score_text)
                if score_match:
                    result["cvss_scores"]["tenable"] = {
                        "score": float(score_match.group(1)),
                        "severity": _cvss_severity(float(score_match.group(1))),
                        "source_url": tenable_url,
                    }
            # Fallback: look for score in meta or specific divs
            if "tenable" not in result["cvss_scores"]:
                page_text = soup.get_text()
                cvss_match = re.search(r'(?:CVSS[^:]*:?\s*|Base Score[:\s]*)(\d+\.?\d*)', page_text)
                if cvss_match:
                    score_val = float(cvss_match.group(1))
                    if 0 <= score_val <= 10:
                        result["cvss_scores"]["tenable"] = {
                            "score": score_val,
                            "severity": _cvss_severity(score_val),
                            "source_url": tenable_url,
                        }
    except Exception:
        pass

    # Check exploit availability from NVD references
    try:
        if vulnerabilities:
            refs = cve_item.get("references", [])
            exploit_found = False
            for ref in refs:
                tags = ref.get("tags", [])
                if "Exploit" in tags:
                    exploit_found = True
                    result["exploit_availability"] = "Public exploit available"
                    break
                if "Third Party Advisory" in tags:
                    result["exploitation_status"] = "Advisory published"
            if not exploit_found:
                result["exploit_availability"] = "No known public exploit"
            if result["exploitation_status"] == "Unknown":
                # Check CISA KEV status
                cisa_kev_check = any("cisa" in ref.get("url", "").lower() for ref in refs)
                if cisa_kev_check:
                    result["exploitation_status"] = "Known exploited (CISA KEV)"
                else:
                    result["exploitation_status"] = "No known active exploitation"
    except Exception:
        pass

    # Fetch short summary from source article
    if source_url:
        try:
            src_resp = requests.get(source_url, headers=headers, timeout=15, allow_redirects=True)
            if src_resp.status_code == 200:
                soup = BeautifulSoup(src_resp.text, "html.parser")
                for tag in soup(["script", "style", "nav", "footer", "header"]):
                    tag.decompose()
                page_text = soup.get_text(separator=" ", strip=True)
                # Extract sentences mentioning this CVE
                sentences = re.split(r'(?<=[.!?])\s+', page_text)
                relevant = []
                for sent in sentences:
                    if cve_id.lower() in sent.lower() and len(sent) > 20:
                        # Clean up and limit sentence length
                        clean = sent.strip()[:300]
                        if clean not in relevant:
                            relevant.append(clean)
                        if len(relevant) >= 3:
                            break
                if relevant:
                    result["source_summary"] = " ".join(relevant)
                else:
                    # Fallback: grab sentences near the CVE mention
                    for i, sent in enumerate(sentences):
                        if cve_id.lower() in sent.lower():
                            context = sentences[max(0, i-1):i+2]
                            result["source_summary"] = " ".join(
                                s.strip()[:200] for s in context if len(s.strip()) > 15
                            )
                            break
        except Exception:
            pass

    # Add source URLs
    result["source_urls"] = {
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "tenable": f"https://www.tenable.com/cve/{cve_id}",
    }

    return jsonify(result)


def _cvss_severity(score):
    """Convert CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


# --- APT Group Files Storage ---
APT_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apt_files")
os.makedirs(APT_FILES_DIR, exist_ok=True)


@app.route("/api/apt-files", methods=["GET"])
def list_apt_files():
    """List all uploaded APT group files."""
    files = []
    for fname in os.listdir(APT_FILES_DIR):
        fpath = os.path.join(APT_FILES_DIR, fname)
        if os.path.isfile(fpath):
            files.append({
                "name": fname,
                "size": os.path.getsize(fpath),
                "uploaded_at": datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat(),
            })
    files.sort(key=lambda x: x["uploaded_at"], reverse=True)
    return jsonify(files)


@app.route("/api/apt-files", methods=["POST"])
def upload_apt_file():
    """Upload a docx file for APT groups."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.lower().endswith(".docx"):
        return jsonify({"error": "Only .docx files are allowed"}), 400
    from werkzeug.utils import secure_filename
    filename = secure_filename(file.filename)
    filepath = os.path.join(APT_FILES_DIR, filename)
    file.save(filepath)
    return jsonify({"message": "File uploaded successfully", "name": filename}), 201


@app.route("/api/apt-files/<filename>", methods=["DELETE"])
def delete_apt_file(filename):
    """Delete an APT group file."""
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    filepath = os.path.join(APT_FILES_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    os.remove(filepath)
    return jsonify({"message": "File deleted"})


@app.route("/api/apt-files/<filename>/view")
def view_apt_file(filename):
    """Serve APT group docx file content as HTML for read-only viewing."""
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    filepath = os.path.join(APT_FILES_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    try:
        import docx
        from docx.oxml.ns import qn
        from xml.sax.saxutils import escape

        doc = docx.Document(filepath)
        html_parts = []

        def render_run(run):
            text = escape(run.text or "")
            if not text:
                return ""
            if run.bold:
                text = f"<strong>{text}</strong>"
            if run.italic:
                text = f"<em>{text}</em>"
            if run.underline:
                text = f"<u>{text}</u>"
            return text

        def render_paragraph(para):
            runs_html = "".join(render_run(r) for r in para.runs)
            if not runs_html.strip():
                return ""
            style = para.style.name.lower() if para.style else ""
            pPr = para._element.find(qn('w:pPr'))
            numPr = pPr.find(qn('w:numPr')) if pPr is not None else None
            if numPr is not None:
                return f"<li>{runs_html}</li>"
            elif "heading 1" in style:
                return f"<h1>{runs_html}</h1>"
            elif "heading 2" in style:
                return f"<h2>{runs_html}</h2>"
            elif "heading 3" in style:
                return f"<h3>{runs_html}</h3>"
            elif "heading 4" in style:
                return f"<h4>{runs_html}</h4>"
            elif "title" in style:
                return f"<h1 class='doc-title'>{runs_html}</h1>"
            elif "subtitle" in style:
                return f"<h2 class='doc-subtitle'>{runs_html}</h2>"
            else:
                return f"<p>{runs_html}</p>"

        def render_table(table):
            tbl_html = "<table>"
            for i, row in enumerate(table.rows):
                tbl_html += "<tr>"
                tag = "th" if i == 0 else "td"
                for cell in row.cells:
                    cell_text = escape(cell.text.strip())
                    tbl_html += f"<{tag}>{cell_text}</{tag}>"
                tbl_html += "</tr>"
            tbl_html += "</table>"
            return tbl_html

        in_list = False
        for element in doc.element.body:
            tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag
            if tag == "p":
                para = docx.text.paragraph.Paragraph(element, doc)
                rendered = render_paragraph(para)
                if not rendered:
                    if in_list:
                        html_parts.append("</ul>")
                        in_list = False
                    continue
                if rendered.startswith("<li>"):
                    if not in_list:
                        html_parts.append("<ul>")
                        in_list = True
                    html_parts.append(rendered)
                else:
                    if in_list:
                        html_parts.append("</ul>")
                        in_list = False
                    html_parts.append(rendered)
            elif tag == "tbl":
                if in_list:
                    html_parts.append("</ul>")
                    in_list = False
                from docx.table import Table as DocxTable
                table = DocxTable(element, doc)
                html_parts.append(render_table(table))

        if in_list:
            html_parts.append("</ul>")

        return jsonify({"html": "\n".join(html_parts), "filename": filename})
    except ImportError:
        return jsonify({"error": "python-docx package not installed. Run: pip install python-docx"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Infostealer Files Storage ---
INFOSTEALER_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "infostealer_files")
os.makedirs(INFOSTEALER_FILES_DIR, exist_ok=True)


@app.route("/api/infostealer-files", methods=["GET"])
def list_infostealer_files():
    """List all uploaded infostealer files."""
    files = []
    for fname in os.listdir(INFOSTEALER_FILES_DIR):
        fpath = os.path.join(INFOSTEALER_FILES_DIR, fname)
        if os.path.isfile(fpath):
            files.append({
                "name": fname,
                "size": os.path.getsize(fpath),
                "uploaded_at": datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat(),
            })
    files.sort(key=lambda x: x["uploaded_at"], reverse=True)
    return jsonify(files)


@app.route("/api/infostealer-files", methods=["POST"])
def upload_infostealer_file():
    """Upload a docx file for infostealers."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400
    # Only allow .docx files
    if not file.filename.lower().endswith(".docx"):
        return jsonify({"error": "Only .docx files are allowed"}), 400
    # Sanitize filename
    from werkzeug.utils import secure_filename
    filename = secure_filename(file.filename)
    filepath = os.path.join(INFOSTEALER_FILES_DIR, filename)
    file.save(filepath)
    return jsonify({"message": "File uploaded successfully", "name": filename}), 201


@app.route("/api/infostealer-files/<filename>", methods=["DELETE"])
def delete_infostealer_file(filename):
    """Delete an infostealer file."""
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    filepath = os.path.join(INFOSTEALER_FILES_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    os.remove(filepath)
    return jsonify({"message": "File deleted"})


@app.route("/api/infostealer-files/<filename>/view")
def view_infostealer_file(filename):
    """Serve infostealer docx file content as HTML for read-only viewing."""
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    filepath = os.path.join(INFOSTEALER_FILES_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    try:
        import docx
        from docx.oxml.ns import qn
        from xml.sax.saxutils import escape

        doc = docx.Document(filepath)
        html_parts = []

        def render_run(run):
            """Render a single run with inline formatting."""
            text = escape(run.text or "")
            if not text:
                return ""
            if run.bold:
                text = f"<strong>{text}</strong>"
            if run.italic:
                text = f"<em>{text}</em>"
            if run.underline:
                text = f"<u>{text}</u>"
            return text

        def render_paragraph(para):
            """Render a paragraph with proper styling."""
            runs_html = "".join(render_run(r) for r in para.runs)
            if not runs_html.strip():
                return ""

            style = para.style.name.lower() if para.style else ""

            # Check for list items
            pPr = para._element.find(qn('w:pPr'))
            numPr = pPr.find(qn('w:numPr')) if pPr is not None else None

            if numPr is not None:
                return f"<li>{runs_html}</li>"
            elif "heading 1" in style:
                return f"<h1>{runs_html}</h1>"
            elif "heading 2" in style:
                return f"<h2>{runs_html}</h2>"
            elif "heading 3" in style:
                return f"<h3>{runs_html}</h3>"
            elif "heading 4" in style:
                return f"<h4>{runs_html}</h4>"
            elif "title" in style:
                return f"<h1 class='doc-title'>{runs_html}</h1>"
            elif "subtitle" in style:
                return f"<h2 class='doc-subtitle'>{runs_html}</h2>"
            else:
                return f"<p>{runs_html}</p>"

        def render_table(table):
            """Render a table with formatting."""
            tbl_html = "<table>"
            for i, row in enumerate(table.rows):
                tbl_html += "<tr>"
                tag = "th" if i == 0 else "td"
                for cell in row.cells:
                    cell_text = escape(cell.text.strip())
                    tbl_html += f"<{tag}>{cell_text}</{tag}>"
                tbl_html += "</tr>"
            tbl_html += "</table>"
            return tbl_html

        # Process document body elements in order (preserves table placement)
        in_list = False
        for element in doc.element.body:
            tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag

            if tag == "p":
                para = docx.text.paragraph.Paragraph(element, doc)
                rendered = render_paragraph(para)
                if not rendered:
                    if in_list:
                        html_parts.append("</ul>")
                        in_list = False
                    continue

                if rendered.startswith("<li>"):
                    if not in_list:
                        html_parts.append("<ul>")
                        in_list = True
                    html_parts.append(rendered)
                else:
                    if in_list:
                        html_parts.append("</ul>")
                        in_list = False
                    html_parts.append(rendered)

            elif tag == "tbl":
                if in_list:
                    html_parts.append("</ul>")
                    in_list = False
                from docx.table import Table as DocxTable
                table = DocxTable(element, doc)
                html_parts.append(render_table(table))

        if in_list:
            html_parts.append("</ul>")

        return jsonify({"html": "\n".join(html_parts), "filename": filename})
    except ImportError:
        return jsonify({"error": "python-docx package not installed. Run: pip install python-docx"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/osint")
def osint():
    return render_template("osint.html")


@app.route("/sandbox")
def sandbox():
    return render_template("sandbox.html")


HA_API_KEY = os.getenv("HA_API_KEY", "")
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY", "")


@app.route("/api/sandbox/hybrid-analysis/search", methods=["POST"])
def hybrid_analysis_search():
    """Search Hybrid Analysis for malware samples."""
    data = request.get_json()
    query = data.get("query", "").strip()
    search_type = data.get("type", "hash").strip()

    if not query:
        return jsonify({"error": "Search query is required"}), 400

    ha_api_key = HA_API_KEY

    headers = {
        "api-key": ha_api_key,
        "User-Agent": "Falcon Sandbox",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        # Use the appropriate search endpoint based on type
        if search_type == "hash":
            # POST /search/hash still works on all API tiers (GET version requires v2.35+ key features)
            resp = requests.post(
                "https://www.hybrid-analysis.com/api/v2/search/hash",
                headers=headers,
                data={"hash": query},
                timeout=30,
            )
        else:
            resp = requests.post(
                "https://www.hybrid-analysis.com/api/v2/search/terms",
                headers=headers,
                data={search_type: query},
                timeout=30,
            )

        # 404 or 403 means no results or endpoint not available for this API tier
        if resp.status_code in (404, 403):
            return jsonify({
                "results": [],
                "total": 0,
                "web_search_url": f"https://www.hybrid-analysis.com/search?query={requests.utils.quote(query)}",
                "message": "No results found via API. Try the direct web search link."
            })

        # 200 with empty response also means no results for this hash
        if resp.status_code == 200:
            try:
                raw_results = resp.json()
            except ValueError:
                return jsonify({
                    "results": [],
                    "total": 0,
                    "web_search_url": f"https://www.hybrid-analysis.com/search?query={requests.utils.quote(query)}",
                    "message": "No results found via API."
                })
            if not raw_results or (isinstance(raw_results, list) and len(raw_results) == 0):
                return jsonify({
                    "results": [],
                    "total": 0,
                    "web_search_url": f"https://www.hybrid-analysis.com/search?query={requests.utils.quote(query)}",
                    "message": "Hash not found in Hybrid Analysis database."
                })
        else:
            resp.raise_for_status()
            raw_results = resp.json()

        # Normalize results
        results = []
        items = raw_results if isinstance(raw_results, list) else raw_results.get("result", raw_results.get("search_terms", []))
        if not isinstance(items, list):
            items = [items] if items else []

        for item in items[:20]:
            if not isinstance(item, dict):
                continue
            results.append({
                "sha256": item.get("sha256", ""),
                "sha1": item.get("sha1", ""),
                "md5": item.get("md5", ""),
                "name": item.get("submit_name", item.get("type_short", "")),
                "verdict": item.get("verdict", "unknown"),
                "threat_score": item.get("threat_score"),
                "type": item.get("type_short", item.get("type", "")),
                "size": item.get("size"),
                "environment": item.get("environment_description", ""),
                "submit_date": item.get("analysis_start_time", item.get("submit_name", "")),
                "tags": item.get("tags", []) or [],
                "report_url": f"https://www.hybrid-analysis.com/sample/{item.get('sha256', '')}" if item.get("sha256") else "",
            })

        return jsonify({"results": results, "total": len(results), "web_search_url": f"https://www.hybrid-analysis.com/search?query={requests.utils.quote(query)}"})

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        status_code = e.response.status_code if e.response is not None else 0
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", error_body.get("error", str(e)))
        except Exception:
            if e.response is not None:
                error_msg = f"HTTP {status_code}: {e.response.text[:200]}"
        return jsonify({"error": f"Hybrid Analysis API error ({status_code}): {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sandbox/hybrid-analysis/submit-file", methods=["POST"])
def hybrid_analysis_submit_file():
    """Submit a file to Hybrid Analysis for sandbox analysis."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    environment_id = request.form.get("environment_id", "160")  # Windows 10 64-bit default

    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
    }

    try:
        resp = requests.post(
            "https://www.hybrid-analysis.com/api/v2/submit/file",
            headers=headers,
            files={"file": (file.filename, file.stream, file.content_type or "application/octet-stream")},
            data={"environment_id": environment_id},
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()

        return jsonify({
            "job_id": result.get("job_id", ""),
            "sha256": result.get("sha256", ""),
            "submission_id": result.get("submission_id", ""),
            "environment_id": environment_id,
            "message": "File submitted successfully. Analysis in progress.",
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"Hybrid Analysis API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sandbox/hybrid-analysis/report/<sha256>")
def hybrid_analysis_report(sha256):
    """Get the analysis report for a submitted file."""
    environment_id = request.args.get("environment_id", "160")

    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
    }

    try:
        # Use GET /overview/{sha256} for report status (preferred over deprecated POST /search/hash)
        resp = requests.get(
            f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}",
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 404:
            return jsonify({"status": "pending", "message": "Analysis still in progress..."}), 202

        resp.raise_for_status()
        raw_results = resp.json()

        if not raw_results:
            return jsonify({"status": "pending", "message": "Analysis still in progress..."}), 202

        items = raw_results if isinstance(raw_results, list) else [raw_results]
        # Find the result matching the environment
        result = None
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("environment_id", "")) == str(environment_id):
                result = item
                break
        if not result and items:
            result = items[0] if isinstance(items[0], dict) else None

        if not result:
            return jsonify({"status": "pending", "message": "Analysis still in progress..."}), 202

        # Check if analysis is complete
        state = result.get("state", "")
        if state and state != "SUCCESS":
            return jsonify({"status": "processing", "message": f"Analysis state: {state}"}), 202

        return jsonify({
            "status": "complete",
            "sha256": result.get("sha256", ""),
            "sha1": result.get("sha1", ""),
            "md5": result.get("md5", ""),
            "name": result.get("submit_name", ""),
            "verdict": result.get("verdict", "unknown"),
            "threat_score": result.get("threat_score"),
            "threat_level": result.get("threat_level"),
            "type": result.get("type_short", result.get("type", "")),
            "size": result.get("size"),
            "environment": result.get("environment_description", ""),
            "analysis_start_time": result.get("analysis_start_time", ""),
            "tags": result.get("tags", []) or [],
            "vx_family": result.get("vx_family", ""),
            "total_processes": result.get("total_processes"),
            "total_network_connections": result.get("total_network_connections"),
            "total_signatures": result.get("total_signatures"),
            "mitre_attcks": result.get("mitre_attcks", []) or [],
            "report_url": f"https://www.hybrid-analysis.com/sample/{result.get('sha256', '')}",
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"Hybrid Analysis API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sandbox/anyrun/submit-file", methods=["POST"])
def anyrun_submit_file():
    """Submit a file to ANY.RUN for sandbox analysis."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    env_os = request.form.get("env_os", "windows")
    env_bitness = request.form.get("env_bitness", "64")

    headers = {
        "Authorization": f"API-Key {ANYRUN_API_KEY}",
    }

    try:
        resp = requests.post(
            "https://api.any.run/v1/analysis",
            headers=headers,
            files={"file": (file.filename, file.stream, file.content_type or "application/octet-stream")},
            data={
                "obj_type": "file",
                "env_os": env_os,
                "env_bitness": env_bitness,
            },
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()

        if result.get("error"):
            return jsonify({"error": result.get("message", "ANY.RUN submission failed")}), 502

        task_id = result.get("data", {}).get("taskid", "")
        return jsonify({
            "task_id": task_id,
            "message": "File submitted successfully to ANY.RUN. Analysis in progress.",
            "report_url": f"https://app.any.run/tasks/{task_id}",
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"ANY.RUN API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sandbox/anyrun/report/<task_id>")
def anyrun_report(task_id):
    """Get the analysis report for an ANY.RUN task."""
    headers = {
        "Authorization": f"API-Key {ANYRUN_API_KEY}",
    }

    try:
        resp = requests.get(
            f"https://api.any.run/v1/analysis/{task_id}",
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 404:
            return jsonify({"status": "pending", "message": "Analysis still in progress..."}), 202

        resp.raise_for_status()
        result = resp.json()

        if result.get("error"):
            return jsonify({"status": "pending", "message": result.get("message", "Waiting...")}), 202

        data = result.get("data", {})
        analysis = data.get("analysis", {})

        # Check if finished
        status = analysis.get("status", "")
        if status not in ("done", "finished"):
            return jsonify({"status": "processing", "message": f"Analysis state: {status or 'running'}"}), 202

        content = analysis.get("content", {})
        main_obj = content.get("mainObject", {})
        scores = main_obj.get("scores", {})
        hashes = main_obj.get("hashes", {})
        verdict_val = scores.get("verdict", {})
        verdict_str = verdict_val.get("threatLevelText", "unknown") if isinstance(verdict_val, dict) else str(verdict_val)
        threat_score = scores.get("specs", {})

        # Collect process/network stats
        counters = analysis.get("counters", {})
        processes = counters.get("processes", {}).get("total", None)
        network = counters.get("network", {}).get("total", None)
        signatures = counters.get("signatures", {}).get("total", None)

        # MITRE
        mitre = [t.get("id", "") for t in analysis.get("mitre", []) if isinstance(t, dict)]

        return jsonify({
            "status": "complete",
            "task_id": task_id,
            "name": main_obj.get("filename", ""),
            "sha256": hashes.get("sha256", ""),
            "sha1": hashes.get("sha1", ""),
            "md5": hashes.get("md5", ""),
            "verdict": verdict_str,
            "threat_score": scores.get("verdict", {}).get("score") if isinstance(scores.get("verdict"), dict) else None,
            "type": main_obj.get("type", ""),
            "size": main_obj.get("size"),
            "environment": analysis.get("sandbox", ""),
            "analysis_start_time": analysis.get("createdAt", ""),
            "total_processes": processes,
            "total_network_connections": network,
            "total_signatures": signatures,
            "mitre_attcks": mitre,
            "tags": [],
            "report_url": f"https://app.any.run/tasks/{task_id}",
        })

    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": f"ANY.RUN API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


@app.route("/api/abuseipdb/check", methods=["POST"])
def abuseipdb_check():
    """Check an IP address against AbuseIPDB."""
    data = request.get_json()
    ip_address = data.get("ip", "").strip()
    max_age = data.get("max_age", 90)

    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip_address, "maxAgeInDays": max_age, "verbose": ""},
            timeout=15,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("errors", [{}])[0].get("detail", str(e))
        except Exception:
            pass
        return jsonify({"error": f"AbuseIPDB API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/abuseipdb/reports", methods=["POST"])
def abuseipdb_reports():
    """Get recent reports for an IP from AbuseIPDB."""
    data = request.get_json()
    ip_address = data.get("ip", "").strip()
    max_age = data.get("max_age", 90)
    page = data.get("page", 1)
    per_page = data.get("per_page", 25)

    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/reports",
            headers=headers,
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": max_age,
                "page": page,
                "perPage": per_page,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("errors", [{}])[0].get("detail", str(e))
        except Exception:
            pass
        return jsonify({"error": f"AbuseIPDB API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/abuseipdb/blacklist", methods=["GET"])
def abuseipdb_blacklist():
    """Get the AbuseIPDB blacklist."""
    confidence_minimum = request.args.get("confidence", 90)

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers=headers,
            params={"confidenceMinimum": confidence_minimum, "limit": 50},
            timeout=15,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("errors", [{}])[0].get("detail", str(e))
        except Exception:
            pass
        return jsonify({"error": f"AbuseIPDB API error: {error_msg}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/urlscan/scan", methods=["POST"])
def urlscan_scan():
    """Submit a URL to urlscan.io for scanning."""
    data = request.get_json()
    url_to_scan = data.get("url", "").strip()

    if not url_to_scan:
        return jsonify({"error": "URL is required"}), 400

    api_key = "019ee01c-4d0a-7765-9015-56f9c3724f64"

    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={
                "API-Key": api_key,
                "Content-Type": "application/json",
            },
            json={
                "url": url_to_scan,
                "visibility": "public",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": error_msg}), e.response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/urlscan/result/<uuid>")
def urlscan_result(uuid):
    """Get scan result from urlscan.io by UUID."""
    api_key = "019ee01c-4d0a-7765-9015-56f9c3724f64"

    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            headers={"API-Key": api_key},
            timeout=30,
        )
        if resp.status_code == 404:
            return jsonify({"status": "pending", "message": "Scan still processing..."}), 202
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        try:
            error_body = e.response.json()
            error_msg = error_body.get("message", str(e))
        except Exception:
            pass
        return jsonify({"error": error_msg}), e.response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/urlscan/screenshot/<uuid>")
def urlscan_screenshot(uuid):
    """Proxy the screenshot image from urlscan.io to avoid CORS issues."""
    try:
        resp = requests.get(
            f"https://urlscan.io/screenshots/{uuid}.png",
            timeout=30,
        )
        if resp.status_code == 404:
            return "Screenshot not available", 404
        resp.raise_for_status()
        from flask import Response
        return Response(resp.content, mimetype="image/png",
                        headers={"Cache-Control": "public, max-age=3600"})
    except Exception as e:
        return str(e), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
