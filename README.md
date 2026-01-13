# Security Detections MCP

An MCP (Model Context Protocol) server that lets LLMs query a unified database of **Sigma**, **Splunk ESCU**, and **Elastic** security detection rules.

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=security-detections&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInNlY3VyaXR5LWRldGVjdGlvbnMtbWNwIl0sImVudiI6eyJTSUdNQV9QQVRIUyI6Ii9wYXRoL3RvL3NpZ21hL3J1bGVzLC9wYXRoL3RvL3NpZ21hL3J1bGVzLXRocmVhdC1odW50aW5nIiwiU1BMVU5LX1BBVEhTIjoiL3BhdGgvdG8vc2VjdXJpdHlfY29udGVudC9kZXRlY3Rpb25zIiwiU1RPUllfUEFUSFMiOiIvcGF0aC90by9zZWN1cml0eV9jb250ZW50L3N0b3JpZXMiLCJFTEFTVElDX1BBVEhTIjoiL3BhdGgvdG8vZGV0ZWN0aW9uLXJ1bGVzL3J1bGVzIn19)

## Features

- **Unified Search** - Query Sigma, Splunk ESCU, and Elastic detections from a single interface
- **Full-Text Search** - SQLite FTS5 powered search across names, descriptions, queries, MITRE tactics, CVEs, process names, and more
- **MITRE ATT&CK Mapping** - Filter detections by technique ID or tactic
- **CVE Coverage** - Find detections for specific CVE vulnerabilities
- **Process Name Search** - Find detections that reference specific processes (e.g., powershell.exe, w3wp.exe)
- **Analytic Stories** - Query by Splunk analytic story (optional - enhances context)
- **Auto-Indexing** - Automatically indexes detections on startup from configured paths
- **Multi-Format Support** - YAML (Sigma, Splunk), TOML (Elastic)
- **Logsource Filtering** - Filter Sigma rules by category, product, or service
- **Severity Filtering** - Filter by criticality level

## Quick Start

### Option 1: npx (Recommended)

No installation required - just configure and run:

```bash
npx -y security-detections-mcp
```

### Option 2: Clone and Build

```bash
git clone https://github.com/MHaggis/Security-Detections-MCP.git
cd Security-Detections-MCP
npm install
npm run build
```

## Configuration

### Cursor IDE

Add to your MCP config (`~/.cursor/mcp.json` or `.cursor/mcp.json` in your project):

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/path/to/sigma/rules,/path/to/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/path/to/security_content/detections",
        "ELASTIC_PATHS": "/path/to/detection-rules/rules",
        "STORY_PATHS": "/path/to/security_content/stories"
      }
    }
  }
}
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/Users/you/sigma/rules,/Users/you/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/Users/you/security_content/detections",
        "ELASTIC_PATHS": "/Users/you/detection-rules/rules",
        "STORY_PATHS": "/Users/you/security_content/stories"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SIGMA_PATHS` | Comma-separated paths to Sigma rule directories | Yes (at least one source) |
| `SPLUNK_PATHS` | Comma-separated paths to Splunk ESCU detection directories | Yes (at least one source) |
| `ELASTIC_PATHS` | Comma-separated paths to Elastic detection rule directories | Yes (at least one source) |
| `STORY_PATHS` | Comma-separated paths to Splunk analytic story directories | No (enhances context) |

## Getting Detection Content

### Quick Start: Download All Rules (Copy & Paste)

Create a `detections` folder and download all three sources with sparse checkout (only downloads the rules, not full repos):

```bash
# Create detections directory
mkdir -p detections && cd detections

# Download Sigma rules (~3,000+ rules)
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..

# Download Splunk ESCU detections + stories (~2,000+ detections, ~330 stories)
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections stories && cd ..

# Download Elastic detection rules (~1,500+ rules)
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules && cd ..

echo "Done! Configure your MCP with these paths:"
echo "  SIGMA_PATHS: $(pwd)/sigma/rules,$(pwd)/sigma/rules-threat-hunting"
echo "  SPLUNK_PATHS: $(pwd)/security_content/detections"
echo "  ELASTIC_PATHS: $(pwd)/detection-rules/rules"
echo "  STORY_PATHS: $(pwd)/security_content/stories"
```

### Alternative: Full Clone

If you prefer full git history:

```bash
# Sigma Rules
git clone https://github.com/SigmaHQ/sigma.git
# Use rules/ and rules-threat-hunting/ directories

# Splunk ESCU
git clone https://github.com/splunk/security_content.git
# Use detections/ and stories/ directories

# Elastic Detection Rules
git clone https://github.com/elastic/detection-rules.git
# Use rules/ directory
```

## MCP Tools

### Core Detection Tools

| Tool | Description |
|------|-------------|
| `search(query, limit)` | Full-text search across all detection fields (names, descriptions, queries, CVEs, process names, etc.) |
| `get_by_id(id)` | Get a single detection by its ID |
| `list_all(limit, offset)` | Paginated list of all detections |
| `list_by_source(source_type)` | Filter by `sigma`, `splunk_escu`, or `elastic` |
| `get_raw_yaml(id)` | Get the original YAML/TOML content |
| `get_stats()` | Get index statistics |
| `rebuild_index()` | Force re-index from configured paths |

### MITRE ATT&CK Filters

| Tool | Description |
|------|-------------|
| `list_by_mitre(technique_id)` | Filter by MITRE ATT&CK technique ID (e.g., T1059.001) |
| `list_by_mitre_tactic(tactic)` | Filter by tactic (execution, persistence, credential-access, etc.) |

### Vulnerability & Process Filters

| Tool | Description |
|------|-------------|
| `list_by_cve(cve_id)` | Find detections for a specific CVE (e.g., CVE-2024-27198) |
| `list_by_process_name(process_name)` | Find detections referencing a process (e.g., powershell.exe, w3wp.exe) |
| `list_by_data_source(data_source)` | Filter by data source (e.g., Sysmon, Windows Security) |

### Classification Filters

| Tool | Description |
|------|-------------|
| `list_by_logsource(category, product, service)` | Filter Sigma rules by logsource |
| `list_by_severity(level)` | Filter by severity (informational/low/medium/high/critical) |
| `list_by_detection_type(type)` | Filter by type (TTP, Anomaly, Hunting, Correlation) |
| `list_by_analytic_story(story)` | Filter by Splunk analytic story |

### Story Tools (Optional)

| Tool | Description |
|------|-------------|
| `search_stories(query, limit)` | Search analytic stories by narrative and description |
| `get_story(name)` | Get detailed story information |
| `list_stories(limit, offset)` | List all analytic stories |
| `list_stories_by_category(category)` | Filter stories by category (Malware, Adversary Tactics, etc.) |

## Example Workflows

### Find PowerShell Detections

```
LLM: "Find me PowerShell detections related to base64 encoding"
Tool: search(query="powershell base64", limit=5)
```

### Check CVE Coverage

```
LLM: "Do we have detections for CVE-2024-27198?"
Tool: list_by_cve(cve_id="CVE-2024-27198")
```

### Compare Coverage Across Sources

```
LLM: "What detections do we have for credential dumping?"
Tool: search(query="credential dumping", limit=10)
→ Returns results from Sigma, Splunk, AND Elastic
```

### Find Web Server Attack Detections

```
LLM: "What detections cover IIS web server attacks?"
Tool: list_by_process_name(process_name="w3wp.exe")
```

### Explore a Threat Campaign

```
LLM: "Tell me about ransomware detections"
Tool: search_stories(query="ransomware")
Tool: list_by_analytic_story(story="Ransomware")
```

## Unified Schema

All detection sources (Sigma, Splunk, Elastic) are normalized to a common schema:

### Core Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (UUID for Sigma, ID field for Splunk, rule_id for Elastic) |
| `name` | Detection name/title |
| `description` | What the detection looks for |
| `query` | Detection logic (Sigma YAML, Splunk SPL, or Elastic EQL/KQL) |
| `source_type` | `sigma`, `splunk_escu`, or `elastic` |
| `severity` | Detection severity level |
| `status` | Rule status (stable, test, experimental, production, etc.) |
| `author` | Rule author |
| `file_path` | Original file path |
| `raw_yaml` | Original YAML/TOML content |

### Enhanced Fields (for Semantic Search)

| Field | Description |
|-------|-------------|
| `mitre_ids` | Mapped MITRE ATT&CK technique IDs |
| `mitre_tactics` | Extracted MITRE tactics (execution, persistence, etc.) |
| `cves` | CVE identifiers (e.g., CVE-2024-27198) |
| `analytic_stories` | Splunk analytic story names |
| `process_names` | Process names referenced in detection |
| `file_paths` | Interesting file paths referenced |
| `registry_paths` | Registry paths referenced |
| `data_sources` | Required data sources |
| `detection_type` | TTP, Anomaly, Hunting, or Correlation |
| `asset_type` | Endpoint, Web Server, Cloud, Network |
| `security_domain` | endpoint, network, cloud, access |

## Database

The index is stored at `~/.cache/security-detections-mcp/detections.sqlite`.

- Auto-created on first run
- Auto-indexed when paths are configured
- Use `rebuild_index()` to refresh after updating detection repos

## Supported Detection Formats

### Sigma Rules (YAML)

Based on the [official Sigma specification](https://github.com/SigmaHQ/sigma-specification):
- All required fields: `title`, `logsource`, `detection`
- All optional fields: `id`, `status`, `description`, `author`, `date`, `modified`, `references`, `tags`, `level`, `falsepositives`, etc.
- CVE tags extracted from `tags` field (e.g., `cve.2021-1675`)

### Splunk ESCU (YAML)

From [Splunk Security Content](https://github.com/splunk/security_content):
- Required: `name`, `id`, `search`
- Optional: `description`, `author`, `date`, `status`, `references`, `tags` (including `mitre_attack_id`, `analytic_story`, `cve`)

### Splunk Analytic Stories (YAML - Optional)

From [Splunk Security Content stories](https://github.com/splunk/security_content/tree/develop/stories):
- Provides rich narrative context for threat campaigns
- Enhances semantic search with detailed descriptions
- Links detections to broader threat context

### Elastic Detection Rules (TOML)

From [Elastic Detection Rules](https://github.com/elastic/detection-rules):
- Required: `rule.name`, `rule.rule_id`
- Optional: `rule.description`, `rule.query`, `rule.severity`, `rule.tags`, `rule.threat` (MITRE mappings)
- Supports EQL, KQL, Lucene, and ESQL query languages

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run with paths
SIGMA_PATHS="./detections/sigma/rules" \
SPLUNK_PATHS="./detections/splunk/detections" \
ELASTIC_PATHS="./detections/elastic/rules" \
STORY_PATHS="./detections/splunk/stories" \
npm start
```

## Stats (with full content)

When fully indexed with all sources:

| Source | Count |
|--------|-------|
| Sigma Rules | ~3,000+ |
| Splunk ESCU | ~2,000+ |
| Elastic Rules | ~1,500+ |
| Analytic Stories | ~330 |
| **Total** | **~6,500+** |

## License

Apache 2.0
