# Tools Reference

All tools use the `dk_cyber_` prefix and return structured JSON with a `_meta` block containing disclaimer, data age, copyright, and source URL.

---

## dk_cyber_search_guidance

Full-text search across CFCS guidelines and technical reports.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `"phishing"`, `"IoT security"`, `"password guidelines"`) |
| `type` | enum | no | Filter by document type: `technical_guideline`, `it_grundschutz`, `standard`, `recommendation` |
| `series` | enum | no | Filter by document series: `CFCS`, `NIS2-DK`, `Guidance` |
| `status` | enum | no | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | no | Max results (default 20, max 100) |

**Returns:** `{ _meta, results: Guidance[], count: number }`

---

## dk_cyber_get_guidance

Get a specific CFCS guidance document by reference.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | Document reference (e.g., `"CFCS-VEJ-forebyggelse-nationale-anbefalinger-logning"`) |

**Returns:** `{ _meta, ...Guidance }` or error if not found.

---

## dk_cyber_search_advisories

Search CFCS security advisories and threat assessments.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `"ransomware"`, `"critical infrastructure"`) |
| `severity` | enum | no | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | no | Max results (default 20, max 100) |

**Returns:** `{ _meta, results: Advisory[], count: number }`

---

## dk_cyber_get_advisory

Get a specific CFCS advisory by reference.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | Advisory reference (e.g., `"CFCS-TV-cybertruslen-trusselsvurderinger"`) |

**Returns:** `{ _meta, ...Advisory }` or error if not found.

---

## dk_cyber_list_frameworks

List all CFCS frameworks and document series covered in this MCP.

**Input:** none

**Returns:** `{ _meta, frameworks: Framework[], count: number }`

---

## dk_cyber_about

Return metadata about this MCP server.

**Input:** none

**Returns:** `{ _meta, name, version, description, data_source, coverage, tools }`

---

## dk_cyber_list_sources

List all data sources with provenance metadata.

**Input:** none

**Returns:** `{ _meta, sources: Source[] }` where each source has `name`, `url`, `scope`, `last_ingest`, `license`, and `limitations`.

---

## dk_cyber_check_data_freshness

Check data freshness and staleness.

**Input:** none

**Returns:** `{ _meta, last_ingest, age_days, stale, document_counts }`

---

## Common _meta block

All responses include a `_meta` field:

```json
{
  "_meta": {
    "disclaimer": "Data sourced from CFCS (cfcs.dk). For informational use only...",
    "data_age": "2026-03-23T15:33:01.122Z",
    "copyright": "Content copyright CFCS (Center for Cybersikkerhed)...",
    "source_url": "https://www.cfcs.dk/"
  }
}
```
