# Coverage

This MCP server provides access to cybersecurity data from **CFCS (Center for Cybersikkerhed — Danish Centre for Cyber Security)**.

## Data Sources

| Source | URL | Type | Coverage |
|--------|-----|------|----------|
| CFCS Website | https://www.cfcs.dk/ | Official government authority | Guidance, threat assessments, frameworks |

## Document Coverage

### Guidance Documents

CFCS guidance documents covering:
- **Forebyggelse (Prevention)**: Practical security guides for organisations and individuals
- **Vejledninger (Guides)**: IoT security, mobile device security, travel security, telework security
- **Nationale Anbefalinger (National Recommendations)**: Password security, logging recommendations
- **PDFs**: Standalone cybersecurity publications and reports

### Advisories / Threat Assessments

CFCS threat assessments (trusselsvurderinger) by sector:
- General cyber threat to Denmark
- Financial sector
- Maritime sector
- Transport sector
- Defence industry
- Telecommunications sector
- Water sector
- Healthcare sector
- Space sector
- Research and universities

### Frameworks

CFCS document series:
- `CFCS` — Core CFCS guidance series
- `NIS2-DK` — NIS2 directive implementation guidance for Denmark
- `Guidance` — General cybersecurity guidance

## Known Gaps and Limitations

- CFCS alerts (varsler) are ingested but may be incomplete
- Historical versions of documents may not be available
- Some CFCS publications require Danish language proficiency
- Coverage reflects the last ingest run; see `dk_cyber_check_data_freshness` for data age

## Update Frequency

Data is ingested periodically from the official CFCS website. Run `npm run ingest` to refresh.

See `.ingest-state.json` in the `data/` directory for the last ingest timestamp and document list.
