# SIEM Integration Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](SIEM_INTEGRATION.es.md)

RedAudit produces ECS v8.11 compliant JSONL exports that integrate directly with Elastic Stack, Splunk, and other SIEM platforms.

## Quick Start (Elastic Stack)

### 1. Configure Filebeat

Copy the bundled configuration:

```bash
sudo cp siem/filebeat.yml /etc/filebeat/filebeat.yml
```

Edit the paths and credentials, then:

```bash
sudo filebeat setup
sudo systemctl restart filebeat
```

### 2. Configure Logstash (Optional)

For additional processing (severity normalization, CVE extraction):

```bash
sudo cp siem/logstash.conf /etc/logstash/conf.d/redaudit.conf
sudo systemctl restart logstash
```

### 3. Import Sigma Rules

Convert Sigma rules to your SIEM format:

```bash
# For Elasticsearch/Kibana
sigma convert -t elasticsearch -p ecs_windows siem/sigma/*.yml

# For Splunk
sigma convert -t splunk siem/sigma/*.yml

# For QRadar
sigma convert -t qradar siem/sigma/*.yml
```

## RedAudit JSONL Schema

### findings.jsonl

Each line contains a vulnerability finding:

```json
{
  "@timestamp": "2025-12-18T12:00:00Z",
  "event": {
    "module": "redaudit",
    "category": "vulnerability"
  },
  "host": {
    "ip": "192.168.1.100",
    "name": "webserver"
  },
  "vulnerability": {
    "id": "CVE-2021-44228",
    "severity": "critical",
    "score": 10.0,
    "description": "Log4Shell RCE"
  }
}
```

### assets.jsonl

Each line contains a discovered host/service:

```json
{
  "@timestamp": "2025-12-18T12:00:00Z",
  "event": {
    "module": "redaudit",
    "category": "host"
  },
  "host": {
    "ip": "192.168.1.100",
    "mac": "00:11:22:33:44:55",
    "vendor": "Dell Inc."
  },
  "service": {
    "name": "ssh",
    "version": "OpenSSH 8.9p1"
  }
}
```

## Included Sigma Rules

| Rule | Description |
|------|-------------|
| `redaudit_critical_vuln.yml` | Critical/high severity findings |
| `redaudit_missing_headers.yml` | Web security header issues |
| `redaudit_ssl_tls_vuln.yml` | SSL/TLS vulnerabilities |

## Splunk Integration

For Splunk, use the HTTP Event Collector (HEC):

1. Create a HEC token in Splunk
2. Configure Filebeat with `output.logstash` disabled and `output.http` enabled
3. Point to your Splunk HEC endpoint

## Troubleshooting

- **No data in Elasticsearch?** Check Filebeat logs: `journalctl -u filebeat -f`
- **Parsing errors?** Ensure JSONL files are valid: `jq . < findings.jsonl`
- **Missing fields?** Verify ECS version compatibility
