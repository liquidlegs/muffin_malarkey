# 🧁 muffin_malarkey  

**muffin_malarkey** is a threat intelligence command-line tool that serves up reputation lookups with a side of sass. Whether you're dealing with suspicious IPs, sketchy URLs, shady domains, or mysterious file hashes, this fluffy little beast queries top-tier sources like **VirusTotal**, **AlienVault OTX**, and **ThreatFox** to sniff out the nonsense.

Perfect for SOC analysts, incident responders, or anyone who just wants to sprinkle a little flavor on their IOC investigations.

---

## 🚀 Features

- 🔍 Lookup reputation for:
  - IP addresses  
  - URLs  
  - Domains  
  - File hashes (MD5, SHA1, SHA256)

- 🌐 Integrates with:
  - [VirusTotal](https://www.virustotal.com/)  
  - [AlienVault OTX](https://otx.alienvault.com/)  
  - [Abuse.ch ThreatFox](https://threatfox.abuse.ch/)

- 🛠️ Built for:
  - Fast IOC triage  
  - Threat intelligence enrichment  
  - SIEM automation or CLI usage

---

## 🧪 Example Usage

```bash
$ python3 muffin_malarkey.py --ip 8.8.8.8
$ python3 muffin_malarkey.py --url http://malicious.site
$ python3 muffin_malarkey.py --domain badguy.biz
$ python3 muffin_malarkey.py --hash d41d8cd98f00b204e9800998ecf8427e
