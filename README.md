# 🛡️ Email Header & URL Analyzer (with VirusTotal Integration)

Një mjet i fuqishëm dhe praktik për Siguri Kibernetike (OSINT) i krijuar për të analizuar "Email Headers", për të ekstraktuar URL-të e dyshimta nga email-et dhe për t'i kontrolluar ato automatikisht përmes API-së së VirusTotal.

Ky projekt ndihmon analistët e sigurisë (SOC) dhe përdoruesit e thjeshtë të dallojnë sulmet e tipit Phishing dhe email-et keqdashëse në kohë reale.

---

## 🚀 Veçoritë (Features)

- **Email Header Parser:** Analizon burimin e email-it (raw header) dhe nxjerr informacionin kritik si: *Hop-et e rrjetit, IP-në e dërguesit, SPF, DKIM, DMARC records*.
- **URL Extractor:** Skonon automatikisht tekstin për të gjetur të gjitha vegëzat (links) e fshehura ose të dyshimta.
- **VirusTotal API Integration:** Çdo URL e gjetur dërgohet automatikisht për skanim në VirusTotal për të parë nëse është raportuar si Malicious, Phishing apo Malware.
- **Raport i Detajuar:** Shfaq një përmbledhje të pastër me ngjyra ose grafikë (varësisht nga UI/CLI) nëse email-i është i sigurt apo jo.

---

## 🛠️ Teknologjitë e Përdorura

- **Gjuha:** [HTML,CSS and JavaScript ]
- **API:** [VirusTotal v3 API](https://docs.virustotal.com/)


---

## 💻 Si ta Instalosh dhe Përdorësh

### 1. Klonimi i Repositorit
```bash
git clone https://github.com/Dardi2205/threat-intel-analyzer.git
cd threat-intel-analyzer
