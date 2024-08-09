# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 

# Overview 

FortiGuard Labs continue to observe attack attempts targeting the recent ServiceNow Platform vulnerabilities (CVE-2024-4879, CVE-2024-5217, & CVE-2024-5178). When chained together, could lead to Remote Code Execution and potential data breaches with unauthorized system access.  

 The **Outbreak Response - ServiceNow Remote Code Execution Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/1.1.0/README.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

 The [FortiGuard Outbreak Page](https://www.fortiguard.com/outbreak-alert/servicenow-rce) contains information about the outbreak alert **Outbreak Response - ServiceNow Remote Code Execution Attack**. 

## Background: 

ServiceNow is a widely used platform for business transformation used to manage enterprise operations such as HR and employee management. It recently has disclosed three security vulnerabilities identified as CVE-2024-4879, CVE-2024-5178, and CVE-2024-5217, these vulnerabilities affect various versions of the Now Platform including Utah, Vancouver, and Washington DC Now platform releases.

FortiGuard IPS telemetry indicates that the flaws are actively being targeted, with threat actors potentially weaponizing publicly available proof-of-concept (PoC) exploits.

CVE-2024-4879 is a Jelly Template Injection Vulnerability in UI macros that could enable an unauthenticated user to remotely execute code within the context of the Now Platform. 

CVE-2024-5178 is an Incomplete Input Validation in SecurelyAccess API. This vulnerability could allow an administrative user to gain unauthorized access to sensitive files on the web application server. 

CVE-2024-5217 is an Incomplete Input Validation in GlideExpression Script. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. 

## Announced: 

FortiGuard Labs recommends organizations using ServiceNow to apply the updates for CVE-2024-4879, CVE-2024-5178 and CVE-2024-5217 to fully mitigate risks of potential attacks. Please see the references section for links to individual KB articles disclosed by ServiceNow.  

## Latest Developments: 

July 29, 2024: FortiGuard Labs released a Threat Signal.
https://www.fortiguard.com/threat-signal-report/5497/

July 29, 2024: CISA added CVE-2024–4879 and CVE-2024-5178 to its Known Exploited Vulnerabilities (KEV) Catalog

July 11, 2024: Assetnote researchers who discovered the flaw published a detailed write-up about CVE-2024-4879 and two more flaws (CVE-2024-5178 and CVE-2024-5217) in ServiceNow that can be chained for full database access.
https://www.assetnote.io/resources/research/chaining-three-bugs-to-access-all-your-servicenow-data 

# Next Steps
 | [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) | 
 |--------------------------------------------|----------------------------------------------|------------------------|------------------------------|