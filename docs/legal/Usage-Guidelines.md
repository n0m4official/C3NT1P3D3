# ⚖️ C3NT1P3D3 Legal & Ethical Usage Guidelines

**Version:** 1.2  
**Last Updated:** October 2025  
**Jurisdiction:** Canada and the Province of Alberta (with international considerations)

---

## ⚠️ CRITICAL LEGAL NOTICE

**READ THIS ENTIRE DOCUMENT BEFORE USING THIS SOFTWARE**

C3NT1P3D3 (CENTIPEDE) is a security research and vulnerability assessment tool designed for **AUTHORIZED TESTING ONLY**. Unauthorized use of this software may violate:

- **Criminal Code of Canada** (Section 342.1 - Unauthorized use of computer)
- **Personal Information Protection and Electronic Documents Act (PIPEDA)**
- **Computer Fraud and Abuse Act (USA)** - If targeting US systems
- **Computer Misuse Act (UK)** - If targeting UK systems
- **Various international cybercrime laws**

**Penalties for unauthorized use can include:**
- Criminal prosecution
- Imprisonment (up to 10 years in Canada)
- Substantial fines
- Civil liability
- Professional sanctions

---

## 📋 Table of Contents

1. [Authorized Use Cases](#authorized-use-cases)
2. [Prohibited Uses](#prohibited-uses)
3. [Authorization Requirements](#authorization-requirements)
4. [Scope Definition](#scope-definition)
5. [Responsible Disclosure](#responsible-disclosure)
6. [Incident Response](#incident-response)
7. [Legal Compliance](#legal-compliance)
8. [Liability Limitations](#liability-limitations)

---

## 1. Authorized Use Cases

### ✅ Permitted Uses

#### 1.1 Internal Security Assessments
- Testing your own organization's systems
- Vulnerability assessments of owned infrastructure
- Security audits of managed services
- Compliance testing (PCI DSS, ISO 27001, etc.)

**Requirements:**
- Written authorization from system owner
- Documented scope of testing
- Incident response plan in place
- Stakeholder notification

#### 1.2 Authorized Penetration Testing
- Contracted security assessments
- Red team engagements
- Security research with permission
- Bug bounty programs

**Requirements:**
- Signed contract or engagement letter
- Rules of engagement document
- Scope limitations clearly defined
- Emergency contact information

#### 1.3 Educational & Research Purposes
- Academic research with proper authorization
- Security training in controlled environments
- Vulnerability research on owned systems
- Proof-of-concept development

**Requirements:**
- Isolated test environment
- No production systems
- Institutional approval (if applicable)
- Ethical review board approval (if applicable)

#### 1.4 Compliance & Audit
- Regulatory compliance testing
- Security control validation
- Third-party audits
- Risk assessments

**Requirements:**
- Audit authorization
- Compliance framework alignment
- Documentation requirements met
- Stakeholder coordination

---

## 2. Prohibited Uses

### ❌ NEVER Use This Tool For:

#### 2.1 Unauthorized Access
- Scanning systems without explicit permission
- Testing third-party networks
- Accessing systems you don't own or manage
- Circumventing security controls without authorization

**Legal Consequences:**
- Criminal Code of Canada, Section 342.1
- Up to 10 years imprisonment
- Substantial fines
- Criminal record

#### 2.2 Malicious Activities
- Deploying malware or ransomware
- Data theft or exfiltration
- Service disruption (DoS/DDoS)
- System damage or destruction

**Legal Consequences:**
- Criminal prosecution
- Civil liability
- Restitution requirements
- Professional sanctions

#### 2.3 Privacy Violations
- Unauthorized data collection
- Personal information harvesting
- Surveillance without consent
- PIPEDA violations

**Legal Consequences:**
- Privacy Commissioner investigation
- Substantial fines
- Civil lawsuits
- Reputational damage

#### 2.4 Commercial Espionage
- Competitor intelligence gathering
- Trade secret theft
- Intellectual property theft
- Unauthorized market research

**Legal Consequences:**
- Criminal charges
- Civil lawsuits
- Injunctions
- Damages

---

## 3. Authorization Requirements

### 3.1 Written Authorization Template

**ALL security testing must have written authorization. Use this template:**

```
SECURITY TESTING AUTHORIZATION

Date: [DATE]
Organization: [ORGANIZATION NAME]
Authorized By: [NAME, TITLE]

I, [NAME], in my capacity as [TITLE] of [ORGANIZATION], hereby authorize:

Tester Name: [YOUR NAME]
Tester Organization: [YOUR ORGANIZATION]

To conduct security vulnerability assessments on the following systems:

SCOPE:
- IP Ranges: [LIST IP RANGES]
- Domains: [LIST DOMAINS]
- Systems: [LIST SPECIFIC SYSTEMS]

TESTING PERIOD:
- Start Date: [DATE]
- End Date: [DATE]
- Authorized Hours: [TIME RANGE]

AUTHORIZED ACTIVITIES:
- [ ] Vulnerability scanning
- [ ] Port scanning
- [ ] Service enumeration
- [ ] Vulnerability verification
- [ ] Other: [SPECIFY]

RESTRICTIONS:
- [ ] No denial of service testing
- [ ] No data exfiltration
- [ ] No social engineering
- [ ] Other: [SPECIFY]

EMERGENCY CONTACTS:
- Primary: [NAME, PHONE, EMAIL]
- Secondary: [NAME, PHONE, EMAIL]
- Security Team: [PHONE, EMAIL]

ACKNOWLEDGMENTS:
- Tester agrees to follow all guidelines
- Tester agrees to responsible disclosure
- Tester agrees to stop immediately if requested
- Tester agrees to provide detailed report

Authorizing Signature: ___________________
Print Name: [NAME]
Title: [TITLE]
Date: [DATE]

Tester Signature: ___________________
Print Name: [YOUR NAME]
Date: [DATE]
```

### 3.2 Scope Documentation

**Create a detailed scope document including:**

1. **In-Scope Systems**
   - IP addresses/ranges
   - Hostnames/domains
   - Specific services/ports
   - Applications

2. **Out-of-Scope Systems**
   - Production databases
   - Critical infrastructure
   - Third-party systems
   - Personal devices

3. **Testing Constraints**
   - Time windows
   - Rate limiting
   - Excluded tests
   - Notification requirements

4. **Success Criteria**
   - Objectives
   - Deliverables
   - Timeline
   - Reporting format

---

## 4. Scope Definition

### 4.1 IP Range Validation

**Before scanning ANY IP range:**

```
┌─────────────────────────────────────────────────────────────┐
│ IP Range Validation Checklist                              │
├─────────────────────────────────────────────────────────────┤
│ [ ] Verify IP range ownership                               │
│ [ ] Confirm authorization covers entire range               │
│ [ ] Check for third-party systems in range                  │
│ [ ] Identify critical systems requiring special handling    │
│ [ ] Document any exclusions                                 │
│ [ ] Verify no public internet IPs without explicit auth     │
│ [ ] Confirm testing window                                  │
│ [ ] Establish emergency stop procedures                     │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Safe IP Ranges (RFC 1918)

**These are generally safe for testing (but still require authorization):**

- `10.0.0.0/8` - Private Class A
- `172.16.0.0/12` - Private Class B
- `192.168.0.0/16` - Private Class C
- `127.0.0.0/8` - Loopback
- `169.254.0.0/16` - Link-local

**NEVER scan without authorization, even in private ranges!**

### 4.3 Dangerous IP Ranges

**NEVER scan these without EXPLICIT authorization:**

- Public internet IP addresses
- Government networks (.gov, .gc.ca)
- Military networks (.mil)
- Critical infrastructure
- Healthcare systems
- Financial institutions
- Educational institutions
- Cloud provider infrastructure

---

## 5. Responsible Disclosure

### 5.1 Vulnerability Disclosure Process

**If you discover a vulnerability:**

```
┌─────────────────────────────────────────────────────────────┐
│ Responsible Disclosure Timeline                             │
├─────────────────────────────────────────────────────────────┤
│ Day 0:   Discovery                                          │
│          └─> Document vulnerability                         │
│          └─> Verify exploitability                          │
│          └─> Assess severity                                │
│                                                              │
│ Day 1:   Initial Notification                               │
│          └─> Contact vendor/organization                    │
│          └─> Provide summary (not full details)             │
│          └─> Establish communication channel                │
│                                                              │
│ Day 7:   Detailed Report                                    │
│          └─> Provide technical details                      │
│          └─> Include reproduction steps                     │
│          └─> Suggest remediation                            │
│                                                              │
│ Day 30:  Follow-up                                          │
│          └─> Check remediation status                       │
│          └─> Offer assistance                               │
│          └─> Discuss disclosure timeline                    │
│                                                              │
│ Day 90:  Public Disclosure (if appropriate)                 │
│          └─> Coordinate with vendor                         │
│          └─> Publish advisory                               │
│          └─> Share with community                           │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Vulnerability Report Template

```markdown
# Vulnerability Report

## Summary
[Brief description of vulnerability]

## Severity
- CVSS Score: [SCORE]
- Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]

## Affected Systems
- Product: [NAME]
- Version: [VERSION]
- Platform: [PLATFORM]

## Vulnerability Details
[Technical description]

## Proof of Concept
[Steps to reproduce - DO NOT include exploit code]

## Impact
[Potential consequences]

## Remediation
[Recommended fixes]

## Timeline
- Discovered: [DATE]
- Vendor Notified: [DATE]
- Patch Available: [DATE]
- Public Disclosure: [DATE]

## Contact
- Reporter: [YOUR NAME]
- GitHub: [YOUR GITHUB USERNAME]
- Contact Method: [PREFERRED METHOD]
```

---

## 6. Incident Response

### 6.1 If Something Goes Wrong

**STOP IMMEDIATELY if:**
- Systems become unresponsive
- Services are disrupted
- Data is corrupted or lost
- Alarms are triggered
- You exceed authorized scope
- You discover illegal activity

**Immediate Actions:**

1. **STOP ALL TESTING**
   - Terminate all scans
   - Close all connections
   - Document what happened

2. **NOTIFY IMMEDIATELY**
   - Contact primary emergency contact
   - Explain what happened
   - Provide timeline of events

3. **DOCUMENT EVERYTHING**
   - What you were doing
   - What commands were run
   - What the system response was
   - Exact timestamps

4. **COOPERATE FULLY**
   - Provide all logs
   - Answer all questions
   - Assist with remediation
   - Follow instructions

### 6.2 Emergency Contact Template

```
SECURITY TESTING INCIDENT REPORT

Date/Time: [TIMESTAMP]
Tester: [YOUR NAME]
Organization: [YOUR ORG]

INCIDENT SUMMARY:
[Brief description of what happened]

AFFECTED SYSTEMS:
- IP Address: [IP]
- Hostname: [HOSTNAME]
- Service: [SERVICE]

ACTIONS TAKEN:
1. [ACTION 1]
2. [ACTION 2]
3. [ACTION 3]

CURRENT STATUS:
[System status]

IMMEDIATE CONTACTS NOTIFIED:
- [NAME] at [TIME]
- [NAME] at [TIME]

NEXT STEPS:
[Proposed actions]

Contact: [YOUR PHONE/EMAIL]
```

---

## 7. Legal Compliance

### 7.1 Canadian Legal Framework

#### Criminal Code of Canada
**Section 342.1 - Unauthorized use of computer**

> Every person who, fraudulently and without colour of right,
> (a) obtains, directly or indirectly, any computer service,
> (b) by means of an electro-magnetic, acoustic, mechanical or other device, intercepts or causes to be intercepted, directly or indirectly, any function of a computer system,
> (c) uses or causes to be used, directly or indirectly, a computer system with intent to commit an offence under paragraph (a) or (b) or under section 430 in relation to computer data or a computer system, or
> (d) uses, possesses, traffics in or permits another person to have access to a computer password that would enable a person to commit an offence under paragraph (a), (b) or (c)
> is guilty of an indictable offence and liable to imprisonment for a term of not more than 10 years, or is guilty of an offence punishable on summary conviction.

**What this means for you:**
- You MUST have authorization ("colour of right")
- Authorization must be from someone with authority
- Exceeding authorization is still illegal
- "I didn't know" is not a defense

### 7.2 International Considerations

If testing systems outside Canada:

**United States:**
- Computer Fraud and Abuse Act (CFAA)
- Stored Communications Act
- State-specific laws

**European Union:**
- GDPR (data protection)
- Network and Information Security Directive
- National cybercrime laws

**United Kingdom:**
- Computer Misuse Act 1990
- Data Protection Act 2018
- Investigatory Powers Act 2016

### 7.3 Ethical Standards Alignment

C3NT1P3D3 (CENTIPEDE) adheres to the ethical principles outlined by the **Canadian Centre for Cyber Security (CCCS)** and the **Communications Security Establishment (CSE)**, which emphasize lawful, authorized, and responsible cyber defence operations.  
The project’s purpose aligns with CSE’s defensive mandate to:
- Protect Canadian information infrastructure,
- Advance research in vulnerability detection,
- Promote secure system design and cyber resilience.

In keeping with these standards:
- No offensive or exploitative capabilities are included or encouraged.
- All vulnerability detection modules operate under strict authorization and non-destructive testing principles.
- The framework is intended solely for lawful defensive research, education, and institutional training within authorized environments.

This alignment ensures that C3NT1P3D3 (CENTIPEDE)’s design, operation, and ethical posture conform to both **Canadian law (Criminal Code s.342.1)** and **CSE’s professional ethical expectations** for cybersecurity research.


**Always consult with legal counsel for international testing.**

---

## 8. Liability Limitations

### 8.1 Disclaimer

```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
```

### 8.2 User Responsibility

**BY USING THIS SOFTWARE, YOU AGREE THAT:**

1. You are solely responsible for your actions
2. You will obtain proper authorization before testing
3. You will comply with all applicable laws
4. You will use the tool ethically and responsibly
5. You will not hold the authors liable for your misuse
6. You understand the legal risks
7. You have consulted with legal counsel if necessary
8. You accept full responsibility for any consequences

### 8.3 Indemnification

Users agree to indemnify and hold harmless the authors, contributors, and maintainers from any claims, damages, losses, liabilities, and expenses (including legal fees) arising from:

- Unauthorized use of the software
- Violation of applicable laws
- Exceeding authorized scope
- Negligent or willful misconduct
- Failure to follow these guidelines

---

## 9. Best Practices

### 9.1 Pre-Engagement Checklist

- [ ] Written authorization obtained
- [ ] Scope clearly defined and documented
- [ ] Emergency contacts established
- [ ] Testing window confirmed
- [ ] Stakeholders notified
- [ ] Incident response plan in place
- [ ] Backup and rollback procedures ready
- [ ] Legal review completed (if necessary)
- [ ] Insurance coverage verified (if applicable)
- [ ] Tools tested in lab environment

### 9.2 During Testing

- [ ] Stay within authorized scope
- [ ] Monitor for adverse effects
- [ ] Document all activities
- [ ] Maintain communication with stakeholders
- [ ] Stop immediately if issues arise
- [ ] Follow rate limiting guidelines
- [ ] Respect testing windows
- [ ] Keep detailed logs

### 9.3 Post-Engagement

- [ ] Provide comprehensive report
- [ ] Include remediation recommendations
- [ ] Securely delete all collected data
- [ ] Destroy unauthorized copies
- [ ] Follow up on critical findings
- [ ] Conduct lessons learned session
- [ ] Archive authorization documents
- [ ] Update procedures based on experience

---

## 10. Resources

### Legal Resources
- [Canadian Centre for Cyber Security](https://cyber.gc.ca/)
- [Office of the Privacy Commissioner of Canada](https://www.priv.gc.ca/)
- [PIPEDA Compliance](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/)

### Security Resources
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)

### Professional Organizations
- [ISC² Code of Ethics](https://www.isc2.org/Ethics)
- [EC-Council Code of Ethics](https://www.eccouncil.org/code-of-ethics/)
- [SANS Security Ethics](https://www.sans.org/about/ethics/)

---

## 11. Contact & Support

### Reporting Misuse
If you become aware of misuse of this tool:
- Report via: GitHub Issues (https://github.com/n0m4official/C3NT1P3D3/issues)
- Mark as: Security concern
- Include: Details of misuse, evidence, contact information

### Legal Questions
For legal questions about this tool:
- Consult with qualified legal counsel
- Review applicable laws in your jurisdiction
- Seek professional advice before testing

### Security Questions
For responsible disclosure or security questions:
- GitHub Issues: https://github.com/n0m4official/C3NT1P3D3/issues
- Mark as: Security vulnerability
- Response time: 48-72 hours
- Note: This is a solo developer project - please be patient

---

## 12. Acknowledgment

**I have read and understand these guidelines. I agree to:**

- Use this tool only for authorized purposes
- Obtain proper authorization before testing
- Comply with all applicable laws
- Follow responsible disclosure practices
- Accept full responsibility for my actions
- Indemnify the author from my misuse

**Signature:** ___________________  
**Print Name:** ___________________  
**Date:** ___________________  
**Organization:** ___________________

---

**Remember: With great power comes great responsibility. Use this tool ethically, legally, and responsibly.**

---

**Document Version:** 1.1  
**Last Updated:** October 2025  
**Next Review:** April 2026
