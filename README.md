This repository contains a collection of documented, proactive threat hunting operations conducted within an enterprise environment.

Rather than reacting to automated alerts, these scenarios are driven by hypothesis and management inquiries. The objective of this project is to proactively sift through SIEM/XDR telemetry to hunt for hidden misconfigurations, identify potential unauthorized access, map any discovered TTPs to the MITRE ATT&CK Framework, and engineer strategic security improvements to harden the environment against future attacks.

Tools & Technologies

SIEM / XDR: Microsoft Sentinel, Microsoft Defender for Endpoint

Query Language: Kusto Query Language (KQL)

Frameworks: MITRE ATT&CK

Techniques: Hypothesis-Driven Hunting, Log Analysis, Telemetry Correlation, Security Posture Hardening

The Threat Hunting Methodology

Every investigation in this repository strictly adheres to a 7-step Threat Hunting Lifecycle designed to answer critical security questions and improve defensive posture:

Preparation

Goal: Set up the hunt by defining the scope and objective.

Activity: Develop a data-driven hypothesis based on threat intelligence, environment changes, or inquiries from management (e.g., "During routine maintenance, legacy shared-services VMs were exposed to the internet. Could external actors have successfully brute-forced credentials before the exposure was closed?").

Data Collection

Goal: Gather relevant telemetry from endpoints, network traffic, and identity logs.

Activity: Identify and ensure the availability of necessary data tables (e.g., DeviceLogonEvents, DeviceInfo) to track anomalies, source IPs, and authentication records.

Data Analysis

Goal: Analyze the collected data to test the hypothesis.

Activity: Utilize KQL to query the data for patterns and Indicators of Compromise (IOCs). For example, looking for evidence of brute force success (a massive spike in failed logons immediately followed by a successful logon from the same IP).

Investigation

Goal: Dig deeper to understand the full context of any suspicious findings.

Activity: If anomalous activity is found, pivot to other log sources to determine what happened next. Did the actor achieve lateral movement? Are there corresponding TTPs that can be mapped to the MITRE ATT&CK framework?

Response

Goal: Deliver actionable intelligence based on the findings.

Activity: Because these are proactive hunts rather than active incident responses, the "response" focuses on communication: escalating verified breaches to the incident response team, or providing management with a clear, definitive answer regarding the security gap.

Documentation

Goal: Create a permanent record of the hunt.

Activity: Systematically document the timeline, the specific KQL queries used, the IOCs found, and the final verdict of the hunt.

Improvement

Goal: Close the security gap and refine the defensive posture.

Activity: Recommend and implement architectural changes (e.g., implementing DISA STIGs, configuring global account lockout policies, or deploying Bastion hosts) to ensure the environment is hardened against this specific attack vector moving forward.