Hypothesis 

Due to flat internal network and unrestricted PowerShell execution, and absence of egress filtering on cloud-storage destinations, an internal host might have been levereged by a compromised account or malicious insider to conduct internal network reconnaissance, automatically collect and stage sensitive documents, archive them using built-in ("living off the land") utilities, and
exfiltrate the archive to attacker-controlled cloud storage. Because the activity relied entirely on native Windows tooling, it would generate no antivirus detection and would only be visible through behavioral telemetry correlation.

Success Criteria 

Which host performed internal network reconnaissance, and against how manydistinct destinations and ports (indicating a port sweep rather than normal traffic)?

Which sensitive files were accessed, collected, and copied into a single staging location, and by which process and account?

Was the resulting archive exfiltrated to external cloud storage, and was the outbound connection initiated by `powershell.exe` rather than a sanctioned application?

Can the full kill chain — reconnaissance → collection → staging → archive → exfiltration — be reconstructed as a single time-ordered sequence on the host?

