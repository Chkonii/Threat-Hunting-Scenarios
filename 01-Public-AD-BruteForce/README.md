Hypothesis

Due to misconfigured host-based firewalls and a lack of account lockout policies, shared-services VMs (DNS, AD DS, DHCP) located on the internet-facing segment of the enterprise environment were temporarily exposed. An external threat actor may have leveraged this exposure to brute-force credentials, achieve a successful interactive network logon, and potentially initiate lateral movement across the domain.

Success Criteria

This hunt will be considered successful if it can definitively answer the following:

Which specific VMs were exposed and externally reachable?

Which hosts received excessive failed network logon attempts originating from public IP addresses?

Was any brute-force failure burst immediately followed by a successful logon (LogonSuccess) from the same source?

If a breach occurred, what post-compromise activity (e.g., process execution, lateral movement) took place on the host?