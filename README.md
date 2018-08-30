# PSAccessSentinel
Access Sentinel stores XACML policy information in several different directory entries in the ViewDS directory, and you can access and manage the data using the LDAP protocol. This document explains the different entries and attributes and provides some examples.

_NOTE: The Access Sentinel management UI (VMA) contains logic to maintain certain kinds of logical consistency in the policy store, for instance ensuring that version numbers are sequential. The PowerShell commands do not at this time enforce these constraints, so take care and keep snapshots of your environment._

_NOTE: The Access Sentinel policy store can store more complex policies than the VMA can produce. For instance, the VMA only generates policies with a single XACML Rule. You can create policies with multiple rules in a single policy entry, and the PDP can handle it just fine. However, the VMA can only deal with policy entries containing a single rule and is unable to display or manage policies with multiple rules._

The PSAccessSentinel module contains all of the PowerShell commands to manage AccessSentinel policies. It has a dependency on the PSLDAP PowerShell module (currently only provided as binaries), which also needs to me installed.
After you pull the files from Github, add the top-level ~\PSAccessSentinel directory and the ~\PSAccessSentine\PSLDAP to your PSModulePath environment variable, and restart your PowerShell session. The run the following PowerShell command to load the modules:

`PS> Import-Module PSAccessSentinel -verbose`

PowerShell will display a list of commands that will now be available.


