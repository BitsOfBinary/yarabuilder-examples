# yarabuilder_vbs.py
Automatically parse variable/function names from a VBScript script, and create a dummy rule to be refined manually. The underlying class is also designed to let you create multiple rules at once if you have many VBScript files to signature.

## Usage
```
usage: yarabuilder_vbs.py [-h] --input INPUT [--rulename RULENAME] [--min-var MIN_VAR] [--max-var MAX_VAR]
                          [--min-func MIN_FUNC] [--max-func MAX_FUNC]

Generate YARA rules from variable/function names of a VBScript file

optional arguments:
  -h, --help           show this help message and exit
  --input INPUT        VBScript file to generate rule for
  --rulename RULENAME  (Optional) name for the generated YARA rule
  --min-var MIN_VAR    (Optional) the minimun length of VBScript variable names to be parsed (default: 5)
  --max-var MAX_VAR    (Optional) the maximum length of VBScript variable names to be parsed (default: 50)
  --min-func MIN_FUNC  (Optional) the minimun length of VBScript function names to be parsed (default: 5)
  --max-func MAX_FUNC  (Optional) the maximum length of VBScript functions names to be parsed (default: 50)
```

## Example
Running this application with the default settings on `C:\Windows\system32\gatherNetworkInfo.vbs` (hopefully a default Windows scripts or I've been pwned) gives the following result:
```
rule generated_vbscript_rule_1 {
    strings:
        $var0 = "Set objWmiService " ascii wide
        $var1 = "Set objIntro " ascii wide
        $var2 = "Dim FileSet" ascii wide
        $var3 = "Set objCimService " ascii wide
        $var4 = "Set WcnInfoFile" ascii wide
        $var5 = "Dim adapterInfoFile, netInfoFile, WcnInfoFile" ascii wide
        $var6 = "Set objWMIService " ascii wide
        $var7 = "Set lanEndPoint " ascii wide
        $var8 = "Set portOffloadData " ascii wide
        $var9 = "Set xmlDoc " ascii wide
        $var10 = "Set regEx " ascii wide
        $var11 = "Set mostRecent " ascii wide
        $var12 = "Dim adapterDetailNames, adapterDetailRegValNames" ascii wide
        $var13 = "Set WcnInfoFile " ascii wide
        $var14 = "Set Matches " ascii wide
        $var15 = "Set colFiles " ascii wide
        $var16 = "Set fileNameForCab " ascii wide
        $var17 = "Dim MiracastInfoFile" ascii wide
        $var18 = "Set AdapterProp " ascii wide
        $var19 = "Set portBandwidthData " ascii wide
        $var20 = "Dim fwPolicy2    " ascii wide
        $var21 = "Set adapterInfoFile " ascii wide
        $var22 = "Set objTextFile " ascii wide
        $var23 = "Dim WcnInfoFile" ascii wide
        $var24 = "Dim buildDetailNames, buildDetailRegValNames" ascii wide
        $var25 = "Set connectedlanEndPoint " ascii wide
        $var26 = "Set queryResult " ascii wide
        $var27 = "Set objRoot " ascii wide
        $var28 = "Dim FSO, shell, xslProcessor" ascii wide
        $var29 = "Dim NotifRegFile, RegFolder, Key" ascii wide
        $var30 = "Set objVmmsService " ascii wide
        $var31 = "Set nicLanEndPoint " ascii wide
        $var32 = "Set MiracastInfoFile " ascii wide
        $var33 = "Set fileProp " ascii wide
        $var34 = "Set offload " ascii wide
        $var35 = "Set switchSetting " ascii wide
        $var36 = "Set shell " ascii wide
        $var37 = "Set portOffload " ascii wide
        $var38 = "Set portIsolationData " ascii wide
        $var39 = "Set objShell " ascii wide
        $var40 = "Set portLanEndPoint " ascii wide
        $var41 = "Set envInfoFile " ascii wide
        $var42 = "Set fwPolicy2 " ascii wide
        $var43 = "Set portBandwidth " ascii wide
        $var44 = "Dim ProfileType" ascii wide
        $var45 = "Set extensionList " ascii wide
        $var46 = "Set portSettingObject " ascii wide
        $var47 = "Set colItems " ascii wide
        $var48 = "Set entryObject " ascii wide
        $var49 = "Dim envInfoFile" ascii wide
        $var50 = "Set objFolder " ascii wide
        $var51 = "Set switchPort " ascii wide
        $var52 = "Set switches " ascii wide
        $var53 = "Set objVirtualizationService " ascii wide
        $var54 = "Dim adapters, objReg" ascii wide
        $var55 = "Set portVlanData " ascii wide
        $var56 = "Set objService " ascii wide
        $var57 = "Dim RulesObject" ascii wide
        $var58 = "Set objReg " ascii wide
        $var59 = "Set outputFile " ascii wide
        $var60 = "Dim Dot3FileSet" ascii wide
        $var61 = "Set portSecurityData " ascii wide
        $var62 = "Set bandwidth " ascii wide
        $var63 = "Dim objReg, outputFile" ascii wide
        $var64 = "Set RulesObject " ascii wide
        $func0 = "Sub GetDnsInfo(logFileName)" ascii wide
        $func1 = "Sub GetGPResultInfo(logFileName)" ascii wide
        $func2 = "Sub GetWinsockLog(outputFileName)" ascii wide
        $func3 = "Sub GetBatteryInfo(outputFile)" ascii wide
        $func4 = "Sub DumpRegKey(outputFileName,regpath)" ascii wide
        $func5 = "Sub GetOSInfo(outputFileName)" ascii wide
        $func6 = "Sub GetShowStateInfo(outputFileName, logFileName)" ascii wide
        $func7 = "Sub GetFileSharingInfo(logFileName)" ascii wide
        $func8 = "Sub GetWiredAdapterInfo(outputFile)" ascii wide
        $func9 = "Sub AddXmlNodeEntry(xmlDoc, entryName, entryValue, parentEntry, entryObject)" ascii wide
        $func10 = "Sub GetVmswitchLog(vmswitchlogFileName, vmmslogFileName)" ascii wide
        $func11 = "Sub GetExistingFile(inputFileName, outputDirectory)" ascii wide
        $func12 = "Sub GetSystemExportLog(logFileName)" ascii wide
        $func13 = "Sub GetEpdPolicies(outputFileName)" ascii wide
        $func14 = "Sub GetWlanReport(outputPath)" ascii wide
        $func15 = "Sub GetHomeGroupListener(outputFileName)" ascii wide
        $func16 = "Sub GetBatteryReport(batteryReportFilename)" ascii wide
        $func17 = "Sub GetSysPortsInfo(outputFileName, logFileName)" ascii wide
        $func18 = "Sub GetServiceLogInfo(outputFileName)" ascii wide
        $func19 = "Sub GetExistingFiles(inputPath, outputPath, filePrefix)" ascii wide
        $func20 = "Sub GetWirelessAdapterInfo(outputFile)" ascii wide
        $func21 = "Sub GetExistingFiles(inputPath, outputPath, filePrefix, fileSuffix)" ascii wide
        $func22 = "Sub GetNeighborInfo(logFileName)" ascii wide
        $func23 = "Sub GetVmswitchInfo(outputFileName)" ascii wide
        $func24 = "Sub GetHotFixInfo(outputFileName)" ascii wide
        $func25 = "Sub GetHomeGroupProvider(outputFileName)" ascii wide
        $func26 = "Sub GetPantherFiles(inputPath, outputPath, outputFilePrefix, filePrefix, fileSuffix)" ascii wide
        $func27 = "Sub RunCmd(CommandString, OutputFile)" ascii wide
        $func28 = "Sub GetMiracastInfo(outputFileName)" ascii wide
        $func29 = "Sub GetPolicyManager(outputFileName)" ascii wide
        $func30 = "Sub GetCreateBindingMap(outputFileName)" ascii wide
        $func31 = "Sub GetWwanLog(logFileName)" ascii wide
        $func32 = "Sub GetWcnInfo(outputFileName)" ascii wide
        $func33 = "Sub GetWcmLog(logFileName)" ascii wide
        $func34 = "Sub GetWirelessAutoconfigLog(logFileName)" ascii wide
        $func35 = "Sub GetApplicationExportLog(logFileName)" ascii wide
        $func36 = "Sub DumpWinsockCatalog(outputFileName)" ascii wide
        $func37 = "Sub GetNetEventsInfo(outputFileName, logFileName)" ascii wide
        $func38 = "Sub GetNetioInfo(outputFileName)" ascii wide
        $func39 = "Sub GetWfpInfo(outputFileName, logFileName)" ascii wide
        $func40 = "Sub GetEnvironmentInfo(outputFileName)" ascii wide
        $func41 = "Sub GetPowershellInfo(outputFileName)" ascii wide
        $func42 = "Sub GetLatestNdfSessionEtlFile(inputPath, outputPath, filePrefix, fileSuffix)" ascii wide

    condition:
        any of them
}
```
This can then be manually edited to remove unwanted strings, and add a more complicated `condition`.