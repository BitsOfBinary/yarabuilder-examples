# yarabuilder_powershell.py
Automatically parse variable/function names from a PowerShell script, and create a dummy rule to be refined manually. The underlying class is also designed to let you create multiple rules at once if you have many PowerShell scripts to signature.

## Usage
```
usage: yarabuilder_powershell.py [-h] --input INPUT [--rulename RULENAME] [--min-var MIN_VAR] [--max-var MAX_VAR]
                                 [--min-func MIN_FUNC] [--max-func MAX_FUNC]

Generate YARA rules from variable/function names of a PowerShell script

optional arguments:
  -h, --help           show this help message and exit
  --input INPUT        PowerShell script to generate rule for
  --rulename RULENAME  (Optional) name for the generated YARA rule
  --min-var MIN_VAR    (Optional) the minimun length of PowerShell variable names to be parsed (default: 5)
  --max-var MAX_VAR    (Optional) the maximum length of PowerShell variable names to be parsed (default: 20)
  --min-func MIN_FUNC  (Optional) the minimun length of PowerShell function names to be parsed (default: 5)
  --max-func MAX_FUNC  (Optional) the maximum length of PowerShell functions names to be parsed (default: 50)
```

## Example
Running this application with the default setting on [this PowerShell script that invokes Metasploit](https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1) gives the following results:
```
rule generated_powershell_rule_1 {
    strings:
        $var0 = "$DownloadCradle" ascii wide
        $var1 = "$Process" ascii wide
        $var2 = "$client" ascii wide
        $var3 = "$PowershellExe" ascii wide
        $var4 = "$ProcessInfo" ascii wide
        $func0 = "function Invoke-MetasploitPayload" ascii wide

    condition:
        any of them
}
```
This can then be manually edited to remove unwanted strings (e.g. `$var2 = "$client" ascii wide` might be too common), and add a more complicated `condition`.