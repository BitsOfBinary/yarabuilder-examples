# yarabuilder_js.py
Automatically parse variable/function names from a JavaScript file, and create a dummy rule to be refined manually. The underlying class is also designed to let you create multiple rules at once if you have many JavaScript files to signature.

## Usage
```
usage: yarabuilder_js.py [-h] --input INPUT [--rulename RULENAME] [--min-var MIN_VAR] [--max-var MAX_VAR]
                         [--min-func MIN_FUNC] [--max-func MAX_FUNC]

Generate YARA rules from variable/function names of a JavaScript script

optional arguments:
  -h, --help           show this help message and exit
  --input INPUT        JavaScript script to generate rule for
  --rulename RULENAME  (Optional) name for the generated YARA rule
  --min-var MIN_VAR    (Optional) the minimun length of JavaScript variable names to be parsed (default: 5)
  --max-var MAX_VAR    (Optional) the maximum length of JavaScript variable names to be parsed (default: 20)
  --min-func MIN_FUNC  (Optional) the minimun length of JavaScript function names to be parsed (default: 5)
  --max-func MAX_FUNC  (Optional) the maximum length of JavaScript functions names to be parsed (default: 50)
```

## Example
Running this application with the default setting on `C:\Windows\System32\spool\tools\Microsoft Print To PDF\MPDW-constraints.js` gives the following results:
```
rule generated_javascript_rule_1 {
    strings:
        $var0 = "var pdfNs" ascii wide
        $var1 = "var pdcParameterDef" ascii wide
        $var2 = "var xsiNs" ascii wide
        $var3 = "var currNode" ascii wide
        $var4 = "var ptRoot" ascii wide
        $var5 = "var pskNs" ascii wide
        $var6 = "var psk11Ns" ascii wide
        $var7 = "var pdcRoot" ascii wide
        $var8 = "var parameterDefs" ascii wide
        $var9 = "var defCount" ascii wide
        $var10 = "var prefix" ascii wide
        $var11 = "var property" ascii wide
        $var12 = "var newAttr" ascii wide
        $var13 = "var xmlCapabilities" ascii wide
        $var14 = "var rootCapabilities" ascii wide
        $var15 = "var namespaceNode" ascii wide
        $var16 = "var propCount" ascii wide
        $var17 = "var pdfNsPrefix" ascii wide
        $var18 = "var psfNs" ascii wide
        $var19 = "var newNode" ascii wide
        $var20 = "var xPathQuery" ascii wide
        $var21 = "var psk12Ns" ascii wide
        $var22 = "var newParam" ascii wide
        $var23 = "var paramName" ascii wide
        $var24 = "var capabilitiesParamDef" ascii wide
        $var25 = "var childProperty" ascii wide
        $var26 = "var pdcConfig" ascii wide
        $var27 = "var xsdNs" ascii wide
        $var28 = "var newProp" ascii wide
        $var29 = "var paramString" ascii wide
        $var30 = "var newText" ascii wide
        $var31 = "var rootNode" ascii wide
        $var32 = "var pdcParameterDefs" ascii wide
        $var33 = "var properties" ascii wide
        $var34 = "var psf2Ns" ascii wide
        $func0 = "function getPrefixForNamespace(node, namespace)" ascii wide
        $func1 = "function createProperty(strPropertyName, strNodeName, strValueType, strValue, documentNode)" ascii wide
        $func2 = "function CreateCapabilitiesParamDefFromPDC(pdcParameterDef, pdfNsPrefix, printCapabilities)" ascii wide
        $func3 = "function convertPrintTicketToDevMode(printTicket, scriptContext, devModeProperties)" ascii wide
        $func4 = "function convertDevModeToPrintTicket(devModeProperties, scriptContext, printTicket)" ascii wide
        $func5 = "function getParameterDefs(scriptContext)" ascii wide
        $func6 = "function validatePrintTicket(printTicket, scriptContext)" ascii wide
        $func7 = "function completePrintCapabilities(printTicket, scriptContext, printCapabilities)" ascii wide
        $func8 = "function SetStandardNameSpaces(xmlNode)" ascii wide

    condition:
        any of them
}
```
This can then be manually edited to remove unwanted strings, and add a more complicated `condition`.