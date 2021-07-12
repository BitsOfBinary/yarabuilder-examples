# yarabuilder_pe.py
Automatically parse metadata (import hash, rich header hash, PDB path) from a PE file, and create a dummy rule to be refined manually. The underlying class is also designed to let you create multiple rules at once if you have many PE files to signature.

## Usage
```
usage: yarabuilder_pe.py [-h] --input INPUT [--rulename RULENAME]

Generate YARA rules from metadata of a PE file

optional arguments:
  -h, --help           show this help message and exit
  --input INPUT        PE file to generate rule for
  --rulename RULENAME  (Optional) name for the generated YARA rule
```

## Example
Running this script on `calc.exe` will give the following result:
```
import "pe"
import "hash"

rule generated_pe_rule_1 {
    strings:
        $pdb_path = "calc.pdb"

    condition:
        uint16(0) == 0x5A4D and (pe.imphash() == "8eeaa9499666119d13b3f44ecd77a729" or hash.md5(pe.rich_signature.clear_data) == "3be62ba98028839e9311442fce41a41e" or any of them)
}
```