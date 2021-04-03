"""
Description: Command line application which extends YaraBuilder to parse a PE file,
and output a YARA rule based off its metadata (e.g. imphash, rich header hash, PDB path, etc.)
Author: @BitsOfBinary
License: MIT
"""

import argparse
import hashlib
import pefile
import yarabuilder


class YaraBuilderPE(yarabuilder.YaraBuilder):
    """
    Class extension of YaraBuilder to handle portable executables (PE)
    """

    def __init__(self):
        yarabuilder.YaraBuilder.__init__(self)

        self.rule_id = 1

    def pe_to_yara(self, pe, rule_name=None):
        """
        Main method to call get features of the PE, and then create the YARA rules
        """

        if not rule_name:
            rule_name = "generated_pe_rule_" + str(self.rule_id)
            self.rule_id += 1

        self.create_rule(rule_name)
        self.add_import(rule_name, "pe")
        self.add_import(rule_name, "hash")

        condition = "uint16(0) == 0x5A4D and ("

        # Import hash
        imphash = pe.get_imphash()

        condition += 'pe.imphash() == "{}"'.format(imphash)

        # Rich header hash
        if pe.RICH_HEADER:
            rich_header_hash = hashlib.md5(pe.RICH_HEADER.clear_data).hexdigest()

            condition += ' or hash.md5(pe.rich_signature.clear_data) == "{}"'.format(
                rich_header_hash
            )

        # PDB path
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            if pe.DIRECTORY_ENTRY_DEBUG[0].entry:
                if pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName:
                    pdb_path = pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName

                    pdb_path = (
                        pdb_path.replace(b"\x00", b"").decode().replace("\\", "\\\\")
                    )

                    self.add_text_string(rule_name, pdb_path, name="pdb_path")

                    condition += " or any of them"

        condition += ")"

        self.add_condition(rule_name, condition)


parser = argparse.ArgumentParser(
    description=("Generate YARA rules from metadata of a PE file")
)
parser.add_argument(
    "--input", type=str, help="PE file to generate rule for", required=True
)
parser.add_argument(
    "--rulename", type=str, help="(Optional) name for the generated YARA rule"
)
args = parser.parse_args()

input_pe = pefile.PE(args.input)

pe_yarabuilder = YaraBuilderPE()

pe_yarabuilder.pe_to_yara(input_pe, rule_name=args.rulename)

rules = pe_yarabuilder.build_rules()

print(rules)
