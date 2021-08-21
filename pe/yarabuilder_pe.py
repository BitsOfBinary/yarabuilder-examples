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
import glob
import logging


class YaraBuilderPE(yarabuilder.YaraBuilder):
    """
    Class extension of YaraBuilder to handle portable executables (PE)
    """

    def __init__(self):
        yarabuilder.YaraBuilder.__init__(self)

        self.imphashes = []
        self.rich_headers_hashes = []
        self.pdbs = []
        self.rule_id = 1
        
    def get_pe_sha256_hash(self, pe):
        return hashlib.sha256(pe.__data__).hexdigest()
        
    def parse_imphash(self, pe):
        try:
            imphash = pe.get_imphash()
            self.imphashes.append(imphash)
        except:
            pass
            
    def parse_rich_header_hash(self, pe):
        if pe.RICH_HEADER:
            rich_header_hash = hashlib.md5(pe.RICH_HEADER.clear_data).hexdigest()
            
            self.rich_headers_hashes.append(rich_header_hash)
            
    def parse_pdb(self, pe):
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            if pe.DIRECTORY_ENTRY_DEBUG[0].entry:
                if pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName:
                    pdb_path = pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName

                    pdb_path = (
                        pdb_path.replace(b"\x00", b"").decode().replace("\\", "\\\\")
                    )

                    self.pdbs.append(pdb_path)
        
    def parse_pe(self, pe_filepath, rule_name):
        try:
            pe = pefile.PE(pe_filepath)
        except pefile.PEFormatError:
            logging.warning("{} is not a PE".format(pe_filepath))
            return
            
        pe_hash = self.get_pe_sha256_hash(pe)
        
        self.add_meta(rule_name, "hash", pe_hash)
           
        self.parse_imphash(pe)
        self.parse_rich_header_hash(pe)
        self.parse_pdb(pe)
        
                    
    def build_pe_condition(self, rule_name):
        
        condition = "uint16(0) == 0x5A4D and ("
        
        imphash_str = ""
        if self.imphashes:
            
            for imphash in self.imphashes[:-1]:
                imphash_str += 'pe.imphash() == "{}" or '.format(imphash)
                
            imphash_str += 'pe.imphash() == "{}"'.format(self.imphashes[-1])
        
        rich_header_hash_str = ""
        if self.rich_headers_hashes:
            
            for rich_header_hash in self.rich_headers_hashes[:-1]:
                rich_header_hash_str += 'hash.md5(pe.rich_signature.clear_data) == "{}" or '.format(rich_header_hash)
                
            rich_header_hash_str += 'hash.md5(pe.rich_signature.clear_data) == "{}"'.format(self.rich_headers_hashes[-1])
        
        pdb_str = ""
        if self.pdbs:
            pdb_str = "any of them"
            pdb_id = 0
            
            for pdb in self.pdbs:
                self.add_text_string(rule_name, pdb, name="pdb_path{}".format(pdb_id))
                pdb_id += 1
                
        condition += ' or '.join(filter(None, [imphash_str, rich_header_hash_str, pdb_str]))
        
        condition += ")"

        self.add_condition(rule_name, condition)
            

    def pe_to_yara(self, input_pes, rule_name=None):
        """
        Main method to call get features of the PE, and then create the YARA rules
        """

        if not rule_name:
            rule_name = "generated_pe_rule_" + str(self.rule_id)
            self.rule_id += 1
            
        self.create_rule(rule_name)
        self.add_import(rule_name, "pe")
        self.add_import(rule_name, "hash")

        for pe_filepath in input_pes:
            self.parse_pe(pe_filepath, rule_name)

        self.build_pe_condition(rule_name)


parser = argparse.ArgumentParser(
    description=("Generate YARA rules from the metadata of PE files")
)
parser.add_argument(
    "--input", type=str, help="PE file(s) to generate rule for (accepts wildcards)", required=True
)
parser.add_argument(
    "--rulename", type=str, help="(Optional) name for the generated YARA rule"
)
args = parser.parse_args()

input_pes = glob.glob(args.input)

pe_yarabuilder = YaraBuilderPE()

pe_yarabuilder.pe_to_yara(input_pes, rule_name=args.rulename)

rules = pe_yarabuilder.build_rules()

print(rules)
