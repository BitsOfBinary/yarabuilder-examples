"""
Description: Command line application which extends YaraBuilder to parse a PowerShell script,
and output a YARA rule based off the variable/function names of the script
Author: @BitsOfBinary
License: MIT
"""

import re
import argparse
import yarabuilder


class YaraBuilderPowerShellParser(yarabuilder.YaraBuilder):
    """
    Class extension of YaraBuilder to handle parsed PowerShell variables/function names
    """

    def __init__(self, min_var_len=5, max_var_len=20, min_func_len=5, max_func_len=50):
        yarabuilder.YaraBuilder.__init__(self)

        self.min_var_len = min_var_len
        self.max_var_len = max_var_len
        self.min_func_len = min_func_len
        self.max_func_len = max_func_len

        self.ps_parser = PowerShellParser(
            min_var_len, max_var_len, min_func_len, max_func_len
        )

        self.rule_id = 1

    def add_parsed_strings(self, rule_name, str_name, str_list):
        """
        Helper method to add a collection of strings with an incrementing id
        """

        str_id = 0

        for parsed_str in str_list:
            self.add_text_string(
                rule_name,
                parsed_str,
                name=str_name + str(str_id),
                modifiers=["ascii", "wide"],
            )

            str_id += 1

        return True

    def powershell_to_yara(self, ps_str, rule_name=None):
        """
        Main method to call PowerShellParser, and then create the YARA rules
        """

        str_matches = self.ps_parser.parse_powershell(ps_str)

        if not rule_name:
            rule_name = "generated_powershell_rule_" + str(self.rule_id)
            self.rule_id += 1

        self.create_rule(rule_name)
        self.add_condition(rule_name, "any of them")

        for str_name, str_list in str_matches.items():
            self.add_parsed_strings(rule_name, str_name, str_list)


class PowerShellParser:

    """
    Class to parse a PowerShell script and return a dictionary of parsed values
    """

    ps_var_regex = r"(\$[A-Za-z0-9_-]{MIN_VAR_LENGTH,MAX_VAR_LENGTH}) "
    ps_func_regex = (
        r"(function\s{1,5}[A-Za-z0-9_-]{MIN_FUNC_LENGTH,MAX_FUNC_LENGTH})[\s\r\n]{1,5}{"
    )

    def __init__(self, min_var_len, max_var_len, min_func_len, max_func_len):
        self.min_var_len = min_var_len
        self.max_var_len = max_var_len
        self.min_func_len = min_func_len
        self.max_func_len = max_func_len

        self.compiled_ps_var_regex = None
        self.compiled_ps_func_regex = None

    def compile_regex(self):
        """
        Method to compile the regex patterns on first running of the class' main method
        """

        self.compiled_ps_var_regex = re.compile(
            self.ps_var_regex.replace("MIN_VAR_LENGTH", str(self.min_var_len)).replace(
                "MAX_VAR_LENGTH", str(self.max_var_len)
            )
        )

        self.compiled_ps_func_regex = re.compile(
            self.ps_func_regex.replace(
                "MIN_FUNC_LENGTH", str(self.min_func_len)
            ).replace("MAX_FUNC_LENGTH", str(self.max_func_len))
        )

    def parse_powershell(self, powershell_str):
        """
        Parse the variable/function names out of an input PowerShell script
        """

        if not self.compiled_ps_var_regex:
            self.compile_regex()

        var_matches = self.compiled_ps_var_regex.findall(powershell_str)
        var_matches = list(set(var_matches))

        func_matches = self.compiled_ps_func_regex.findall(powershell_str)
        func_matches = list(set(func_matches))

        return {"var": var_matches, "func": func_matches}


parser = argparse.ArgumentParser(
    description=(
        "Generate YARA rules from variable/function names of a PowerShell script"
    )
)
parser.add_argument(
    "--input", type=str, help="PowerShell script to generate rule for", required=True
)
parser.add_argument(
    "--rulename", type=str, help="(Optional) name for the generated YARA rule"
)
parser.add_argument(
    "--min-var",
    type=int,
    help="(Optional) the minimun length of PowerShell variable names to be parsed (default: 5)",
)
parser.add_argument(
    "--max-var",
    type=int,
    help="(Optional) the maximum length of PowerShell variable names to be parsed (default: 20)",
)
parser.add_argument(
    "--min-func",
    type=int,
    help="(Optional) the minimun length of PowerShell function names to be parsed (default: 5)",
)
parser.add_argument(
    "--max-func",
    type=int,
    help="(Optional) the maximum length of PowerShell functions names to be parsed (default: 50)",
)
args = parser.parse_args()

if not args.min_var:
    args.min_var = 5

if not args.max_var:
    args.max_var = 20

if not args.min_func:
    args.min_func = 5

if not args.max_func:
    args.max_func = 50

with open(args.input, "r") as infile:
    input_ps_str = infile.read()

ps_yarabuilder = YaraBuilderPowerShellParser(
    min_var_len=args.min_var,
    max_var_len=args.max_var,
    min_func_len=args.min_func,
    max_func_len=args.max_func,
)

ps_yarabuilder.powershell_to_yara(input_ps_str, rule_name=args.rulename)

rules = ps_yarabuilder.build_rules()

print(rules)
