import yara
from yara import *
import os

yara_rule_1 = """
rule test {
    strings:
        $a1 = "Freshworks" nocase
        $a2 = "Freshservice" nocase
        $a3 = "Freshdesk" nocase
        $a4 = "9487"
        $a5 = "Amjith" nocase
    condition:
        1 of ($a1, $a2, $a3, $a4, $a5)
}
"""

rule = yara.compile(source=yara_rule_1)
file_path = '/Users/aramani/Documents/yara-rules/python_yara_test'
match = rule.match(file_path)

if match:
    print("Match Found")
    for matched in match:
        print(f"Rule name: {matched.rule}")
else:
    print("No Match")
