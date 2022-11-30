SUS_CFTS = {}
# No executable file at all
SUS_CFTS["NO_EXE"] = 2
# Memory region has "wx" permissions
SUS_CFTS["CODE_WX"] = 4
# .text within process differs from .text section of executable
SUS_CFTS["CODE_DIFFERS"] = 8
# Process' executable has no digital signature or it is expired/invalid
SUS_CFTS["NO_DIG_SIG"] = 4
# There are signs of packaging in executable file
SUS_CFTS["EXE_PKD"] = 16


CFT_TOTAL = sum(SUS_CFTS.values())
