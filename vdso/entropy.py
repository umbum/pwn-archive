import subprocess
import re
from pprint import pprint

bentropy = {}
size = 64
for i in range(size):
    bentropy[i] = {0:0, 1:0}    # dict in dict

NSAMPLE = 500

def evaluate_bentropy():
    po = re.compile(r"vdso[\.A-Za-z0-9\s\=\>\(]*(0x[A-Za-z0-9]{16})\)")
    for _ in range(NSAMPLE):
        res = subprocess.check_output(["ldd", "/bin/ls"])
        vdso_addr_str = po.search(res.decode()).group(1)
        vdso_addr = int(vdso_addr_str, 16)
        for i in range(size):
            if vdso_addr & 0b1 << i:
                bentropy[i][1] += 1
            else:
                bentropy[i][0] += 1
        
def recommand_addr():
    rec = 0
    for i in range(size):
        if bentropy[i][1] >= bentropy[i][0]:
            rec = rec | 0b1 << i
            
    return rec


if __name__ == "__main__":
    print("[*] evaluate vDSO binary entropy {} addrs".format(NSAMPLE))
    print("[*] 0 is LSB")
    evaluate_bentropy()
    pprint(bentropy)
    pprint("[*] recommand : {}".format(hex(recommand_addr())))
    