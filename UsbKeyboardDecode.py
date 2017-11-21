#!/usr/bin/python
from scapy.all import *
import sys

KEY_CODES = {
4:"A",
5:"B",
6:"C",
7:"D",
8:"E",
9:"F",
10:"G",
11:"H",
12:"I",
13:"J",
14:"K",
15:"L",
16:"M",
17:"N",
18:"O",
19:"P",
20:"Q",
21:"R",
22:"S",
23:"T",
24:"U",
25:"V",
26:"W",
27:"X",
28:"Y",
29:"Z",
30:"1",
31:"2",
32:"3",
33:"4",
34:"5",
35:"6",
36:"7",
37:"8",
38:"9",
39:"0",
40:"\n",
44:" ",
45:"_",
46:"=",
47:"{",
48:"}",
52:"'",
55:".",
42:"!~!",
79:">",
80:"<",
}
if len(sys.argv) == 1:
    print "usage: python UsbkeyboardDecode.py [pcapfile]"
    sys.exit()

target =   sys.argv[1]
pkts = rdpcap(target)
msg1= " "
for packet in pkts:
    global msg1
    hid_report = packet.load[-8:]
    key_code = ord(hid_report[2])
    ch = KEY_CODES.get(key_code, False)
    if ch:
        msg1 += ch


print msg1

index = 0
list= [];
for p in msg1:

	if str(p) == "<":
		index = int(index-1)
		continue
	if str(p) == ">":
		index = int(index+1)
		continue


	list.insert(index-1,str(p))

	print "".join(str(x) for x in list)
	index= index + 1
