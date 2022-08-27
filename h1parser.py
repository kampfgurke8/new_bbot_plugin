#!/usr/bin/python3
import sys,re,json
print("Starting the parser")

def main():
    if len(sys.argv) < 2:
        print("please add a h1 burp configuratoin file")
    else:
        parse_include()
        parse_outsc()


def parse_include():
    print("parsing inscope domains")
    forbidden = "^\$"
    with open(sys.argv[1],'r') as f:
       jsondata = json.load(f) 
    include = jsondata["target"]["scope"]["include"]
    domlist = []
    fix = []
    for i in include:
        domlist.append(i["protocol"] +"://"+ i["host"])
    
    for i in domlist:
        for n in forbidden: 
           i = i.replace(n,"") 
        fix.append(i)

    with open("inscope.txt","w") as f:
        for n in fix:
            if n.find('*') > 0:
                n = n.split("*",1)[1]

            n = re.sub(r"^\.","", n)
            f.write(n + "\n")



def parse_outsc():
    print("prasing out of scope domains")
    forbidden = "^\$"
    with open(sys.argv[1],'r') as f:
       jsondata = json.load(f) 
    include = jsondata["target"]["scope"]["exclude"]
    domlist = []
    fix = []
    for i in include:
        domlist.append(i["protocol"] +"://"+ i["host"])
    
    for i in domlist:
        for n in forbidden: 
           i = i.replace(n,"") 
        fix.append(i)

    with open("outscope.txt","w") as f:
        for n in fix:
            if n.find('*') > 0:
                n = n.split("*",1)[1]

            n = re.sub(r"^\.","", n)
            f.write(n + "\n")
main()