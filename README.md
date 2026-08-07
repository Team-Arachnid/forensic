# Arachnid Core

**Live triage and network forensics for the Arachnid Forensic suite.**

Arachnid Core collects volatile system state and network evidence from a running
host into a tamper-evident, cryptographically signed evidence container. It is
read-only against the target: the only writes go to the container directory you
name.

For use by authorized analysts on systems they have permission to examine.

```
arachnid-core collect     -o ./ev-host01              # volatile state
arachnid-core capture     -o ./ev-net -d eth0 --duration 300 -f "not port 22"
arachnid-core parse-pcap  suspicious.pcap -o ./ev-pcap
arachnid-core verify      ./ev-host01                 # exit 0 = intact, 3 = tampered
arachnid-core report      ./ev-host01 --format html -o triage.html
```

---

