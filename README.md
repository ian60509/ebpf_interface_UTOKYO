```
cd /home/ubuntu/UTOKYO/ebpf-interface
go generate ./...
go build -o ebpf-interface .
./ebpf-interface -iface upfgtp        # start UI
./ebpf-interface -iface upfgtp -debug # debug counters still supported (no UI change)
```