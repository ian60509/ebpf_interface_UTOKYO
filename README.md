```
cd /home/ubuntu/UTOKYO/ebpf-interface
go generate ./...
go build -o ebpf-interface .
./ebpf-interface -iface upfgtp        # start UI
./ebpf-interface -iface upfgtp -debug # debug counters still supported (no UI change)
```

```
# 添加源 IP 黑名單
curl -X POST http://localhost:8080/api/ip-blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.60.100.1"}'

# 添加目的 IP 黑名單
curl -X POST http://localhost:8080/api/dest-blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.1.1.1"}'

# 列出所有黑名單
curl http://localhost:8080/api/ip-blacklist/list
curl http://localhost:8080/api/dest-blacklist/list

# 移除黑名單
curl -X POST http://localhost:8080/api/ip-blacklist/remove \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.60.100.1"}'

```