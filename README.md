# pmhq_bypass

pmhq 8.1.1 (x86_64) 免授权补丁。

## 使用

在官方部署方式基础上增加两个挂载：

```yaml
volumes:
  - ./pmhq_bypass.so:/opt/pmhq_bypass.so:ro
  - ./startup.sh:/startup.sh:ro
```

`startup.sh` 与官方文件的差异只有一行：启动命令前加 `LD_PRELOAD=/opt/pmhq_bypass.so`。
