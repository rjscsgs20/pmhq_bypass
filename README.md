# pmhq_bypass

pmhq 9.0.3(x86_64)免授权补丁。

## 使用

在官方部署方式基础上,挂载 `pmhq_bypass.so` 并预载:

```yaml
services:
  pmhq:
    environment:
      - LD_PRELOAD=/opt/pmhq_bypass.so
    volumes:
      - ./pmhq_bypass.so:/opt/pmhq_bypass.so:ro
```

## 构建

```sh
gcc -shared -fPIC -O2 -Wall -Wextra -o pmhq_bypass.so pmhq_bypass.c
```
