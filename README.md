# Genua geek week PoC

- decode hex encoded packages on command line:
```bash
cat - | xxd -r -ps | msgpack2json -d
```