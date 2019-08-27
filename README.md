# gencert

A thing that generates certificates. Since https://letsencrypt.org/ is
also a thing, you should probably use that instead. Still, gencert can
be useful to do PKI on things that only live on your LAN.

## Examples

```shell
# Generate a self-signed certificate.
# This generates ~/out/my-ca.crt and ~/out/my-ca.key.
$ gencert             \
    -c US             \
    -o example.com    \
    -cn 'My CA'       \
    -d $((100 * 24))h \
    -out ~/out/my-ca

# Generate a normal certificate.
# This reads ~/out/my-ca.crt and ~/out/my-ca.key, and generates
# ~/out/my-site.crt and ~/my-site.key.
$ gencert                \
    -ca ~/out/my-ca      \
    -c US                \
    -o example.com       \
    -cn 'My Server'      \
    -d $((10 * 24))h     \
    -dns www.example.com \
    -out ~/out/my-site
```
