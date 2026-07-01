# Ring Testing

1.Place the certificate file to be converted into the specified input_dir path

```shell
input_dir=" " # Replace with the actual path
```

2.The order of tools can be adjusted as needed

```sh
tools=(OpenSSL GnuTLS wolfSSL Cryptography Golang Bouncycastle)
```

3.Intermediate results and log storage：

Intermediate results for each round are stored in: `./intermediate/half_duplex_roundX/`

Conversion logs are stored in: `./result/half_duplex/*.txt`

4.Run the Ring Testing Script

```shell
bash Ring.sh
```

(Ps:  The conversion programs for each tool are provided under ./program/. Ensure that the paths inside the script match your environment.)

