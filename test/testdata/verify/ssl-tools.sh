#!/bin/bash

caPath=${CAPATH:-./}
caName=${CANAME:-RootCA}
caPriv=${CAPRIV:-${caName}.key}
caCert=${CACERT:-${caName}.crt}
caPem=${CAPEM:-${caName}.pem}
caDays=${CADAYS:-365}

outPath=${OUTPATH:-./}
mkcertBin=${MKCERTBIN:-./mkcert}
OS="$(uname)"
mkcertDownloadURL="https://github.com/FiloSottile/mkcert/releases/download/v1.4.3/mkcert-v1.4.3-linux-amd64"
if [[ "$OS" == "Darwin" ]]; then
  mkcertDownloadURL="https://github.com/FiloSottile/mkcert/releases/download/v1.4.3/mkcert-v1.4.3-darwin-amd64"
fi


echo
echo "root CA private key path to file '${caPath}/${caPriv}' (env CAPRIV)"
echo "root CA cert key path to file '${caPath}/${caCert}' (env CACERT)"
echo "root CA pem key path to file '${caPath}/${caPem}' (env CAPEM)"
echo "root CA lifetime '${caDays}' days (env CADAYS)"
echo

case "$1" in
    "install-mkcert")
      if [ ! -f $mkcertBin ]; then
        curl -L $mkcertDownloadURL -o $mkcertBin -s
        chmod +x $mkcertBin
      fi
      $($mkcertBin -version)
      $($mkcertBin -install)
    ;;
    "copy-trusted-ca-from-mkcert")
      name=$2
      echo "name '${name}'"
      cp "$($mkcertBin -CAROOT)/rootCA-key.pem" ${caPath}/$name.key
      cp "$($mkcertBin -CAROOT)/rootCA.pem" ${caPath}/$name.crt
      cp "$($mkcertBin -CAROOT)/rootCA.pem" ${caPath}/$name.pem
    ;;
    "ca" | "c" | "C"  )
      openssl \
        req -x509 \
        -nodes -new -sha256 \
        -days $caDays \
        -newkey rsa:2048 \
        -keyout $caPath/$caPriv \
        -out $caPath/$caPem \
        -subj "/C=US/CN=Example-Root-CA"
      [ $? -eq 0 ]  || { echo "⛔ failed gen CA"; exit 1 ;}

      openssl x509 \
        -outform pem \
        -in $caPath/$caPem \
        -out $caPath/$caCert
      [ $? -eq 0 ]  || { echo "⛔ failed gen CA"; exit 1 ;}

      echo "👌  done."

    ;;
    "fingerprint" | "f" |"F")
      echo -n | openssl s_client -connect $2 | openssl x509 -noout -fingerprint -sha1
    ;;
    "simple" | "s" | "S")
      name=$2
      echo "name '${name}'"
      domain=${3:-localhost}
      echo "domain '${domain}'"
      days=${4:-365}
      echo "lifetime '${days}' days"
      openssl req -x509 -nodes -newkey rsa:2048 -keyout $outPath/$name.key -out $outPath/$name.crt -days $days -subj "/CN=${domain}"

      openssl x509 -in $outPath/${name}.crt -noout -fingerprint -sha1 > $outPath/${name}.crt.sha1
      [ $? -eq 0 ]  || { echo "⛔ failed to gen fingerprint cert '${domain}'"; exit 1 ;}
    ;;
    "domain" | "d" | "D" )
      name=$2
      echo "name '${name}'"
      domain=${3:-localhost}
      echo "for domain '${domain}'"
      days=${4:-365}
      echo "lifetime '${days}' days"

      openssl req -new -nodes -newkey rsa:2048 \
        -keyout $outPath/${name}.key \
        -out $outPath/${name}.csr \
        -subj "/C=US/ST=YourState/L=YourCity/O=Example-Certificates/CN=${domain}"
      [ $? -eq 0 ]  || { echo "⛔ failed gen priv key for domain '${domain}'"; exit 1 ;}

      openssl x509 -req -sha256 \
        -days $days \
        -in $outPath/${name}.csr \
        -CA $caPath/$caPem \
        -CAkey $caPath/$caPriv \
        -CAcreateserial \
        -out $outPath/${name}.crt
      [ $? -eq 0 ]  || { echo "⛔ failed gen cert for domain '${domain}'"; exit 1 ;}

      openssl x509 -in $outPath/${name}.crt -noout -fingerprint -sha1 > $outPath/${name}.crt.sha1
      [ $? -eq 0 ]  || { echo "⛔ failed to gen fingerprint cert '${domain}'"; exit 1 ;}

      echo "👌  done."
    ;;
    * | "--help" )
        echo "Command '$@' not found"
        echo "List commands:"
        echo "➡️  [C]A generation."
        echo "➡️  [F]ingerprint for domain."
        echo "    {1} - domain"
        echo "➡️  For [d]omain generation public and private certs."
        echo "    {1} - file name"
        echo "    {2} - domain name (default localhost)"
        echo "    {3} - days (default 365)"
    ;;
esac
