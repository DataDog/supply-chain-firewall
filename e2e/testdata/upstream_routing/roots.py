import pathlib
import ssl
import sys

# Read public roots; standalone Python builds may have no compiled-in CA path.
certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
if certificates:
    print("Trust source: pinned runtime SSL context", file=sys.stderr)
    for certificate in certificates:
        print(ssl.DER_cert_to_PEM_cert(certificate))
else:
    for path in ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"):
        source = pathlib.Path(path)
        if source.is_file():
            print("Trust source: " + path, file=sys.stderr)
            print(source.read_text())
            break
