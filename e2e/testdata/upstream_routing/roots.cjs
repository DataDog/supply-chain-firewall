// Read Node's public roots; the harness adds only its ephemeral proxy root.
process.stdout.write(require('tls').rootCertificates.join('\n') + '\n');
