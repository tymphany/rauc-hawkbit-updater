curl -v --cacert 3rdparty_infra_cert_chain.pem --cert client.crt --key client.key  https://device.ota-spk.goriv.co/v1/campaigns/speaker/deployment -H "ota-current-version:1.0.0"
