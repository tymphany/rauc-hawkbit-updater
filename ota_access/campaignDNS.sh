curl -v --request POST 'https://speaker-api.eota-vpn.goriv.co/v1/ota/speaker/activate' \
--header 'Authorization: Basic c3BlYWtlcjpsb3Vkc3BlYWtlcg==' \
--header 'Content-Type: application/json' \
--data-raw '{
"binaryName": "paragraph.txt",
"speakerSwVersion": "2.2.2"
}'
