curl -v -k --request POST 'https://172.16.77.226/v1/ota/speaker/activate' \
--header 'Authorization: Basic c3BlYWtlcjpsb3Vkc3BlYWtlcg==' \
--header 'Content-Type: application/json' \
--data-raw '{
"binaryName": "ota_09.12.2020",
"speakerSwVersion": "3.3.3"
}'
