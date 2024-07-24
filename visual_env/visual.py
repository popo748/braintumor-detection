from inference_sdk import InferenceHTTPClient

# Initialize the client with the API URL and key
CLIENT = InferenceHTTPClient(
    api_url="https://detect.roboflow.com",
    api_key="BHKI2g8uI3d93Tw9S2Ic"
)

# Use the image file in the same directory
result = CLIENT.infer('image1.png', model_id="brain-tumor-scans/2")

# Print the result to see the output
print(result)