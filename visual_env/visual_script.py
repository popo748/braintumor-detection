import argparse
from inference_sdk import InferenceHTTPClient

def main(api_url, api_key, image_path, model_id):
    CLIENT = InferenceHTTPClient(
        api_url=api_url,
        api_key=api_key
    )
    result = CLIENT.infer(image_path, model_id=model_id)
    print(result)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Brain MRI Image Inference using API')
    parser.add_argument('--api_url', type=str, required=True, help='API URL for inference')
    parser.add_argument('--api_key', type=str, required=True, help='API key for inference')
    parser.add_argument('--image_path', type=str, required=True, help='Path to the brain MRI image')
    parser.add_argument('--model_id', type=str, required=True, help='Model ID for inference')

    args = parser.parse_args()
    main(args.api_url, args.api_key, args.image_path, args.model_id)
