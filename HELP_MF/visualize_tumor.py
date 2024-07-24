# visualize_tumor.py
import cv2
import numpy as np
from PIL import Image

def draw_tumor_circle(image_path, tumor_location, output_path):
    img = Image.open(image_path)
    opencv_image = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    
    x, y, radius = tumor_location
    cv2.circle(opencv_image, (x, y), radius, (0, 0, 255), 2)
    cv2.imwrite(output_path, cv2.cvtColor(opencv_image, cv2.COLOR_BGR2RGB))
    
    return output_path

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Visualize Brain Tumor on MRI Image')
    parser.add_argument('--image_path', type=str, required=True, help='Path to the brain MRI image')
    parser.add_argument('--tumor_location', type=str, required=True, help='Tumor location as x,y,radius')
    parser.add_argument('--output_path', type=str, required=True, help='Path to save the annotated image')
    
    args = parser.parse_args()
    x, y, radius = map(int, args.tumor_location.split(','))
    
    output_path = draw_tumor_circle(args.image_path, (x, y, radius), args.output_path)
    print(f"Tumor visualized and saved to: {output_path}")



