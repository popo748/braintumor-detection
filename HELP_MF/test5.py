import cv2
import tensorflow as tf
import numpy as np
from PIL import Image
import argparse

def load_model(model_path):
    model = tf.keras.models.load_model(model_path)
    return model

def img_pred(model, image_path):
    img = Image.open(image_path)
    opencvImage = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    img = cv2.resize(opencvImage,(150,150))
    img = img.reshape(1,150,150,3)
    p = model.predict(img)
    p = np.argmax(p,axis=1)[0]

    if p==0:
        p='Glioma Tumor'
    elif p==1:
        p='Meningioma Tumor'

    elif p==2:
        p='Pituitary Tumor'
    else:
        print('The model predicts that there is no tumor')

    if p!=1:
        print(f'The Model predicts that it is a {p}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Brain MRI Image Prediction')
    parser.add_argument('--model_path', type=str, required=True, help='Path to the trained model .h5 file')
    parser.add_argument('--image_path', type=str, required=True, help='Path to the brain MRI image')

    args = parser.parse_args()

    model = load_model(args.model_path)
    img_pred(model, args.image_path)


