#!/usr/bin/python3

import cv2
import numpy as np
import pytesseract
import sys
import optparse


def usage ():
    scriptname = sys.argv[0]
    print ("Usage :" + scriptname + "-f filename.jpg")
    sys.exit()

# get grayscale image
def get_grayscale(image):
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

# noise removal
def remove_noise(image):
    return cv2.medianBlur(image,5)

#thresholding
def thresholding(image):
    return cv2.threshold(image, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]

#dilation
def dilate(image):
    kernel = np.ones((5,5),np.uint8)
    return cv2.dilate(image, kernel, iterations = 1)

#erosion
def erode(image):
    kernel = np.ones((5,5),np.uint8)
    return cv2.erode(image, kernel, iterations = 1)

#opening - erosion followed by dilation
def opening(image):
    kernel = np.ones((5,5),np.uint8)
    return cv2.morphologyEx(image, cv2.MORPH_OPEN, kernel)

#canny edge detection
def canny(image):
    return cv2.Canny(image, 100, 200)

#skew correction
def deskew(image):
    coords = np.column_stack(np.where(image > 0))
    angle = cv2.minAreaRect(coords)[-1]
    if angle < -45:
        angle = -(90 + angle)
    else:
        angle = -angle
    (h, w) = image.shape[:2]
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(image, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    return rotated

#template matching
def match_template(image, template):
    return cv2.matchTemplate(image, template, cv2.TM_CCOEFF_NORMED)

scriptname = sys.argv[0]
parser = optparse.OptionParser('Example: '+scriptname+' -f <file> -o <external_file>')
parser.add_option('-f', dest='image_file', type='string', help='specify input image file')
parser.add_option('-o', dest='output_file', type='string', help='specify output file')
(options, args) = parser.parse_args()
image_file = options.image_file
output_file = options.output_file

if image_file == None:
    print (parser.usage)
    exit(0)
else:
    #image = cv2.imread('IMG_20220417_113115.jpg')
    image = cv2.imread(image_file)
    gray = get_grayscale(image)
    thresh = thresholding(gray)
    opening = opening(gray)
    canny = canny(gray)
    # Adding custom options
    custom_config = r'--oem 3 --psm 6'
    processed_data = pytesseract.image_to_string(image, config=custom_config)
    #print (processed_data)
    with open(output_file, "w") as external_file:
        add_text = processed_data
        print(add_text, file=external_file)
        external_file.close()
