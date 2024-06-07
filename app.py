import streamlit as st
import pandas as pd
import numpy as np
import pickle
from urllib.parse import urlparse
import re
from googlesearch import search
from tld import get_tld

# Load the pre-trained model
model = pickle.load(open('model.pkl', 'rb'))

# Function for feature extraction
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

def count_dot(url):
    count_dot = url.count('.')
    return count_dot

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    return 1 if match else 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits += 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters += 1
    return letters

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1


# Feature extraction
def main(url):
    
    status = []
    
    status.append(float(abnormal_url(url)))
    status.append(float(count_dot(url)))
    status.append(float(count_www(url)))
    status.append(float((count_atrate(url))))
    status.append(float(no_of_dir(url)))
    status.append(float(no_of_embed(url)))
    
    status.append(float(shortening_service(url)))
    status.append(float(count_https(url)))
    status.append(float(count_http(url)))
    
    status.append(float(count_per(url)))
   
    status.append(float(count_ques(url)))
    status.append(float(count_hyphen(url)))
    status.append(float(count_equal(url)))

    status.append(float(url_length(url)))
    status.append(float(hostname_length(url)))
    status.append(float(suspicious_words(url)))
    status.append(float(digit_count(url)))
    status.append(float(letter_count(url)))
    status.append(float(fd_length(url)))
    tld = get_tld(url,fail_silently=True)
      
    status.append(float(tld_length(tld)))
    

    return status

    # Convert string features to numerical format
    for i in range(len(status)):
        try:
            status[i] = int(status[i])
        except ValueError:
            # Handle the case where a feature extraction function returns a string
            status[i] = 0  

    return status


# Predict function
def get_prediction_from_url(test_url):
    features_test = main(test_url)
    features_test = np.array(features_test).reshape((1, -1))
    pred = model.predict(features_test)
    
    if pred[0] == 0:
        res = "BENIGN"
        return res
    elif pred[0] == 1:
        res = "MALICIOUS"
        return res


# Streamlit app
st.title("Malicious URL Recognition System")
st.markdown(
    "This simple web app predicts whether a given URL is malicious or benign."
)

# User input
user_input = st.text_input("Enter the URL:")


if st.button("Predict"):
    prediction = get_prediction_from_url(user_input)
    st.subheader("Prediction Result:")
    st.write(f"The URL is predicted as: **{prediction}**")

st.sidebar.title("Instructions")
st.sidebar.markdown(
    "1. Enter a URL in the text box.\n"
    "2. Click the 'Predict' button to see the model's prediction.\n"
)

