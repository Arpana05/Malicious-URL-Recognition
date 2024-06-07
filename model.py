#!/usr/bin/env python
# coding: utf-8

# In[59]:


# Libraries
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

import tensorflow as tf
from tensorflow import keras


# In[60]:


# Load the Dataset
df = pd.read_csv('data.csv')
df.head()


# In[61]:


features = df.columns
print(features)


# In[62]:


df.describe()


# In[63]:


df['type'].value_counts()


# In[64]:


plt.figure(figsize= (10 , 5))
plt.title('Distribution of Types of Attacks')
sns.countplot(x = 'type', data = df)
# ax.bar_label(ax.containers[0])
plt.xlabel('Attacks')
plt.savefig("output/Distribution_of_Types_of_Attacks.png")


# In[65]:


df_malicious = df[df['type'] == 'malicious']
df_benign = df[df['type'] == 'benign']


# In[66]:


from urllib.parse import urlparse
import re

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:      
        return 1
    else:
       
        return 0


df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))


# In[67]:


df['abnormal_url'].value_counts()


# In[68]:


from googlesearch import search
def google_index(url):
    
    site = search(url, 5)
    return 1 if site else 0

df['google_index'] = df['url'].apply(lambda i: google_index(i))
print(df['url'][0])
for j in search(df['url'][0], num_results=10):
    print(j)


# In[69]:


df['google_index'].value_counts()


# In[70]:


def count_dot(url):
    count_dot = url.count('.')
    return count_dot

df['count.'] = df['url'].apply(lambda i: count_dot(i))
df['count.'].value_counts()


# In[90]:


plt.figure(figsize = (10, 10))
sns.set(style="darkgrid")
ax = sns.countplot(y="count.", data=df)
plt.ylabel('No. of Dots in URL')
plt.title("No. Of Dots Available in URLs");


# In[91]:


def count_www(url):
    url.count('www')
    return url.count('www')

df['count-www'] = df['url'].apply(lambda i: count_www(i))
df['count-www'].value_counts()


# In[92]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="count-www", data=df)
plt.ylabel('Count of WWW in URL')
plt.title("No. Of WWW Available in URLs ");


# In[93]:


def count_atrate(url):
     
    return url.count('@')

df['count@'] = df['url'].apply(lambda i: count_atrate(i))
df['count@'].value_counts()


# In[94]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="count@", data=df)
plt.xlabel('Count of @ in URL')
plt.title("No. Of @ Available in URLs");


# In[95]:


def no_of_dir(url):
    urldir = urlparse(url).path
#     print(urldir)
    return urldir.count('/')

df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
print(df['url'][5])
no_of_dir(df['url'][5])


# In[96]:


df['count_dir'].value_counts()


# In[97]:


def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

df['count_embed_domain'] = df['url'].apply(lambda i: no_of_embed(i))
def no_of_embed(url):
    urldir = urlparse(url).path
    
    print(urldir)
    return urldir.count('//')

print(df['url'][7])
no_of_embed(df['url'][7])


# In[98]:


df['count_embed_domain'].value_counts()


# In[99]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="count_embed_domain", data=df)
plt.xlabel('Count of embedded domain in URL')
plt.title("No. Of embedded domain Available in URLs ");


# In[100]:


def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0
    
df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
df['sus_url'].value_counts()


# In[101]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="sus_url", data=df)
plt.xlabel('Count of Suspicious Words in URL')
plt.title("No. Of Suspicious Words  Available in URLS ");


# In[102]:


sns.set(style="darkgrid")
ax = sns.countplot(y="type", data=df,hue="sus_url")


# In[103]:


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
    if match:
        return 1
    else:
        return 0
    
    
df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
df['short_url'].value_counts()


# In[104]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="short_url", data=df)
plt.xlabel('Short URL')
plt.title("Identify whether the URL uses URL shortening services");


# In[105]:


df[df['type'] == 'benign']['short_url'].value_counts()


# In[106]:


df[df['type'] == 'malicious']['short_url'].value_counts()


# In[107]:


def count_https(url):
    return url.count('https')

df['count_https'] = df['url'].apply(lambda i : count_https(i))
df['count_https'].value_counts()


# In[108]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="count_https", data=df)
plt.xlabel('Count of Https in URL')
plt.title("Identify the no. of Https in URLs");


# In[109]:


df[df['type'] == 'benign']['count_https'].value_counts()


# In[110]:


df[df['type'] == 'malicious']['count_https'].value_counts()


# In[111]:


def count_http(url):
    return url.count('http')

df['count_http'] = df['url'].apply(lambda i : count_http(i))
df['count_http'].value_counts()


# In[113]:


plt.figure(figsize = (8 , 4))
sns.set(style="darkgrid")
ax = sns.countplot(x="count_http", data=df)
plt.xlabel('Count of Http in URL')
plt.title("Identify the no. of Http in URLs");


# In[114]:


df[df['type'] == 'benign']['count_http'].value_counts()


# In[115]:


df[df['type'] == 'malicious']['count_http'].value_counts()


# In[116]:


def count_per(url):
    return url.count('%')

df['count%'] = df['url'].apply(lambda i : count_per(i))
df['count%'].value_counts()


# In[117]:


def count_ques(url):
    return url.count('?')

df['count?'] = df['url'].apply(lambda i: count_ques(i))
df['count?'].value_counts()


# In[118]:


def count_hyphen(url):
    return url.count('-')

df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
df['count-'].value_counts()


# In[119]:


def count_equal(url):
    return url.count('=')

df['count='] = df['url'].apply(lambda i: count_equal(i))
df['count='].value_counts()


# In[120]:


def url_length(url):
    return len(str(url))

df['url_length'] = df['url'].apply(lambda i: url_length(i))
df['url_length'].value_counts()


# In[121]:


def hostname_length(url):
    return len(urlparse(url).netloc)

df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
df['hostname_length'].value_counts()


# In[122]:


from tld import get_tld
import os.path

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
df['fd_length'].value_counts()


# In[123]:


#Length of Top Level Domain
df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))


def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
df['tld']


# In[124]:


df['tld'].value_counts()


# In[125]:


df['tld_length'].value_counts()


# In[126]:


df.drop(["tld"], axis = 1, inplace = True)


# In[127]:


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits += 1
    return digits


df['count_digits']= df['url'].apply(lambda i: digit_count(i))
df['count_digits'].value_counts()


# In[128]:


df['count_digits'].describe()


# In[129]:


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters += 1
    return letters


df['count_letters']= df['url'].apply(lambda i: letter_count(i))
df['count_letters'].value_counts()


# In[130]:


df['count_letters'].describe()


# In[131]:


df.head()


# In[132]:


df.to_csv("preprocessed_data.csv")


# In[133]:


from sklearn.preprocessing import LabelEncoder

label_encoder = LabelEncoder()

df['type_code'] = label_encoder.fit_transform(df['type'])
df['type_code'].value_counts()


# In[134]:


df.columns


# In[135]:


X = df[['abnormal_url', 'count.', 'count-www', 'count@',
       'count_dir', 'count_embed_domain', 'short_url', 'count%', 'count?', 'count-', 'count=', 'url_length', 'count_https',
       'count_http', 'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count_digits',
       'count_letters']]
Y = df['type_code']
X.shape
(651191, 21)
Y.shape


# In[140]:


from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd

# Assuming your main function for feature extraction is defined somewhere in your script
def main(url):
    # Replace the feature extraction logic with your actual code
    status = []
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    status.append(tld_length(tld))
    
    return status

df['features'] = df['url'].apply(main)

# Separate features and labels
X = np.vstack(df['features'].to_numpy())
Y = df['type_code']

# Split the data into training and testing sets
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, shuffle=True, random_state=42)

# Create a StandardScaler instance
scaler = StandardScaler()

# Fit the scaler on the training data and transform both training and test data
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Create and train the Random Forest classifier
clf = RandomForestClassifier(class_weight='balanced')
clf.fit(X_train_scaled, Y_train)

# Print the shapes of training and testing data
print("Training data shape:", X_train_scaled.shape, Y_train.shape)
print("Testing data shape:", X_test_scaled.shape, Y_test.shape)


# In[180]:


clf = RandomForestClassifier(class_weight='balanced')
clf.fit(X_train, Y_train)


X_train.shape , Y_train.shape
((355220, 20), (355220,))
X_test.shape , Y_test.shape
((88805, 20), (88805,))
X_train


# In[181]:


X.shape


# In[182]:


#Y_train.values


# In[183]:


Y.shape


# In[184]:


from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
print(scaler.fit(X))
X = scaler.transform(X)


# In[151]:


from sklearn.metrics import accuracy_score , precision_recall_fscore_support, classification_report

def result(y_pred , y_test):
    accuracy = accuracy_score(y_test, y_pred) * 100
#     print(accuracy)
    
    precision , recall, f1_score, support = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    
    res = {
        "Accuracy": accuracy,
        "Precision" : precision,
        "Recall" : recall,
        "F1-Score" : f1_score,
        "Support" : support
    }
    
    print(classification_report(y_test, y_pred ,target_names=['malicious','benign']))
    
    
    
    return res


# In[152]:


from sklearn.metrics import confusion_matrix

def create_confusion_metric(y_pred , y_test):
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm,
                     index = ['malicious', 'benign'], 
                     columns = ['malicious', 'benign'])
    
    plt.figure(figsize=(8,6))
    sns.heatmap(cm_df, annot=True,fmt=".1f")
    plt.title('Confusion Matrix')
    plt.ylabel('Actal Values')
    plt.xlabel('Predicted Values')
    
    plt.show()


# In[153]:


from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, roc_curve
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns
from termcolor import colored
# print(colored('Hello', 'red', attrs=['bold']))


# Define classification models
models = {
    "Random Forest": RandomForestClassifier(),
    "XGBoost": XGBClassifier(),
}


# In[154]:


# Train and evaluate each model
for model_name, model in models.items():
    print(colored(f"Training {model_name}...", 'red', attrs=['bold']))
#     print(f"Training {model_name}...")
    
    # Fit model to training data
    model.fit(X_train, Y_train)
    
    # Make predictions on training and testing data
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    
    # Calculate performance metrics for Train Data
    train_accuracy = accuracy_score(Y_train, y_train_pred)
    train_precision = precision_score(Y_train, y_train_pred, average='weighted')
    train_recall = recall_score(Y_train, y_train_pred, average='weighted')
    train_f1 = f1_score(Y_train, y_train_pred, average='weighted')
#     train_roc_auc = roc_auc_score(Y_train, model.predict_proba(X_train), multi_class='ovr')
    
    
    # Calculate performance metrics for Test Data
    accuracy = accuracy_score(Y_test, y_test_pred)
    precision = precision_score(Y_test, y_test_pred, average='weighted')
    recall = recall_score(Y_test, y_test_pred, average='weighted')
    f1 = f1_score(Y_test, y_test_pred, average='weighted')
#     test_roc_auc = roc_auc_score(Y_test, model.predict_proba(X_test), multi_class='ovr')
    
    # Generate confusion matrix
    cm = confusion_matrix(Y_test, y_test_pred)
    plt.figure(figsize=(8,6))
#     sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', cbar=False)
    sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', cbar=False)
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    plt.title(f'Confusion Matrix - {model_name}')
    plt.show()
    
    # Generate ROC-AUC curve
#     fpr, tpr, thresholds = roc_curve(Y_test, model.predict_proba(X_test), multi_class='ovr')
#     plt.figure(figsize=(8,6))
#     plt.plot(fpr, tpr, label=f'ROC-AUC Curve (Area = {roc_auc:.2f})')
#     plt.plot([0, 1], [0, 1], linestyle='--')
#     plt.xlabel('False Positive Rate')
#     plt.ylabel('True Positive Rate')
#     plt.title(f'ROC-AUC Curve - {model_name}')
#     plt.legend()
#     plt.show()
    print(""*5)
    # Print results Train Data
#     print(f"{model_name} classifier: Training Results")
    print(colored(f"{model_name} classifier: Training Results", 'green', attrs=['bold']))
    print("Training accuracy:", train_accuracy)
    print("Training precision:", train_precision)
    print("Training recall:", train_recall)
    print("Training F1 score:", train_f1)
    print("="*50)
    print(""*5)
    
    # Print results Test Data
#     print(f"{model_name} classifier: Testing Results")
    print(colored(f"{model_name} classifier: Testing Results", 'green', attrs=['bold']))
    print(f"Testing accuracy: {accuracy:.10f}")
    print(f"Testing Precision: {precision:.10f}")
    print(f"Testing Recall: {recall:.10f}")
    print(f"Testing F1 score: {f1:.10f}")
    print("="*50)
    print(""*5)


# In[155]:


# Random Forest
rf_param_grid = {
    'n_estimators': [100, 200, 300, 400, 500],
    'max_depth': [None, 5, 10, 15],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'max_features': [None, 'sqrt', 'log2']
}


# XGBoost
xgb_param_grid = {
    'learning_rate': [0.01, 0.1, 1],
    'n_estimators': [100, 200, 500],
    'max_depth': [3, 5, 10],
    'min_child_weight': [1, 3, 5],
    'subsample': [0.5, 0.8, 1.0],
    'colsample_bytree': [0.5, 0.8, 1.0]
}


# In[156]:


param_grid = {
    "Random Forest": rf_param_grid,
    "XGBoost": xgb_param_grid,
}


# In[157]:


# Set up the hyperparameters to be tuned for each model
param_grid = {
    "Random Forest": {
        "n_estimators": [100, 200, 300],
        "max_depth": [None, 5, 10]
    },

    "XGBoost": {
        "n_estimators": [100, 200, 300],
        "max_depth": [None, 5, 10],
        "learning_rate": [0.01, 0.1, 0.5]
    }
}


# In[158]:


from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import accuracy_score, make_scorer



# Set up the cross-validation method
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Set up the scoring metric
scoring_metric = make_scorer(accuracy_score)



# Perform the grid search for each model and print the best hyperparameters
for model_name, model in models.items():
    
    print(colored(f"Tuning hyperparameters for {model_name}...", 'red', attrs=['bold']))
    
    clf = GridSearchCV(model, param_grid[model_name], scoring=scoring_metric, cv=cv)
    
    clf.fit(X_train, Y_train)
    
    print(f"Best hyperparameters: {clf.best_params_}")
    print(f"Training accuracy: {clf.best_score_}")
    print(f"Validation accuracy: {accuracy_score(Y_test, clf.predict(X_test))}")
    
    y_train_pred = clf.predict(X_train)
    y_test_pred = clf.predict(X_test)
    
    # Calculate performance metrics for Train Data
    train_accuracy = accuracy_score(Y_train, y_train_pred)
    train_precision = precision_score(Y_train, y_train_pred, average='weighted')
    train_recall = recall_score(Y_train, y_train_pred, average='weighted')
    train_f1 = f1_score(Y_train, y_train_pred, average='weighted')
#     train_roc_auc = roc_auc_score(Y_train, model.predict_proba(X_train), multi_class='ovr')
    
    
    # Calculate performance metrics for Test Data
    accuracy = accuracy_score(Y_test, y_test_pred)
    precision = precision_score(Y_test, y_test_pred, average='weighted')
    recall = recall_score(Y_test, y_test_pred, average='weighted')
    f1 = f1_score(Y_test, y_test_pred, average='weighted')
#     test_roc_auc = roc_auc_score(Y_test, model.predict_proba(X_test), multi_class='ovr')
    
    # Generate confusion matrix
    cm = confusion_matrix(Y_test, y_test_pred)
    plt.figure(figsize=(8,6))
#     sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', cbar=False)
    sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', cbar=False)
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    plt.title(f'Confusion Matrix - {model_name}')
    plt.show()
    

    print(""*5)


# In[174]:


import pickle
import numpy as np

# Assume you have the main function defined as before
def main(url):
    status = []
    
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)
      
    status.append(tld_length(tld))
    
    return status

scaler = StandardScaler()

# Fit the scaler on the training data and transform both training and test data
X_train_scaled = scaler.fit_transform(X_train)

# Create and train the RandomForestClassifier
clf = RandomForestClassifier(class_weight='balanced')
clf.fit(X_train_scaled, Y_train)

# Save the trained model using pickle
with open('model.pkl', 'wb') as model_file:
    pickle.dump(clf, model_file)
    
# Load the trained model
loaded_model = pickle.load(open('model.pkl', 'rb'))

# Assume you have a function to preprocess the input for prediction
def preprocess_input(url):
    features = main(url)
    return np.array(features).reshape((1, -1))

# Function to get predictions using the loaded model
def get_prediction_from_url(model, test_url):
    features_test = preprocess_input(test_url)
    pred = model.predict(features_test)
    if int(pred[0]) == 0:
        return "MALICIOUS"
    elif int(pred[0]) == 1:
        return "BENIGN"


# In[186]:


# Example usage with debugging prints
urls = ['http://cmmtoronto.com/en/pastors/pastor-aristides-falcao', 'br-icloud.com.br']
for url in urls:
    # Preprocess the input
    features_test = preprocess_input(url)
    
    # Get raw prediction values
    #raw_predictions = loaded_model.predict_proba(features_test)
    #print(f"Raw predictions for {url}: {raw_predictions}")
    
    # Get the final prediction
    result = get_prediction_from_url(loaded_model, url)
    print(f"Prediction for {url}: {result}")


# In[188]:


print("X_train_scaled shape:", X_train_scaled.shape)
print("Y_train shape:", Y_train.shape)
print("X_test_scaled shape:", X_test_scaled.shape)
print("Y_test shape:", Y_test.shape)


##### In[187]:


# Assuming you have a trained RandomForestClassifier named 'clf'
feature_importance = clf.feature_importances_

# Create a DataFrame to display feature names and their importance scores
feature_importance_df = pd.DataFrame({'Feature': df.columns[:-1], 'Importance': feature_importance})

# Sort the DataFrame by importance scores in descending order
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)

# Display the top features
print(feature_importance_df.head())


# In[163]:


clf = RandomForestClassifier()
clf.fit(X_train.values, Y_train.values)


# In[164]:


import pickle
pickle.dump(clf, open('model.pkl', 'wb'))


# In[ ]:




