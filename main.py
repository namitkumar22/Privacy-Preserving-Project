import streamlit as st
import pandas as pd
import numpy as np
import hashlib
import datetime
import time
import pickle
import os
import threading
import matplotlib.pyplot as plt
import requests
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Set page configuration
st.set_page_config(
    page_title="Privacy-Preserving Data Mining for Big Data",
    page_icon="❤️",
    layout="wide"
)

# Encryption key generation
def get_encryption_key():
    """Generate a consistent encryption key using a secret passphrase"""
    # Use a fixed passphrase that only you know - this should be kept secret
    passphrase = "5uP3r_s3cR3t_P@$$phR4s3_f0r_PPBDM_2025"
    # Use a fixed salt
    salt = b'PPBDM_salt_fixed_value_2025_'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key

# License encryption/decryption functions
def encrypt_license_data(license_data):
    """Encrypt license data before storing"""
    key = get_encryption_key()
    fernet = Fernet(key)
    license_json = json.dumps(license_data)
    encrypted_data = fernet.encrypt(license_json.encode())
    return encrypted_data

def decrypt_license_data(encrypted_data):
    """Decrypt license data after reading from file"""
    key = get_encryption_key()
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    license_data = json.loads(decrypted_data.decode())
    return license_data

# License verification system
def verify_license():
    """
    Verify the license status with a remote server or locally
    Returns True if license is valid, False otherwise
    """
    # Local expiration approach (using an encrypted file)
    license_file = "license_key.enc"
    
    try:
        if os.path.exists(license_file):
            with open(license_file, "rb") as f:
                encrypted_data = f.read()
                
            # Decrypt the license data
            try:
                license_data = decrypt_license_data(encrypted_data)
                
                # Check if license key is valid
                if "expiration_date" in license_data and "license_key" in license_data:
                    # Check if the license key is correct
                    expected_key = "9b156df7-a4c1-4f3b-8f1e-dc9fd5ba581c"  # You can change this to your secret key
                    if license_data["license_key"] != expected_key:
                        return False
                    
                    # Check if the license is expired
                    expiration_date = datetime.datetime.strptime(license_data["expiration_date"], "%Y-%m-%d %H:%M:%S")
                    if datetime.datetime.now() > expiration_date:
                        st.error("License has expired. Please contact the developer for renewal.")
                        return False
                    return True
            except Exception as e:
                # Failed to decrypt - tampered file
                st.error("License file appears to be corrupted or tampered with.")
                return False
        
        # If license file doesn't exist or has wrong format
        st.error("License verification failed. Please contact the developer.")
        return False
    
    except Exception as e:
        st.error(f"License verification error: {e}")
        return False

# Create or update license function
def create_or_update_license(key="9b156df7-a4c1-4f3b-8f1e-dc9fd5ba581c", minutes=30):
    """Helper function to create or update the license file"""
    expiration_date = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
    
    license_data = {
        "license_key": key,
        "expiration_date": expiration_date.strftime("%Y-%m-%d %H:%M:%S"),
        "client_name": "Your Client's Name",
        "issued_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checksum": hashlib.sha256(f"{key}{expiration_date.isoformat()}".encode()).hexdigest()
    }
    
    # Encrypt the license data
    encrypted_data = encrypt_license_data(license_data)
    
    # Save the encrypted data
    with open("license_key.enc", "wb") as f:
        f.write(encrypted_data)
    
    return license_data

# Check if license file exists, if not create one
if not os.path.exists("license_key.enc"):
    create_or_update_license(minutes=30)  # Default 30 minutes instead of 30 days

# Verify license before proceeding
if not verify_license():
    st.warning("This application requires a valid license to run.")
    
    # Show an informative message that only you would understand
    st.markdown("""
    ### License Verification Failed
    
    To obtain a valid license, please contact the developer with the following information:
    
    1. Project ID: PPBDM-2025
    2. Client ID: Your assigned client ID
    3. Verification code: (Check console output for code)
    
    If you believe this is an error, try restarting the application.
    """)
    
    # Secret code that only you would know how to use
    activation_code = st.text_input("Enter activation code (developer use only)", type="password")
    
    if activation_code == "enable-ppbdm-2025":  # Your secret activation code
        if st.button("Activate License"):
            # Create a new 30-min license
            license_data = create_or_update_license(minutes=30)
            expiry_time = datetime.datetime.strptime(license_data['expiration_date'], "%Y-%m-%d %H:%M:%S")
            st.success(f"License activated until {expiry_time.strftime('%Y-%m-%d %H:%M:%S')}")
            st.experimental_rerun()
    
    # Stop execution here if license is invalid
    st.stop()

# Initialize session state variables
if 'data' not in st.session_state:
    if os.path.exists('user_data.csv'):
        st.session_state.data = pd.read_csv('user_data.csv')
    else:
        # Create an empty DataFrame with the required columns
        columns = ['hashed_name', 'hashed_email', 'hashed_location', 'hashed_pincode', 
                   'age', 'gender', 'heart_rate', 'systolic_bp', 'diastolic_bp', 
                   'ck_mb', 'troponin', 'heart_attack_risk', 'timestamp']
        st.session_state.data = pd.DataFrame(columns=columns)

if 'last_trained' not in st.session_state:
    st.session_state.last_trained = datetime.datetime.now()

if 'model' not in st.session_state:
    if os.path.exists('heart_attack_model.pkl'):
        st.session_state.model = joblib.load('heart_attack_model.pkl')
    else:
        # Initialize with a basic model (will be trained once we have data)
        st.session_state.model = RandomForestClassifier(n_estimators=100, random_state=42)


# Function to hash sensitive information
def hash_data(data):
    """Hash sensitive data using SHA-256"""
    if pd.isna(data) or data == "":
        return ""
    return hashlib.sha256(str(data).encode()).hexdigest()


# Function to train the model
def train_model():
    """Train the heart attack prediction model using the current dataset"""
    if len(st.session_state.data) < 5:  # Need at least some samples to train
        return None
    
    # Use only relevant features for prediction
    features = ['age', 'gender_numeric', 'heart_rate', 'systolic_bp', 
                'diastolic_bp', 'ck_mb', 'troponin']
    
    # Create a numeric gender column for the model (temporary)
    data_copy = st.session_state.data.copy()
    data_copy['gender_numeric'] = data_copy['gender'].map({'Male': 1, 'Female': 0})
    
    X = data_copy[features]
    y = data_copy['heart_attack_risk']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Model trained. Accuracy: {accuracy:.4f}")
    
    return model


# Function to periodically retrain the model (every 2 hours)
def scheduled_model_training():
    """Background task to retrain the model every 2 hours"""
    while True:
        current_time = datetime.datetime.now()
        if (current_time - st.session_state.last_trained).total_seconds() >= 7200:  # 2 hours = 7200 seconds
            print("Retraining model...")
            new_model = train_model()
            if new_model is not None:
                st.session_state.model = new_model
                joblib.dump(new_model, 'heart_attack_model.pkl')
                st.session_state.last_trained = current_time
                st.session_state.data.to_csv('user_data.csv', index=False)
                print("Model retrained and saved.")
        time.sleep(60)  # Check every minute


# Function to predict heart attack risk
def predict_heart_attack_risk(age, gender, heart_rate, systolic_bp, diastolic_bp, ck_mb, troponin):
    """Predict heart attack risk based on input features"""
    # Convert gender to numeric
    gender_numeric = 1 if gender == 'Male' else 0
    
    # Create feature array
    features = np.array([[age, gender_numeric, heart_rate, systolic_bp, diastolic_bp, ck_mb, troponin]])
    
    # If we have no model or insufficient data, use a simple rule-based system
    if 'model' not in st.session_state or len(st.session_state.data) < 5:
        # Simple rule-based risk assessment
        risk_score = 0
        # Age risk
        if age > 60:
            risk_score += 3
        elif age > 45:
            risk_score += 2
        
        # Blood Pressure risk
        if systolic_bp > 180 or diastolic_bp > 120:
            risk_score += 3
        elif systolic_bp > 140 or diastolic_bp > 90:
            risk_score += 2
        
        # Heart Rate risk
        if heart_rate > 100:
            risk_score += 1
            
        # Cardiac markers
        if ck_mb > 6.3:  # Elevated CK-MB
            risk_score += 3
        if troponin > 0.4:  # Elevated troponin
            risk_score += 4
            
        # Determine risk category
        return 1 if risk_score >= 6 else 0
    else:
        # Use the trained model for prediction
        prediction = st.session_state.model.predict(features)[0]
        return prediction


# Start the background model training thread
training_thread = threading.Thread(target=scheduled_model_training, daemon=True)
training_thread.start()

# App UI
st.title("Privacy-Preserving Heart Attack Risk Prediction")
st.subheader("Data Mining for Big Data")

# Add a version number (useful for later updates)
version = "1.1.0"
st.markdown(f"<p style='text-align: right; color: gray; font-size: 0.8em;'>Version {version}</p>", unsafe_allow_html=True)

st.markdown("""
This application predicts heart attack risk based on health data while preserving user privacy.
Personal identifiers are securely hashed before storage using SHA-256.
""")

# Create two columns layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Enter Your Information")
    
    # Personal Information (to be hashed)
    st.markdown("#### Personal Information (will be hashed for privacy)")
    name = st.text_input("Full Name")
    email = st.text_input("Email Address")
    location = st.text_input("Country")
    pincode = st.text_input("PIN/ZIP Code")
    
    # Health Information (used for prediction)
    st.markdown("#### Health Information")
    age = st.number_input("Age", min_value=18, max_value=120, value=40)
    gender = st.selectbox("Gender", ["Male", "Female"])
    
    # Vital Signs
    st.markdown("#### Vital Signs")
    heart_rate = st.number_input("Heart Rate (bpm)", min_value=40, max_value=250, value=80)
    col_bp1, col_bp2 = st.columns(2)
    with col_bp1:
        systolic_bp = st.number_input("Systolic BP (mmHg)", min_value=70, max_value=250, value=120)
    with col_bp2:
        diastolic_bp = st.number_input("Diastolic BP (mmHg)", min_value=40, max_value=150, value=80)
    
    # Cardiac Markers
    st.markdown("#### Cardiac Markers")
    ck_mb = st.number_input("CK-MB (ng/mL)", min_value=0.0, max_value=100.0, value=3.0, step=0.1)
    troponin = st.number_input("Troponin (ng/mL)", min_value=0.0, max_value=50.0, value=0.01, step=0.01)
    
    predict_button = st.button("Predict Heart Attack Risk")

with col2:
    # Display the current model status
    st.subheader("Model Status")
    model_age = datetime.datetime.now() - st.session_state.last_trained
    st.write(f"Last model training: {model_age.seconds // 60} minutes ago")
    st.write(f"Total data points: {len(st.session_state.data)}")
    
    if len(st.session_state.data) > 0:
        # Show the percentage of positive cases
        positive_percentage = st.session_state.data['heart_attack_risk'].mean() * 100
        st.write(f"Positive cases: {positive_percentage:.1f}%")
        
        # Display a gauge chart for the latest prediction
        st.subheader("Latest Prediction")
        if predict_button:
            prediction = predict_heart_attack_risk(age, gender, heart_rate, systolic_bp, diastolic_bp, ck_mb, troponin)
            if prediction == 1:
                st.error("⚠️ High Risk of Heart Attack")
            else:
                st.success("✅ Low Risk of Heart Attack")

# Processing the prediction
if predict_button:
    # Validate input data
    if not name or not email or not location or not pincode:
        st.warning("Please fill in all the personal information fields")
    else:
        # Hash sensitive information
        hashed_name = hash_data(name)
        hashed_email = hash_data(email)
        hashed_location = hash_data(location)
        hashed_pincode = hash_data(pincode)
        
        # Make prediction
        prediction = predict_heart_attack_risk(age, gender, heart_rate, systolic_bp, diastolic_bp, ck_mb, troponin)
        
        # Add to the dataset
        new_data = pd.DataFrame({
            'hashed_name': [hashed_name],
            'hashed_email': [hashed_email],
            'hashed_location': [hashed_location],
            'hashed_pincode': [hashed_pincode],
            'age': [age],
            'gender': [gender],
            'heart_rate': [heart_rate],
            'systolic_bp': [systolic_bp],
            'diastolic_bp': [diastolic_bp],
            'ck_mb': [ck_mb],
            'troponin': [troponin],
            'heart_attack_risk': [prediction],
            'timestamp': [datetime.datetime.now()]
        })
        
        st.session_state.data = pd.concat([st.session_state.data, new_data], ignore_index=True)
        
        # Save the updated dataset
        st.session_state.data.to_csv('user_data.csv', index=False)
        
        # Display prediction result
        st.subheader("Prediction Result")
        if prediction == 1:
            st.error("⚠️ High Risk of Heart Attack")
            st.markdown("""
            **Recommendation:** Please consult a healthcare professional immediately.
            This is not a medical diagnosis, but based on the provided information, 
            the model indicates an elevated risk of heart attack.
            """)
        else:
            st.success("✅ Low Risk of Heart Attack")
            st.markdown("""
            **Note:** This is not a medical diagnosis. Regular health check-ups are still recommended.
            The model predicts a lower risk based on the provided information.
            """)

# Visualizations
st.header("Insights and Trends")

if len(st.session_state.data) > 1:
    # Create tabs for different visualizations
    tab1, tab2, tab3 = st.tabs(["Risk Trends", "Age Distribution", "Health Metrics"])
    
    with tab1:
        st.subheader("Heart Attack Risk Trend Over Time")
        # Calculate moving average of risk to show trend
        df_viz = st.session_state.data.copy()
        df_viz['timestamp'] = pd.to_datetime(df_viz['timestamp'])
        df_viz = df_viz.sort_values('timestamp')
        df_viz['risk_moving_avg'] = df_viz['heart_attack_risk'].rolling(window=max(3, len(df_viz)//10)).mean()
        
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(range(len(df_viz)), df_viz['risk_moving_avg'], marker='o', linestyle='-', color='#FF5555')
        ax.set_xlabel('Number of Users')
        ax.set_ylabel('Heart Attack Risk (Moving Average)')
        ax.set_ylim([0, 1])
        ax.grid(True, linestyle='--', alpha=0.7)
        st.pyplot(fig)
        
        # Show total number of assessments over time
        st.subheader("Cumulative Assessments Over Time")
        df_viz['cumulative_count'] = range(1, len(df_viz) + 1)
        fig2, ax2 = plt.subplots(figsize=(10, 4))
        ax2.plot(df_viz['timestamp'], df_viz['cumulative_count'], marker='', linestyle='-', color='#5555FF')
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Total Assessments')
        ax2.grid(True, linestyle='--', alpha=0.7)
        st.pyplot(fig2)
    
    with tab2:
        st.subheader("Age Distribution and Risk")
        # Create age groups
        df_viz['age_group'] = pd.cut(df_viz['age'], bins=[0, 30, 40, 50, 60, 120], 
                                    labels=['<30', '30-40', '40-50', '50-60', '>60'])
        
        # Calculate risk percentage by age group
        age_risk = df_viz.groupby('age_group')['heart_attack_risk'].mean().reset_index()
        
        fig3, ax3 = plt.subplots(figsize=(10, 4))
        bars = ax3.bar(age_risk['age_group'], age_risk['heart_attack_risk'] * 100, color='#55AAFF')
        ax3.set_xlabel('Age Group')
        ax3.set_ylabel('Heart Attack Risk (%)')
        ax3.set_ylim([0, 100])
        
        # Add data labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f}%', ha='center', va='bottom')
        
        st.pyplot(fig3)
    
    with tab3:
        st.subheader("Health Metrics Analysis")
        
        # Create scatterplot of key metrics
        fig4, ax4 = plt.subplots(figsize=(10, 6))
        
        # Color points by risk
        colors = ['#55AA55', '#FF5555']
        for risk in [0, 1]:
            mask = df_viz['heart_attack_risk'] == risk
            ax4.scatter(df_viz.loc[mask, 'systolic_bp'], 
                       df_viz.loc[mask, 'heart_rate'],
                       c=colors[risk], 
                       label=f'{"High" if risk==1 else "Low"} Risk',
                       alpha=0.7)
        
        ax4.set_xlabel('Systolic Blood Pressure (mmHg)')
        ax4.set_ylabel('Heart Rate (bpm)')
        ax4.legend()
        ax4.grid(True, linestyle='--', alpha=0.7)
        st.pyplot(fig4)

else:
    st.info("Visualizations will appear once more data is collected.")

# Privacy information
st.sidebar.title("Privacy Information")
st.sidebar.info("""
### Privacy-Preserving Features

- Personal identifiers (name, email, location, PIN) are hashed using SHA-256
- Only anonymized data is stored
- The model is trained locally
- No data is sent to external servers
- Regular model retraining ensures accuracy with new data

This application demonstrates privacy-preserving techniques in data mining.
""")

st.sidebar.markdown("---")
st.sidebar.subheader("About")
st.sidebar.write("""
This application was created for a project on 
"Privacy-Preserving Data Mining for Big Data".

It demonstrates the use of privacy-enhancing technologies
while delivering valuable health insights.
""")

# Add a note about the demo nature of the app
st.sidebar.warning("""
**Note:** This is a demonstration application and 
should not be used for actual medical diagnosis.
Always consult healthcare professionals for medical advice.
""")

# Display the last model training time in the sidebar
st.sidebar.markdown("---")
st.sidebar.subheader("System Status")
st.sidebar.write(f"Last model training: {st.session_state.last_trained.strftime('%Y-%m-%d %H:%M:%S')}")
st.sidebar.write(f"Next scheduled training: {(st.session_state.last_trained + datetime.timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')}")

# Add license information in sidebar
with st.sidebar.expander("License Information"):
    try:
        if os.path.exists("license_key.enc"):
            with open("license_key.enc", "rb") as f:
                encrypted_data = f.read()
            
            # Decrypt the license data
            try:
                license_data = decrypt_license_data(encrypted_data)
                
                st.write(f"Client: {license_data['client_name']}")
                st.write(f"Issued: {license_data['issued_date']}")
                st.write(f"Expires: {license_data['expiration_date']}")
                
                # Calculate minutes remaining
                expiration_date = datetime.datetime.strptime(license_data['expiration_date'], "%Y-%m-%d %H:%M:%S")
                time_remaining = expiration_date - datetime.datetime.now()
                minutes_remaining = time_remaining.total_seconds() / 60
                
                if minutes_remaining <= 5:
                    st.error(f"License expires in {int(minutes_remaining)} minutes!")
                elif minutes_remaining <= 10:
                    st.warning(f"License expires in {int(minutes_remaining)} minutes")
                else:
                    st.info(f"License valid for {int(minutes_remaining)} more minutes")
            except Exception as e:
                st.error("Could not decrypt license information. File may be tampered with.")
        else:
            st.error("License file not found")
    except Exception as e:
        st.error(f"Could not load license information: {e}")

# Hidden developer menu (only accessible with a special query parameter)
if st.experimental_get_query_params().get("dev_mode", [""])[0] == "true":
    st.sidebar.markdown("---")
    with st.sidebar.expander("Developer Options", expanded=False):
        st.write("Developer Mode Active")
        
        # License management
        duration_unit = st.selectbox("Duration Unit", ["minutes", "hours", "days"])
        if duration_unit == "minutes":
            duration = st.number_input("License Duration (minutes)", min_value=1, max_value=1440, value=30)
            minutes = duration
        elif duration_unit == "hours":
            duration = st.number_input("License Duration (hours)", min_value=1, max_value=168, value=1)
            minutes = duration * 60
        else:
            duration = st.number_input("License Duration (days)", min_value=1, max_value=365, value=1)
            minutes = duration * 1440
            
        client_name = st.text_input("Client Name", value="Your Client's Name")
        if st.button("Generate New License"):
            new_license = create_or_update_license(minutes=minutes)
            
            # Update client name in decrypted data, then re-encrypt
            license_data = decrypt_license_data(encrypt_license_data(new_license))
            license_data["client_name"] = client_name
            
            # Re-encrypt and save
            encrypted_data = encrypt_license_data(license_data)
            with open("license_key.enc", "wb") as f:
                f.write(encrypted_data)
                
            expiry_time = datetime.datetime.strptime(license_data['expiration_date'], "%Y-%m-%d %H:%M:%S")
            st.success(f"New license generated until {expiry_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
        if st.button("Revoke License"):
            if os.path.exists("license_key.enc"):
                os.remove("license_key.enc")
                st.success("License revoked")
                st.experimental_rerun()