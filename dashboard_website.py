app.py
import streamlit as st
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import plotly.express as px  # For interactive graphs
import bcrypt
from pymongo import MongoClient
import time
from streamlit_option_menu import option_menu
from pathlib import Path
from datetime import datetime
import os
from dotenv import load_dotenv
from db import users_collection, support_messages, threats_collection, model_results


# Page Configuration
st.set_page_config(
    page_title="SecureNet",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Initialize session state
if "page" not in st.session_state:
    st.session_state["page"] = "landing"
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = None
if "logout_confirmation" not in st.session_state:  # Add this line
    st.session_state["logout_confirmation"] = False


# Load environment variables from .env file
load_dotenv()


# Access the MongoDB connection string
MONGO_URI = os.getenv("MONGO_URI")


# MongoDB Connection
try:
    client = MongoClient(MONGO_URI)
    db = client.network_intrusion
    print("Connected to MongoDB successfully!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")




# Custom CSS
st.markdown("""
<style>
/* Main container */
.stApp {
    background-color: #ffffff;
    font-family: 'Arial', sans-serif;
}


/* Sidebar */
.stSidebar {
    background-color: #2c3e50;
    color: white;
}
/* Sidebar buttons */
.stSidebar .stButton button {
    background-color: #FF4545;;
    color: white;
    border-radius: 5px;
    padding: 10px 20px;
    border: none;
    font-size: 16px;
    margin: 5px 0;
    width: 100% !important; /* Force full width */
}


/* Sidebar button hover effect */
.stSidebar .stButton button:hover {
    background-color: #FF4545 !important;
}
/* Custom CSS for the Log Out button */
.stSidebar .stButton button[key="logout_button"] { /* Increased specificity */
    width: 100% !important; /* Force full width */
    background-color: #e74c3c !important; /* Red background */
    color: white !important; /* White text */
    border-radius: 5px !important; /* Rounded corners */
    padding: 10px 20px !important; /* Add padding */
    font-size: 16px !important; /* Increase font size */
    margin: 5px 0 !important; /* Add margin */
}
/* Sidebar title */
.stSidebar .stMarkdown h1 {
    color: white;
}
/* Metrics */
.stMetric {
    background-color: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}


/* Metric labels */
.stMetric label {
    font-size: 12px;
    color: #666;
}


/* Metric values */
.stMetric div {
    font-size: 16px;
    font-weight: bold;
    color: #333;
}


/* Buttons */
.stButton button {
    background-color: #FF4545;;
    color: white;
    border-radius: 5px;
    padding: 10px 20px;
    border: none;
    font-size: 16px;
    margin: 10px 0;
    width: 100%;
   
}
.stButton button:hover {
    background-color: #FF6363 !important;
}
/* Dataframe */
.stDataFrame {
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}


/* Table headers */
.stDataFrame th {
    background-color: #3498db;
    color: white;
}


/* Table rows */
.stDataFrame tr:nth-child(even) {
    background-color: #f2f2f2;
}


/* Table rows hover */
.stDataFrame tr:hover {
    background-color: #ddd;
}


/* Custom colors for ML Model Status and Network Health */
.ml-model-accuracy {
    color: green !important;
    font-size: 14px !important;
}


.network-health-optimal {
    color: green !important;
    font-size: 14px !important;
}


.network-health-medium {
    color: orange !important;
    font-size: 14px !important;
}


.network-health-low {
    color: red !important;
    font-size: 14px !important;
}


/* Custom CSS for tooltip icon */
.stMetric label span {
    font-size: 12px;
    color: #666;
    margin-left: 5px;
    cursor: help;
}
.stForm button {
    background-color: #FF4545;
    color: white;
    border-radius: 5px;
    padding: 10px 20px;
    border: none;
    font-size: 16px;
    width: 100%;
    margin: 10px 0;
}
</style>
""", unsafe_allow_html=True)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)


def create_user(username, password, email):
    if users_collection.find_one({"username": username}):
        return False
    hashed_password = hash_password(password)
    users_collection.insert_one({"username": username, "password": hashed_password, "email": email})
    return True


def authenticate_user(username, password):
    user = users_collection.find_one({"username": username})
    if user and check_password(user["password"], password):
        return True
    return False


# Function to save model results to MongoDB
def save_model_results_to_db(username, model_name, accuracy, detected_threats):
    """
    Save the model results to the 'model_results' collection.
    """
    try:
        # Extract detected attack types
        detected_attack_types = get_detected_attack_types(detected_threats)


        # Create the results record
        results_record = {
            "username": username,
            "model_name": model_name,
            "accuracy": accuracy,
            "detected_attack_types": detected_attack_types,  # Add detected attack types
            "detected_threats": detected_threats.to_dict("records"),  # Convert DataFrame to a list of dictionaries
            "run_time": datetime.now()
    }
        print("Results Record to Insert:", results_record)


        # Insert the record into the database
        db.model_results.insert_one(results_record)
        print("Model results saved to MongoDB successfully!")
    except Exception as e:
        print(f"Failed to save model results to MongoDB: {e}")
def get_detected_attack_types(detected_threats):
    """
    Extract unique attack types from the detected_threats DataFrame.
    """
    if detected_threats is not None and not detected_threats.empty:
        return detected_threats[" Label"].unique().tolist()
    return []


def landing_page():
    # Custom CSS for the landing page
    st.markdown("""
    <style>
    /* General Styles */
    body {
        font-family: 'Poppins', sans-serif;
        margin: 0;
        padding: 0;
        background-color: ;  /* Light gray background */
        color: #333;
    }


    /* Header Section */
    .header {
        background: linear-gradient(135deg, #FF6363, #FF9E53);
        color: white;
        padding: 100px 20px;
        text-align: center;
    }


    .header h1 {
        font-size: 3rem;
        font-weight: 700;
        margin-bottom: 20px;
    }


    .header p {
        font-size: 1.2rem;
        margin-bottom: 40px;
    }


    /* Features Section */
    .features {
        display: flex;
        justify-content: space-around;
        padding: 60px 20px;
        background-color: white;
    }


    .feature {
        text-align: center;
        max-width: 300px;
    }


    .feature img {
        width: 80px;
        margin-bottom: 20px;
    }


    .feature h3 {
        font-size: 1.5rem;
        margin-bottom: 10px;
    }


    .feature p {
        font-size: 1rem;
        color: #666;
    }


    /* About Section */
    .about {
        background-color: #f4f4f9;  /* Light gray background */
        padding: 60px 20px;
        text-align: center;
    }


    .about h2 {
        font-size: 2.5rem;
        margin-bottom: 20px;
    }


    .about p {
        font-size: 1.1rem;
        max-width: 800px;
        margin: 0 auto 40px;
        color: #555;
    }


    /* Centered Button Container */
    .button-container {
        display: flex;
        justify-content: center;
        align-items: center;
        margin-top: 15px;
        margin-bottom: 60px;
    }


    /* Streamlit Button Styling */
    .stButton button {
        background-color: #FF4545;  /* red background */
        color: white;
        border-radius: 25px;
        padding: 10px 30px;
        font-size: 1.2rem;
        border: none;
        cursor: pointer;
        transition: background-color 0.3s ease;
        width: 100%;
    }


    .stButton button:hover {
        background-color: #2575fc;
    }
    </style>
    """, unsafe_allow_html=True)


    # Option Menu
    selected = option_menu(
        menu_title=None,
        options=["Home", "Sign In", "Sign Up"],
        icons=["house", "person-fill", "person-plus-fill"],
        orientation="horizontal",
        styles={
            "container": {
                "background-color": "#f8f9fa",
                "width": "100%",
                "display": "flex",
                "justify-content": "center",
                "padding": "10px",
                "box-shadow": "0px 2px 5px rgba(0, 0, 0, 0.1)",
                "margin": "0px 10px",
                "padding": "5px 15px",
                "border-radius": "10px",
            },
            "icon": {
                "color": "#DC2525",
                "font-size": "20px",
                "margin": "0px 10px",
            },
            "nav-link": {
                "font-size": "18px",
                "color": "black",
                "text-align": "center",
                "margin": "0px 10px",
                "padding": "5px 15px",
                "border-radius": "10px",
                "transition": "all 0.3s ease",
            },
            "nav-link-hover": {
                "color": "white",
                "background-color": "#4aaae8",
            },
            "nav-link-selected": {
                "background-color": "#FF9A9A",
                "color": "white",
                "font-weight": "bold",
            },
        },
    )


    # Update the session state based on the selected menu option
    if selected == "Home":
        st.session_state["page"] = "landing"
    elif selected == "Sign In":
        st.session_state["page"] = "sign_in"
    elif selected == "Sign Up":
        st.session_state["page"] = "sign_up"


    # Landing Page HTML
    landing_page_html = """
    <!-- Header Section -->
    <div class="header">
        <h1>Welcome to SecureNet</h1>
        <p>Protect your network with cutting-edge machine learning algorithms.</p>
    </div>
    <br>
    <br>
    <!-- Features Section -->
    <div class="features">
        <div class="feature">
            <!-- SVG for Contact Support -->
            <svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 512 512" fill="#DC2525">
                <path d="M256 48C141.1 48 48 141.1 48 256l0 40c0 13.3-10.7 24-24 24s-24-10.7-24-24l0-40C0 114.6 114.6 0 256 0S512 114.6 512 256l0 144.1c0 48.6-39.4 88-88.1 88L313.6 488c-8.3 14.3-23.8 24-41.6 24l-32 0c-26.5 0-48-21.5-48-48s21.5-48 48-48l32 0c17.8 0 33.3 9.7 41.6 24l110.4 .1c22.1 0 40-17.9 40-40L464 256c0-114.9-93.1-208-208-208zM144 208l16 0c17.7 0 32 14.3 32 32l0 112c0 17.7-14.3 32-32 32l-16 0c-35.3 0-64-28.7-64-64l0-48c0-35.3 28.7-64 64-64zm224 0c35.3 0 64 28.7 64 64l0 48c0 35.3-28.7 64-64 64l-16 0c-17.7 0-32-14.3-32-32l0-112c0-17.7 14.3-32 32-32l16 0z"/>
            </svg>
            <h3>Contact Support</h3>
            <p>Reach out to our support team for assistance and guidance.</p>
        </div>
        <div class="feature">
            <!-- SVG for Advanced Threat Detection -->
            <svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#DC2525" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <h3>Advanced Threat Detection</h3>
            <p>Leverage AI to detect and neutralize threats proactively.</p>
        </div>
        <div class="feature">
            <!-- SVG for Detailed Analytics -->
            <svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#DC2525" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="20" x2="18" y2="10"/>
                <line x1="12" y1="20" x2="12" y2="4"/>
                <line x1="6" y1="20" x2="6" y2="14"/>
            </svg>
            <h3>Detailed Analytics</h3>
            <p>Gain insights into network health and performance metrics.</p>
        </div>
    </div>
    <br>
   
    <!-- About Section -->
    <div class="about">
        <h2>About SecureNet</h2>
        <p>SecureNet is a powerful tool designed to help you analyze network threats, detect intrusions, and evaluate machine learning models on uploaded datasets. The dataset must contain a " Label" feature (like CIC-IDS2017) for proper classification.</p>
        <p>Our mission is to provide cutting-edge solutions for network security while ensuring compatibility with standard intrusion detection datasets.</p>
    </div>
    """


    # Render the HTML content
    st.markdown(landing_page_html, unsafe_allow_html=True)


    # Add a centered "Get Started" button using Streamlit's native button
    st.markdown('<div class="button-container">', unsafe_allow_html=True)
    if st.button("Get Started", key="get_started_button"):
        st.session_state["page"] = "sign_up"
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
       
#Sign-Up Page
def sign_up():
    st.title("Sign Up")
    email = st.text_input("Email")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Sign Up"):
        if password == confirm_password:
            if create_user(username, password, email):
                st.success("Account created successfully! Please sign in.")
                st.session_state["page"] = "dashboard"
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.session_state["logout_confirmation"] = False  # Reset logout confirmation
                st.rerun()
            else:
                st.error("Username already exists.")
        else:
            st.error("Passwords do not match.")


# Sign-In Page
def sign_in():
    st.title("Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Sign In"):
        if authenticate_user(username, password):
            st.session_state["authenticated"] = True
            st.session_state["page"] = "dashboard"
            st.session_state["username"] = username
            st.success("Logged in successfully!")
            st.session_state["logout_confirmation"] = False
            time.sleep(1)
            st.rerun()
        else:
            st.error("Invalid username or password.")




# Load Pre-trained Models
rf_model = joblib.load("./models/random_forest_model.pkl")
dt_model = joblib.load("./models/decision_tree_model.pkl")
xgb_model = joblib.load("./models/xgboost_model.pkl")
lgbm_model = joblib.load("./models/lightgbm_model.pkl")


# Define attack types and their severity levels
attack_types = [
    'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack � Brute Force',
    'Web Attack � XSS', 'Web Attack � Sql Injection', 'FTP-Patator', 'SSH-Patator',
    'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye', 'Heartbleed'
]


severity_levels = {
    'Sql Injection': 'Critical',
    'DDoS': 'High',
    'PortScan': 'Medium',
    'Bot': 'Medium',
    'Infiltration': 'High',
    'Brute Force': 'High',
    'XSS': 'High',
    'FTP-Patator': 'Medium',
    'SSH-Patator': 'Medium',
    'DoS slowloris': 'High',
    'DoS Slowhttptest': 'High',
    'DoS Hulk': 'High',
    'DoS GoldenEye': 'High',
    'Heartbleed': 'Critical'
}


# Define severity weights for Network Health calculation
severity_weights = {
    "Critical": 5,
    "High": 3,
    "Medium": 1,
}


# Scaling factor for Threat Impact
SCALING_FACTOR = 5000  # Adjust this based on your dataset


# Function to clean up attack names
def clean_attack_name(attack_name):
    if attack_name.startswith("Web Attack � "):
        return attack_name.replace("Web Attack � ", "")
    return attack_name


# Function to calculate Threat Impact
def calculate_threat_impact(detected_threats):
    if detected_threats is None or len(detected_threats) == 0:
        return 0  # No threats, so no impact


    # Count the number of threats by severity
    threat_counts = detected_threats["Severity"].value_counts().to_dict()


    # Calculate Threat Impact
    threat_impact = 0
    for severity, weight in severity_weights.items():
        threat_impact += threat_counts.get(severity, 0) * weight


    # Normalize Threat Impact using the scaling factor
    threat_impact = min(threat_impact / SCALING_FACTOR, 1)  # Cap at 1 (100%)


    return threat_impact * 100  # Convert to percentage


# Function to calculate Network Health with baseline
def calculate_network_health(detected_threats):
    threat_impact = calculate_threat_impact(detected_threats)
    network_health = max(100 - threat_impact, 10)  # Minimum health of 10%
    return network_health


# Function to get performance label and color
def get_network_health_performance(network_health):
    if network_health >= 70:
        return "Optimal Performance", "network-health-optimal"
    elif 30 <= network_health < 70:
        return "Medium Performance", "network-health-medium"
    else:
        return "Low Performance", "network-health-low"
   
# Function to send email
def contact_support():
    st.title("Contact Support")
    st.markdown("Fill out the form below to contact our support team.")


    # Contact Form
    with st.form("support_form"):
        name = st.text_input("Name", placeholder="Enter your name")
        email = st.text_input("Email", placeholder="Enter your email address")
        message = st.text_area("Message", placeholder="Enter your message", height=150)
        submit_button = st.form_submit_button("Send Message")


        if submit_button:
            if name and email and message:
                # Save the message to MongoDB
                support_messages.insert_one({
                    "name": name,
                    "email": email,
                    "message": message,
                    "timestamp": datetime.now()
                })
                st.session_state["page"] = "dashboard"
                st.success("Your message has been submitted! We'll get back to you soon.")
            else:
                st.error("Please fill out all fields.")




# Add this function to handle logout
def logout_user():
    # Delete user from the database (or mark as logged out)
    username = st.session_state.get("username")
    if username:
        users_collection.delete_one({"username": username})  # Delete user from MongoDB
        st.success(f"User {username} logged out and deleted from the database.")
    else:
        st.error("User not found in the database.")


    # Reset session state
    st.session_state["authenticated"] = False
    st.session_state["username"] = None
    st.session_state["page"] = "landing"
    st.rerun()  # Redirect to landing page


def get_detected_attack_types(detected_threats):
    """
    Extract unique attack types from the detected_threats DataFrame.
    """
    if detected_threats is not None and not detected_threats.empty:
        return detected_threats[" Label"].unique().tolist()
    return []




# Dashboard Page
def dashboard():
    attack_descriptions = {
        "DDoS": "Bandwidth floods. Service fails.",
    "PortScan": "Ports checked. Security uncertain.",
    "Bot": "Automated breach. Control stolen.",
    "Infiltration": "Forced entry. You lose.",
    "Brute Force": "Password guessing. Doors open.",
    "XSS": "Script injection. Pages hijacked.",
    "Sql Injection": "Malicious queries. Database broken.",
    "FTP-Patator": "Credentials guessed. System undone.",
    "SSH-Patator": "SSH hammered. Access compromised.",
    "DoS slowloris": "Connections linger. Service denied.",
    "DoS Slowhttptest": "Requests drip. Infrastructure starves.",
    "DoS Hulk": "Requests surge. System breaks.",
    "DoS GoldenEye": "Resource depleted. Downtime follows.",
    "Heartbleed": "Memory leaks. Data exposed.",
    "Normal": "No attack. Situation stable."
    }


    st.sidebar.title("SecureNet")
    st.sidebar.markdown(f"Hi, **<span style='color:HotPink; font-size: 22px;'>{st.session_state['username']}</span>**", unsafe_allow_html=True)
    st.sidebar.markdown("Navigate the SecureNet dashboard to monitor network threats and model performance.")
    st.sidebar.markdown("---")
    st.sidebar.markdown("---")
    st.sidebar.markdown("---")
    st.sidebar.markdown("---")
    if st.sidebar.button("Support"):
        st.session_state["page"] = "contact_support"
        st.rerun()


    if st.sidebar.button("Log Out", key="logout_button", help="Click to log out"):
        st.session_state["logout_confirmation"] = True


    if st.session_state.get("logout_confirmation", False):
        st.sidebar.warning("Are you sure you want to log out?")
        col1, col2 = st.sidebar.columns(2)
        with col1:
            if st.button("Yes", key="confirm_logout"):
                logout_user()
        with col2:
            if st.button("No", key="cancel_logout"):
                st.session_state["logout_confirmation"] = False


    st.title("SecureNet Dashboard")
    st.markdown("📊 A tool for network intrusion detection and machine learning model evaluation.")


    col1, col2, col3 = st.columns(3)
    with col1:
        if "detected_threats" in st.session_state:
            active_threats = len(st.session_state["detected_threats"])
        else:
            active_threats = 0


        st.markdown(f"""
        <div class="stMetric">
            <label>
                Active Threats
                <span title="Number of active threats detected." style="cursor: help;">&#9432;</span>
            </label>
            <div>{active_threats}</div>
            <div style="height: 24px; display: flex; align-items: center; color: green">Monitoring Active</div>
        </div>
        """, unsafe_allow_html=True)


    with col2:
        if "detected_threats" in st.session_state:
            network_health = calculate_network_health(st.session_state["detected_threats"])
        else:
            network_health = 100


        performance_label, performance_color = get_network_health_performance(network_health)
        st.markdown(f"""
        <div class="stMetric">
            <label>
                Network Health
                <span title="Overall health of the network based on detected threats." style="cursor: help;">&#9432;</span>
            </label>
            <div>{network_health:.2f}%</div>
            <div class="{performance_color}" style="height: 24px; display: flex; align-items: center;">{performance_label}</div>
        </div>
        """, unsafe_allow_html=True)


    with col3:
        if "ml_model_status" not in st.session_state:
            st.markdown(f"""
            <div class="stMetric">
                <label>
                    ML Model Status
                    <span title="No model has been selected or run yet." style="cursor: help;">&#9432;</span>
                </label>
                <div style="color: green;">Model not selected yet</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            ml_model_status = st.session_state["ml_model_status"]
            ml_model_accuracy = st.session_state.get("ml_model_accuracy", 0)
            st.markdown(f"""
            <div class="stMetric">
                <label>
                    ML Model Status
                    <span title="Current model in use and its accuracy on the dataset." style="cursor: help;">&#9432;</span>
                </label>
                <div>{ml_model_status}</div>
                <div class="ml-model-accuracy" style="height: 24px; display: flex; align-items: center;">{ml_model_accuracy:.2f}% Accuracy</div>
            </div>
            """, unsafe_allow_html=True)


    col_left, col_right = st.columns([2, 1])
    with col_left:
        if "detected_threats" in st.session_state:
            st.markdown("### Network Activity")
            detected_threats = st.session_state["detected_threats"]
            detected_threats[" Label"] = detected_threats[" Label"].apply(clean_attack_name)
            detected_threats[" Label"] = detected_threats[" Label"].replace("BENIGN", "Normal")
            attack_distribution = detected_threats[" Label"].value_counts().reset_index()
            attack_distribution.columns = ["Attack Type", "Count"]
            fig = px.bar(
                attack_distribution,
                x="Count",
                y="Attack Type",
                title=None,
                labels={"Count": "Number of Attacks", "Attack Type": "Attack Type"},
                orientation="h",
                color="Attack Type",
                color_discrete_sequence=px.colors.qualitative.Plotly,
                height=300,
            )
            fig.update_traces(marker=dict(line=dict(width=0.5)), width=0.5)
            st.plotly_chart(fig, use_container_width=True)


        if "detected_threats" in st.session_state:
            st.markdown("### Detected Threats")
            detected_threats = st.session_state["detected_threats"]
            detected_threats[" Label"] = detected_threats[" Label"].apply(clean_attack_name)
            threat_summary = detected_threats.groupby(" Label").size().reset_index(name="No. of Attacks")
            threat_summary["Severity"] = threat_summary[" Label"].map(severity_levels)
            threat_summary["Details"] = threat_summary[" Label"].apply(
                lambda x: attack_descriptions.get(x, f"Information about {x} attack.")
            )
            threat_summary["Timestamp"] = pd.Timestamp.now()
            st.dataframe(
                threat_summary[["Timestamp", " Label", "No. of Attacks", "Severity", "Details"]],
                column_config={
                    "Timestamp": "Timestamp",
                    " Label": "Type",
                    "No. of Attacks": "No. of Attacks",
                    "Severity": "Severity",
                    "Details": "Details"
                },
                use_container_width=True
            )


    with col_right:
        st.markdown("### Model Selection")
        model = st.selectbox(
            "Select Model:",
            ["Random Forest (RF)", "Decision Tree (DT)", "XGBoost (XGB)", "LightGBM (LGBM)"]
        )
        uploaded_file = st.file_uploader(
            f"Upload data for {model}",
            type=["csv"],
            help="Upload a CSV file containing the training data."
        )
        if uploaded_file is not None:
            st.write("File uploaded successfully!")
            data = pd.read_csv(uploaded_file)
            if " Label" not in data.columns:
                st.error("Uploaded file must contain a ' Label' column.")
            else:
                data = data.dropna()
                data.replace([np.inf, -np.inf], np.nan, inplace=True)
                data = data.dropna()
                if (data.select_dtypes(include=[np.number]).max() > 1e6).any():
                    scaler = StandardScaler()
                    numeric_cols = data.select_dtypes(include=[np.number]).columns
                    data[numeric_cols] = scaler.fit_transform(data[numeric_cols])
                X = data.drop(" Label", axis=1)
                y = data[" Label"]
                unique_classes = y.unique()
                if len(unique_classes) < 2:
                    st.error(f"Dataset contains only one class: {unique_classes[0]}. At least two classes are required for classification.")
                    return
                label_encoder = LabelEncoder()
                y_encoded = label_encoder.fit_transform(y)
                if model == "Random Forest (RF)":
                    selected_model = rf_model
                elif model == "Decision Tree (DT)":
                    selected_model = dt_model
                elif model == "XGBoost (XGB)":
                    selected_model = xgb_model
                elif model == "LightGBM (LGBM)":
                    selected_model = lgbm_model
                    selected_model.set_params(early_stopping_rounds=None)
                else:
                    st.error("Invalid model selected.")
                    selected_model = None
                if selected_model:
                    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42)
                    detected_threats = None
                    try:
                        selected_model.fit(X_train, y_train)
                        predictions = selected_model.predict(X_test)
                        accuracy = accuracy_score(y_test, predictions)
                        st.success(f"Accuracy of {model}: {accuracy * 100:.2f}%")
                        detected_threats = data[data[" Label"] != "BENIGN"].copy()
                        detected_threats["Severity"] = detected_threats[" Label"].map(severity_levels)
                        detected_threats["Timestamp"] = pd.Timestamp.now()
                        save_model_results_to_db(st.session_state["username"], model, accuracy, detected_threats)
                        st.session_state["ml_model_accuracy"] = round(accuracy * 100, 2)
                        st.session_state["ml_model_status"] = f"{model} Active"
                        st.session_state["detected_threats"] = detected_threats
                        st.rerun()
                    except Exception as e:
                        st.error(f"An error occurred while training the model: {e}")
                        if detected_threats is None:
                            st.warning("No threats detected or an error occurred during processing.")


# Main App Logic
def main():
    # Navigation Logic
    if st.session_state["page"] == "landing":
        landing_page()
    elif st.session_state["page"] == "sign_up":
        sign_up()
    elif st.session_state["page"] == "sign_in":
        sign_in()
    elif st.session_state["page"] == "dashboard":
        dashboard()
    elif st.session_state["page"] == "contact_support":
        contact_support()


if __name__ == "__main__":
    main()






# auth.py
import bcrypt
from db import users_collection  # Import users_collection from db.py


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)


def signup_user(username, password):
    if users_collection.find_one({"username": username}):
        return False
    hashed = hash_password(password)
    users_collection.insert_one({"username": username, "password": hashed})
    return True


def login_user(username, password):
    user = users_collection.find_one({"username": username})
    if user and check_password(password, user["password"]):
        return True
    return False



















# db.py
from pymongo import MongoClient
from dotenv import load_dotenv
import os


# Load environment variables from .env file
load_dotenv()


# Access the MongoDB connection string
MONGO_URI = os.getenv("MONGO_URI")


# MongoDB Connection
client = MongoClient(MONGO_URI)
db = client.network_intrusion


# Collections
users_collection = db.users
support_messages = db.support_messages
threats_collection = db.threats
model_results = db.model_results





















#requirements.txt
# This file lists the Python packages required for the project.
streamlit
pymongo
bcrypt
pandas
scikit-learn
xgboost
utils
lightgbm
