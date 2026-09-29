import streamlit as st
import pandas as pd
import numpy as np

DATE_COLUMN = 'date/time'
DATA_URL = ('https://s3-us-west-2.amazonaws.com/'
            'streamlit-demo-data/uber-raw-data-sep14.csv.gz')

@st.cache_data
def load_data(nrows):
    data = pd.read_csv(DATA_URL, nrows=nrows)
    lowercase = lambda x: str(x).lower()
    data.rename(lowercase, axis='columns', inplace=True)
    data[DATE_COLUMN] = pd.to_datetime(data[DATE_COLUMN])
    return data

data = load_data(10000)

st.header('SIEM typskit')

if "count" not in st.session_state:
    st.session_state.count = 67

# Display the current count
st.write(f"Misstänkta intrång: {st.session_state.count}")

# Some number in the range 0-23
hour_to_filter = 10
filtered_data = data[data[DATE_COLUMN].dt.hour == hour_to_filter]

st.subheader('Bombaclat alli NYC har gjort intrång')
st.map(filtered_data)