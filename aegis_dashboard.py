import streamlit as st
import pandas as pd
import re
import plotly.express as px

st.set_page_config(page_title="Aegis Security Audit", layout="wide")

def parse_logs(filename):
    data = []
    # Regex to pull out the AI's structured response
    pattern = r"\[(.*?)\] PROCESS: (.*?) \| ANALYSIS: STATUS: (.*?) REASON: (.*)"
    try:
        with open(filename, "r") as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    data.append({
                        "Timestamp": pd.to_datetime(match.group(1)),
                        "App": match.group(2),
                        "Status": match.group(3).replace("REASON:", "").strip().upper(),
                        "Reason": match.group(4).strip()
                    })
        return pd.DataFrame(data)
    except FileNotFoundError:
        return pd.DataFrame()

st.title("🛡️ Aegis-Local Security Audit")
df = parse_logs("security_alerts.log")

if not df.empty:
    # Sidebar Filters
    status_filter = st.sidebar.multiselect("Filter Status", df["Status"].unique(), default=df["Status"].unique())
    filtered_df = df[df["Status"].isin(status_filter)]

    # Metrics
    c1, c2 = st.columns(2)
    c1.metric("Total Events", len(filtered_df))
    c2.metric("Suspicious Detected", len(filtered_df[filtered_df["Status"] == "SUSPICIOUS"]))

    # Visualization
    fig = px.pie(filtered_df, names='Status', color='Status', 
                 color_discrete_map={'SAFE':'#2ecc71', 'SUSPICIOUS':'#e74c3c'})
    st.plotly_chart(fig)

    # Highlighting Table
    def style_row(row):
        return ['background-color: #ffe5e5' if row.Status == 'SUSPICIOUS' else '' for _ in row]
    
    st.dataframe(filtered_df.style.apply(style_row, axis=1), use_container_width=True)
else:
    st.info("Waiting for data... Start the observer script!")
