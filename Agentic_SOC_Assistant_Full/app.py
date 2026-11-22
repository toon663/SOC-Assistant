import json, platform
from pathlib import Path
import pandas as pd
import streamlit as st
import plotly.express as px

from config import EVENTS_CSV, ALERTS_CSV, UNSW_DATA_PATH, UNSW_META_PATH
from soc.windows_collector import collect_security_events, save_events
from soc.windows_detection import detect_windows_events, train_windows_baseline
from soc.alert_filter import filter_alerts
from soc.event_correlator import correlate_events
from soc.ai_agent import SOCAgent
from soc.incident_store import save_incidents, get_incidents, update_decision
from soc.evaluation import evaluate_simulation

st.set_page_config(page_title="Agentic SOC Assistant", page_icon="🛡️", layout="wide")
st.title("🛡️ Agentic SOC Assistant")
st.caption("Windows Security Log Monitoring | ML Anomaly Detection | RAGGraph | MITRE ATT&CK | Human approval")

pages=["Overview","Collect Windows Logs","Threat Detection","Agent Investigation","Incident Management",
       "RAGGraph & MITRE","UNSW-NB15 Network Model","Testing & Evaluation"]
page=st.sidebar.radio("Navigation",pages)

def load_events():
    return pd.read_csv(EVENTS_CSV) if EVENTS_CSV.exists() else pd.DataFrame()

if page=="Overview":
    st.subheader("Security Operations Overview")
    events=load_events()
    a,b,c,d=st.columns(4)
    a.metric("Collected Windows events",f"{len(events):,}")
    if not events.empty and "event_id" in events:
        b.metric("Event types",events.event_id.nunique())
    else: b.metric("Event types","0")
    incidents=get_incidents()
    c.metric("Incidents",len(incidents))
    d.metric("Pending review",int((incidents.status=="Pending review").sum()) if not incidents.empty else 0)
    if not events.empty:
        st.plotly_chart(px.histogram(events,x="event_id",title="Collected Windows Event IDs"),use_container_width=True)
    else:
        st.info("No Windows logs collected yet. Open Collect Windows Logs to start.")
    st.warning("Run collection on a Windows computer. This dashboard does not execute containment actions.")

elif page=="Collect Windows Logs":
    st.subheader("Windows Security Event Log Collection")
    st.write("Collects selected Security-channel events from the Windows computer running this application.")
    st.code("4624, 4625, 4672, 4688, 4720, 4732, 4740, 1102, 4697, 7045")
    if platform.system()!="Windows":
        st.error("This feature must be run on Windows. You can still use the simulated test data.")
    method=st.selectbox("Collection method",["pywin32","powershell"])
    limit=st.number_input("Maximum events to collect",min_value=10,max_value=20000,value=1000,step=100)
    if st.button("Collect Windows Security Logs",type="primary",disabled=platform.system()!="Windows"):
        try:
            with st.spinner("Reading Windows Security Event Log..."):
                df=collect_security_events(int(limit),method)
                save_events(df,EVENTS_CSV)
            st.success(f"Collected {len(df)} matching events. Saved to {EVENTS_CSV}")
            st.dataframe(df.head(100),use_container_width=True)
        except Exception as e: st.error(str(e))
    st.caption("Permissions: use an authorised Windows account. Security log access may require Administrator rights or Event Log Readers permissions.")

elif page=="Threat Detection":
    st.subheader("Windows Threat Detection")
    events=load_events()
    upload=st.file_uploader("Or upload Windows event CSV",type=["csv"])
    if upload:
        try: events=pd.read_csv(upload)
        except Exception as e: st.error(str(e))
    if events.empty:
        st.info("No events available. Collect logs or load the simulated dataset in Testing & Evaluation.")
    else:
        minrisk=st.slider("Minimum alert risk score",0,100,25)
        if st.button("Run detection",type="primary"):
            try:
                detected=detect_windows_events(events)
                alerts=filter_alerts(detected,minrisk)
                st.session_state["detected"]=detected
                st.session_state["alerts"]=alerts
                alerts.to_csv(ALERTS_CSV,index=False)
            except Exception as e: st.error(str(e))
        detected=st.session_state.get("detected")
        alerts=st.session_state.get("alerts")
        if detected is not None:
            x,y,z=st.columns(3)
            x.metric("Events scored",len(detected))
            y.metric("Alerts after filtering",len(alerts))
            z.metric("High/Critical",int(detected.risk_level.isin(["High","Critical"]).sum()))
            st.plotly_chart(px.histogram(detected,x="risk_level",title="Risk distribution"),use_container_width=True)
            st.dataframe(alerts[["timestamp","computer","event_id","event_name","risk_score","risk_level","rule_reasons","explanation"]],use_container_width=True)
            if st.button("Correlate events"):
                corr=correlate_events(detected)
                st.session_state["correlations"]=corr
            if "correlations" in st.session_state:
                st.subheader("Correlated event groups")
                st.dataframe(st.session_state["correlations"],use_container_width=True)
            st.download_button("Download alerts CSV",alerts.to_csv(index=False).encode(), "soc_alerts.csv","text/csv")

elif page=="Agent Investigation":
    st.subheader("AI-powered SOC investigation workflow")
    alerts=st.session_state.get("alerts")
    if alerts is None or alerts.empty:
        st.info("Run Threat Detection first.")
    else:
        if st.button("Investigate alerts with SOC agent",type="primary"):
            try:
                correlations=st.session_state.get("correlations")
                results=SOCAgent().investigate(alerts,correlations)
                st.session_state["investigations"]=results
            except Exception as e: st.error(str(e))
        results=st.session_state.get("investigations",[])
        for i,item in enumerate(results):
            with st.expander(f"{item['risk_level']} | Event {item['event_id']} | {item['host']}"):
                st.write("**Explanation:**",item["explanation"])
                st.write("**Potential ATT&CK mapping:**",item["mitre_techniques"] or "No mapping retrieved")
                st.write(item["mitre_summary"])
                st.write("**Recommended actions:**")
                for action in item["recommended_actions"].split(" | "): st.write("•",action)
                st.warning("Human approval required. Recommendations are not executed.")
        if results and st.button("Save investigation results as incidents"):
            save_incidents(results); st.success(f"Saved {len(results)} incidents.")

elif page=="Incident Management":
    st.subheader("Human analyst review and approval")
    incidents=get_incidents()
    if incidents.empty: st.info("No incidents saved yet.")
    else:
        st.dataframe(incidents,use_container_width=True)
        pending=incidents[incidents.status=="Pending review"]
        if not pending.empty:
            iid=st.selectbox("Select incident ID",pending.id.tolist())
            item=pending[pending.id==iid].iloc[0]
            st.write("**Explanation:**",item.explanation)
            st.write("**Recommended actions:**",item.recommended_actions)
            decision=st.selectbox("Analyst decision",["Approved for response planning","False positive","Needs more evidence","Escalated"])
            notes=st.text_area("Analyst notes")
            if st.button("Save analyst decision"):
                update_decision(iid,decision,notes); st.success("Decision recorded."); st.rerun()

elif page=="RAGGraph & MITRE":
    st.subheader("Graph-based cybersecurity knowledge retrieval")
    from soc.raggraph import RAGGraph
    rag=RAGGraph()
    st.metric("Knowledge graph nodes",rag.graph.number_of_nodes())
    st.metric("Knowledge graph edges",rag.graph.number_of_edges())
    eid=st.multiselect("Select Windows Event IDs", [4624,4625,4672,4688,4720,4732,4740,1102,4697,7045], default=[4625])
    query=st.text_input("Investigation context", "repeated failed logons")
    if st.button("Retrieve ATT&CK knowledge"):
        result=rag.explain(eid,query)
        st.write(result["summary"])
        for tech in result["techniques"]:
            with st.expander(f"{tech['id']} – {tech['name']}"):
                st.write("Tactic:",tech["tactic"])
                st.write(tech["description"])
                st.write("Evidence Event IDs:",tech["evidence_event_ids"])
                st.write("Caution:",tech["confidence_note"])
                st.write("Suggested checks:")
                for action in tech["response"]: st.write("•",action)
    st.caption("This is a compact local demonstration knowledge base, not the complete MITRE ATT&CK corpus. Validate mappings against current official ATT&CK content before operational use.")

elif page=="UNSW-NB15 Network Model":
    st.subheader("UNSW-NB15 network-flow model")
    st.write("This is separate from Windows Event Log analysis. It classifies network flows using the supplied dataset.")
    if not UNSW_DATA_PATH.exists():
        st.warning(f"Place UNSW-NB15_Dataset2.csv in {UNSW_DATA_PATH}")
    else:
        st.success("UNSW dataset found.")
        if st.button("Train UNSW models"):
            try:
                from soc.unsw_models import train_unsw
                with st.spinner("Training network-flow models..."):
                    meta=train_unsw()
                st.success("Training completed.")
                st.json({k:v for k,v in meta.items() if k not in ("classification_report",)})
            except Exception as e: st.error(str(e))
        if UNSW_META_PATH.exists():
            meta=json.loads(UNSW_META_PATH.read_text())
            st.metric("Macro F1",f"{meta['macro_f1']:.3f}")
            st.write("Classes:",meta["classes"])
            st.warning(meta["note"])

elif page=="Testing & Evaluation":
    st.subheader("Simulated Windows event testing")
    st.write("Generates a small deterministic test set covering failed logons, log clearing, service installation, account creation and suspicious process execution.")
    if st.button("Run simulated test",type="primary"):
        result=evaluate_simulation()
        st.session_state["test_result"]=result
    result=st.session_state.get("test_result")
    if result is not None:
        st.metric("Simulated events",len(result))
        st.metric("Alerts raised",int(result.alert.sum()))
        st.dataframe(result[["timestamp","computer","event_id","event_name","risk_score","risk_level","explanation"]],use_container_width=True)
        st.download_button("Download simulated results",result.to_csv(index=False).encode(),"simulated_windows_results.csv","text/csv")
    st.info("For real evaluation, collect representative benign and attack-labelled Windows logs, define ground truth, and calculate precision, recall, F1, false-positive rate and detection latency. Do not treat simulated-rule coverage as measured model accuracy.")
