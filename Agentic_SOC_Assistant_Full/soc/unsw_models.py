"""Optional UNSW-NB15 network-flow model retained separately from Windows event detection."""
import json, joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, classification_report
from config import UNSW_DATA_PATH, UNSW_RF_PATH, UNSW_ISO_PATH, UNSW_META_PATH

def train_unsw():
    if not UNSW_DATA_PATH.exists():
        raise FileNotFoundError(f"Place your supplied dataset at {UNSW_DATA_PATH}")
    df=pd.read_csv(UNSW_DATA_PATH,low_memory=False)
    if "attack" not in df: raise ValueError("Dataset must contain attack column.")
    df=df.replace([float("inf"),float("-inf")],pd.NA)
    y=df["attack"].astype(str)
    X=df.drop(columns=["attack"])
    X=X.apply(pd.to_numeric,errors="coerce")
    X=X.fillna(X.median(numeric_only=True)).fillna(0)
    # Drop duplicate rows to reduce leakage; report count.
    joined=pd.concat([X,y.rename("attack")],axis=1)
    before=len(joined); joined=joined.drop_duplicates()
    X=joined.drop(columns="attack"); y=joined.attack
    enc=LabelEncoder(); yy=enc.fit_transform(y)
    Xtr,Xte,ytr,yte=train_test_split(X,yy,test_size=.2,random_state=42,stratify=yy)
    rf=RandomForestClassifier(n_estimators=250,class_weight="balanced_subsample",n_jobs=-1,random_state=42)
    rf.fit(Xtr,ytr); pred=rf.predict(Xte)
    iso=IsolationForest(n_estimators=200,contamination="auto",random_state=42,n_jobs=-1).fit(Xtr)
    joblib.dump({"model":rf,"encoder":enc,"features":list(X.columns)},UNSW_RF_PATH)
    joblib.dump({"model":iso,"features":list(X.columns)},UNSW_ISO_PATH)
    meta={"rows_before_dedup":before,"rows_after_dedup":len(joined),"duplicates_removed":before-len(joined),
          "accuracy":accuracy_score(yte,pred),"macro_f1":f1_score(yte,pred,average="macro"),
          "classification_report":classification_report(yte,pred,target_names=enc.classes_,output_dict=True),
          "classes":list(enc.classes_),"note":"Five attack categories only; no benign class in supplied CSV."}
    UNSW_META_PATH.write_text(json.dumps(meta,indent=2))
    return meta
