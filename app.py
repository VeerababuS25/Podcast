import streamlit as st
import base64
import json
import re
import os
import pandas as pd
from graphviz import Digraph, ExecutableNotFound
from datetime import datetime

# Streamlit app configuration
st.set_page_config(page_title="Enterprise Threat Modeling", page_icon="🔒", layout="wide")

# Initialize session state
if 'step' not in st.session_state:
    st.session_state.step = 1
if 'scope' not in st.session_state:
    st.session_state.scope = {
        "assets": "User data (PII), payment details",
        "objectives": "Confidentiality, Integrity, Availability",
        "compliance": "GDPR, PCI-DSS"
    }
if 'text_input' not in st.session_state:
    st.session_state.text_input = "Public-facing e-commerce app with React frontend, Node.js backend, MySQL database, Stripe payment gateway."
if 'diagram' not in st.session_state:
    st.session_state.diagram = None
if 'data_flows' not in st.session_state:
    st.session_state.data_flows = [
        {"source": "Frontend", "destination": "Backend", "dataType": "PII, Credentials"},
        {"source": "Backend", "destination": "Database", "dataType": "User Data, Orders"},
        {"source": "Backend", "destination": "Payment Gateway", "dataType": "Payment Details"}
    ]
if 'trust_boundaries' not in st.session_state:
    st.session_state.trust_boundaries = [
        {"name": "Frontend Boundary", "description": "Untrusted client-side React app"},
        {"name": "Backend Boundary", "description": "Trusted Node.js API and MySQL database"},
        {"name": "Payment Gateway Boundary", "description": "External Stripe service"}
    ]
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = None
if 'error' not in st.session_state:
    st.session_state.error = ""
if 'generated_diagram' not in st.session_state:
    st.session_state.generated_diagram = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False

# Session persistence
SESSION_FILE = "threat_model_session.json"
def save_session():
    session_data = {
        "scope": st.session_state.scope,
        "text_input": st.session_state.text_input,
        "data_flows": st.session_state.data_flows,
        "trust_boundaries": st.session_state.trust_boundaries
    }
    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f)
def load_session():
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, "r") as f:
            data = json.load(f)
            st.session_state.scope.update(data.get("scope", {}))
            st.session_state.text_input = data.get("text_input", "")
            st.session_state.data_flows = data.get("data_flows", [])
            st.session_state.trust_boundaries = data.get("trust_boundaries", [])

# Load session on startup
load_session()

# Title and help section
st.title("Enterprise Threat Modeling")
with st.expander("Help: STRIDE and OWASP Process"):
    st.markdown("""
    **STRIDE Framework**:
    - Spoofing: Impersonating users/systems.
    - Tampering: Modifying data/code.
    - Repudiation: Avoiding accountability.
    - Information Disclosure: Exposing sensitive data.
    - Denial of Service: Disrupting availability.
    - Elevation of Privilege: Gaining unauthorized access.

    **OWASP Process**:
    1. Define Scope: Identify assets, objectives, compliance.
    2. Decompose Application: Map data flows, trust boundaries.
    3. Identify Threats: Use STRIDE for systematic analysis.
    4. Prioritize Mitigations: Address high-risk threats first.
    """)

def generate_diagram(threats):
    try:
        dot = Digraph(comment="Data Flow Diagram", format="png")
        dot.attr(rankdir="TB", size="10,8", fontname="Arial", bgcolor="white", splines="polyline")
        dot.attr("node", fontname="Arial", fontsize="12")
        dot.attr("edge", fontname="Arial", fontsize="10")

        node_styles = {
            "Frontend": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral", "color": "red"},
            "Backend": {"shape": "box", "style": "filled", "fillcolor": "lightblue", "color": "blue"},
            "Database": {"shape": "cylinder", "style": "filled", "fillcolor": "lightblue", "color": "blue"},
            "Payment Gateway": {"shape": "oval", "style": "filled", "fillcolor": "lightgreen", "color": "green"}
        }

        nodes = set()
        for flow in st.session_state.data_flows:
            nodes.add(flow["source"])
            nodes.add(flow["destination"])

        node_threats = {}
        edge_threats = {}
        for threat in threats:
            dfd_element = threat.get("dfd_element", "")
            threat_id = threat.get("id", "")
            if "→" in dfd_element:
                edge_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")
            else:
                node_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")

        assets = st.session_state.scope.get("assets", "").lower()
        for node in nodes:
            threat_label = node_threats.get(node, [])
            asset_info = "Assets: PII" if node.lower() in assets else "Assets: None"
            label = f"{node}\n{asset_info}\nThreats: {', '.join(threat_label) if threat_label else 'None'}"
            style = node_styles.get(node, {"shape": "box", "style": "filled", "fillcolor": "white", "color": "black"})
            dot.node(node, label, **style, penwidth="2" if threat_label else "1")

        for flow in st.session_state.data_flows:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_label = edge_threats.get(edge_key, [])
            label = f"{flow['dataType']}\nThreats: {', '.join(threat_label) if threat_label else 'None'}"
            dot.edge(flow["source"], flow["destination"], label=label, color="red" if threat_label else "black", penwidth="2" if threat_label else "1")

        for boundary in st.session_state.trust_boundaries:
            with dot.subgraph(name=f"cluster_{boundary['name']}") as c:
                c.attr(label=f"{boundary['name']}\nThreats: {', '.join(node_threats.get(boundary['name'], []) or ['None'])}", 
                       style="dashed", color="purple", fontname="Arial", fontsize="12", penwidth="2")
                components = re.findall(r"\b\w+\b", boundary["description"].lower())
                for node in nodes:
                    if node.lower() in components or node.lower() in boundary["name"].lower():
                        c.node(node)

        diagram_path = dot.render("diagram", format="png", cleanup=True)
        with open(diagram_path, "rb") as f:
            st.session_state.generated_diagram = base64.b64encode(f.read()).decode("utf-8")
        return st.session_state.generated_diagram
    except ExecutableNotFound:
        st.session_state.error = "Graphviz executable not found. Using ASCII diagram."
        return None
    except Exception as e:
        st.session_state.error = f"Diagram generation failed: {str(e)}"
        return None

def fallback_ascii_diagram(threats):
    assets = st.session_state.scope.get("assets", "").lower()
    node_threats = {}
    edge_threats = {}
    threat_details = {}
    for threat in threats:
        dfd_element = threat.get("dfd_element", "")
        threat_id = threat.get("id", "")
        threat_details[threat_id] = f"{threat['type']}: {threat['description']}"
        if "→" in dfd_element:
            edge_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")
        else:
            node_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")

    diagram = """
    +----------------+         +----------------+         +----------------+
    |    Frontend    |<------->|    Backend     |<------->|    Database    |
    | Assets: {frontend_assets} | Assets: {backend_assets} | Assets: {database_assets} |
    | Threats: {frontend_threats} | Threats: {backend_threats} | Threats: {database_threats} |
    +----------------+         +----------------+         +----------------+
            |                          |
            |                          v
            |                   +----------------+
            |                   | Payment Gateway |
            |                   | Assets: {payment_assets} |
            |                   | Threats: {payment_threats} |
            |                   +----------------+
    ---- Trust Boundaries ----

    Data Flow Threats:
      Frontend → Backend: {frontend_backend_threats}
      Backend → Database: {backend_database_threats}
      Backend → Payment Gateway: {backend_payment_threats}
    """

    legend = "\nThreat Legend:\n"
    legend += "+-------+--------------------------+\n"
    legend += "| ID    | Threat Description       |\n"
    legend += "+-------+--------------------------+\n"
    for threat_id, description in sorted(threat_details.items()):
        legend += f"| {threat_id:<5} | {description:<24} |\n"
    legend += "+-------+--------------------------+\n"

    return diagram.format(
        frontend_assets="PII" if "frontend" in assets else "None",
        backend_assets="Orders" if "backend" in assets else "None",
        database_assets="User Data, Orders" if "database" in assets else "None",
        payment_assets="Payment Details" if "payment" in assets else "None",
        frontend_threats=", ".join(node_threats.get("Frontend", ["None"])),
        backend_threats=", ".join(node_threats.get("Backend", ["None"])),
        database_threats=", ".join(node_threats.get("Database", ["None"])),
        payment_threats=", ".join(node_threats.get("Payment Gateway", ["None"])),
        frontend_backend_threats=", ".join(edge_threats.get("Frontend → Backend", ["None"])),
        backend_database_threats=", ".join(edge_threats.get("Backend → Database", ["None"])),
        backend_payment_threats=", ".join(edge_threats.get("Backend → Payment Gateway", ["None"]))
    ) + legend

def analyze_threats():
    threats = []
    threat_counter = 1
    is_public_facing = "public-facing" in st.session_state.text_input.lower()

    def add_threat(threat_type, description, stride, mitigation, asvs, samm, dfd_element, controls, likelihood, impact, action):
        nonlocal threat_counter
        risk_score = {"Low": 1, "Medium": 2, "High": 3}
        priority = risk_score[likelihood] * risk_score[impact]
        priority_label = "High" if priority >= 6 else "Medium" if priority >= 3 else "Low"
        threats.append({
            "id": f"T{threat_counter}",
            "type": threat_type,
            "description": description,
            "stride": stride,
            "mitigation": mitigation,
            "asvs": asvs,
            "samm": samm,
            "dfd_element": dfd_element,
            "controls": controls,
            "likelihood": likelihood,
            "impact": impact,
            "priority": priority_label,
            "action": action
        })
        threat_counter += 1

    scope = st.session_state.scope
    assets = scope.get("assets", "").lower()
    objectives = scope.get("objectives", "").lower()

    if "pii" in assets or "payment details" in assets:
        add_threat(
            "Information Disclosure",
            "Sensitive data (PII, payment details) exposed.",
            "Information Disclosure",
            "Encrypt data at rest and in transit.",
            "V9.1.1 - Secure communication; V4.1.3 - Access controls.",
            "Implementation Level 2 - Secure data; Operations Level 2 - Protect data.",
            "Backend → Database",
            "Use AWS KMS for key management, TLS 1.3 for transit.",
            "High" if is_public_facing else "Medium",
            "High",
            "Implement AES-256 encryption and enable TLS 1.3 on all endpoints."
        )
    if "confidentiality" in objectives:
        add_threat(
            "Spoofing",
            "Impersonation of users to access sensitive data.",
            "Spoofing",
            "Implement MFA and secure session management.",
            "V2.1.1 - Strong authentication; V2.7.1 - Session management.",
            "Threat Assessment Level 1 - Identify risks; Governance Level 2 - Policies.",
            "Frontend → Backend",
            "Use MFA (TOTP) and HTTP-only, Secure cookies.",
            "High" if is_public_facing else "Medium",
            "High",
            "Deploy Auth0 or AWS Cognito with MFA enabled."
        )
    if "integrity" in objectives:
        add_threat(
            "Tampering",
            "Modification of order data affecting integrity.",
            "Tampering",
            "Use digital signatures and server-side validation.",
            "V5.1.3 - Input validation; V5.3.4 - Secure queries.",
            "Design Level 2 - Integrity controls; Verification Level 1 - Validate inputs.",
            "Backend → Database",
            "Apply HMAC-SHA256 and whitelist validation.",
            "Medium",
            "High",
            "Configure server-side validation with OWASP ESAPI."
        )
    if "availability" in objectives:
        add_threat(
            "Denial of Service",
            "Flooding disrupts service availability.",
            "Denial of Service",
            "Implement rate limiting and use CDN.",
            "V1.10.1 - Anti-DoS controls; V13.1.1 - API resilience.",
            "Incident Management Level 2 - Monitor DoS; Operations Level 2 - Availability.",
            "Frontend → Backend",
            "Set rate limits (100 requests/min), use AWS CloudFront.",
            "High" if is_public_facing else "Medium",
            "High",
            "Enable AWS WAF and CloudFront with rate limiting."
        )

    for flow in st.session_state.data_flows:
        data_type = flow.get('dataType', '').lower()
        source = flow.get('source', '').lower()
        destination = flow.get('destination', '').lower()
        edge_key = f"{flow['source']} → {flow['destination']}"

        if 'user' in source or 'client' in source:
            add_threat(
                "Spoofing",
                f"Unauthorized access in flow from {source} to {destination}.",
                "Spoofing",
                "Validate source identity with OAuth 2.0 or JWT.",
                "V2.1.2 - Identity validation; V2.7.3 - Session binding.",
                "Threat Assessment Level 1 - Identify risks; Governance Level 2 - Policies.",
                edge_key,
                "Use OAuth 2.0 with PKCE, RS256 JWT signing.",
                "High" if is_public_facing else "Medium",
                "High",
                "Implement OAuth 2.0 with AWS API Gateway."
            )
        if 'pii' in data_type or 'sensitive' in data_type:
            add_threat(
                "Information Disclosure",
                f"Sensitive data ({data_type}) exposed in flow.",
                "Information Disclosure",
                "Encrypt data with TLS 1.3, mask logs.",
                "V9.1.2 - Encryption; V4.1.4 - Access restrictions.",
                "Implementation Level 2 - Secure data; Operations Level 2 - Protect data.",
                edge_key,
                "Use TLS 1.3, implement log masking.",
                "High" if is_public_facing else "Medium",
                "High",
                "Configure HTTPS with TLS 1.3 and log sanitization."
            )

    for boundary in st.session_state.trust_boundaries:
        name = boundary.get('name', '').lower()
        if 'frontend' in name:
            add_threat(
                "Spoofing",
                f"Cross-boundary spoofing in {name}.",
                "Spoofing",
                "Enforce mutual TLS and validate requests.",
                "V2.1.3 - Boundary authentication; V13.2.1 - API security.",
                "Threat Assessment Level 2 - Boundary risks; Governance Level 2 - Policies.",
                boundary["name"],
                "Use mutual TLS with client certificates.",
                "High" if is_public_facing else "Medium",
                "High",
                "Configure mutual TLS on API endpoints."
            )

    threats.sort(key=lambda x: {"High": 1, "Medium": 2, "Low": 3}[x["priority"]])
    return {"threats": threats}

def export_threats(threats):
    df = pd.DataFrame(threats)
    df = df[["id", "type", "stride", "dfd_element", "description", "likelihood", "impact", "priority", "mitigation", "controls", "asvs", "samm", "action"]]
    csv = df.to_csv(index=False)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    st.download_button(
        label="Export Threat Report (CSV)",
        data=csv,
        file_name=f"threat_report_{timestamp}.csv",
        mime="text/csv",
        disabled=not st.session_state.is_admin
    )
    return df

def step_1():
    st.header("Step 1: Define Scope and Objectives")
    st.session_state.is_admin = st.checkbox("Admin Access (Enable Export)", value=st.session_state.is_admin)
    st.session_state.scope["assets"] = st.text_input("Assets (e.g., PII, Payment details)", st.session_state.scope["assets"])
    st.session_state.scope["objectives"] = st.text_input("Security Objectives (e.g., Confidentiality, Integrity)", st.session_state.scope["objectives"])
    st.session_state.scope["compliance"] = st.text_input("Compliance Requirements (e.g., GDPR, PCI-DSS)", st.session_state.scope["compliance"])
    st.session_state.text_input = st.text_area("System Architecture", st.session_state.text_input, height=150)
    uploaded_file = st.file_uploader("Upload DFD (PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        st.session_state.diagram = base64.b64encode(uploaded_file.read()).decode("utf-8")
        st.image(uploaded_file, caption="Uploaded DFD")
    if st.button("Next"):
        if st.session_state.scope["assets"] and st.session_state.scope["objectives"] and (st.session_state.text_input or st.session_state.diagram):
            save_session()
            st.session_state.step = 2
            st.rerun()
        else:
            st.session_state.error = "Provide assets, objectives, and system description or diagram."

def step_2():
    st.header("Step 2: Decompose the Application")
    st.session_state.is_admin = st.checkbox("Admin Access (Enable Export)", value=st.session_state.is_admin)
    st.subheader("Data Flows")
    with st.container():
        source = st.text_input("Source (e.g., User, API)", key="data_flow_source")
        destination = st.text_input("Destination (e.g., Database)", key="data_flow_destination")
        data_type = st.text_input("Data Type (e.g., PII)", key="data_flow_type")
        if st.button("Add Data Flow"):
            if source and destination and data_type:
                st.session_state.data_flows.append({"source": source, "destination": destination, "dataType": data_type})
                save_session()
                st.success("Data Flow added!")
                st.rerun()
            else:
                st.session_state.error = "Fill in all data flow fields."

    if st.session_state.data_flows:
        st.write("**Current Data Flows:**")
        for flow in st.session_state.data_flows:
            st.write(f"{flow['source']} → {flow['destination']} ({flow['dataType']})")

    st.subheader("Trust Boundaries")
    with st.container():
        trust_boundary_options = ["Web Server", "Database", "API", "Frontend", "Payment Gateway", "Custom"]
        selected_boundary = st.selectbox("Select Trust Boundary", trust_boundary_options, key="trust_boundary_select")
        name = selected_boundary
        if selected_boundary == "Custom":
            name = st.text_input("Custom Boundary Name", key="custom_boundary_name")
        description = st.text_input("Boundary Description", key="boundary_description")
        if st.button("Add Trust Boundary"):
            if name and description and name != "Custom":
                st.session_state.trust_boundaries.append({"name": name, "description": description})
                save_session()
                st.success("Trust Boundary added!")
                st.rerun()
            else:
                st.session_state.error = "Provide valid boundary name and description."

    if st.session_state.trust_boundaries:
        st.write("**Current Trust Boundaries:**")
        for boundary in st.session_state.trust_boundaries:
            st.write(f"{boundary['name']}: {boundary['description']}")

    if st.session_state.data_flows or st.session_state.trust_boundaries:
        st.subheader("Data Flow Diagram")
        preview_threats = analyze_threats().get("threats", [])
        diagram = generate_diagram(preview_threats)
        if diagram:
            st.image(f"data:image/png;base64,{diagram}", caption="DFD with Assets and Threats", width=800)
        else:
            st.markdown("**ASCII Diagram**:")
            st.code(fallback_ascii_diagram(preview_threats), language="text")
            if st.session_state.error:
                st.error(st.session_state.error)

    if st.button("Analyze Threats"):
        if st.session_state.data_flows or st.session_state.trust_boundaries:
            with st.spinner("Analyzing threats..."):
                st.session_state.threat_model = analyze_threats()
                st.session_state.step = 3
                st.rerun()
        else:
            st.session_state.error = "Add at least one data flow or trust boundary."

def step_3():
    st.header("Step 3 & 4: Identify Threats and Prioritize Mitigations")
    st.session_state.is_admin = st.checkbox("Admin Access (Enable Export)", value=st.session_state.is_admin)
    if st.session_state.threat_model:
        st.subheader("Threat Analysis Table")
        df = export_threats(st.session_state.threat_model["threats"])
        st.dataframe(
            df.style.apply(lambda x: ["background-color: #ffcccc" if x["priority"] == "High" else 
                                     "background-color: #fff4cc" if x["priority"] == "Medium" else 
                                     "background-color: #ccffcc" for _ in x], axis=1),
            use_container_width=True
        )

    if st.session_state.generated_diagram:
        st.subheader("Data Flow Diagram")
        st.image(f"data:image/png;base64,{st.session_state.generated_diagram}", caption="DFD with Assets and Threats", width=800)
    else:
        st.markdown("**ASCII Diagram**:")
        st.code(fallback_ascii_diagram(st.session_state.threat_model.get("threats", [])), language="text")

    if st.session_state.error:
        st.error(st.session_state.error)

    if st.button("Start Over"):
        st.session_state.step = 1
        st.session_state.scope = {
            "assets": "User data (PII), payment details",
            "objectives": "Confidentiality, Integrity, Availability",
            "compliance": "GDPR, PCI-DSS"
        }
        st.session_state.text_input = "Public-facing e-commerce app with React frontend, Node.js backend, MySQL database, Stripe payment gateway."
        st.session_state.diagram = None
        st.session_state.data_flows = [
            {"source": "Frontend", "destination": "Backend", "dataType": "PII, Credentials"},
            {"source": "Backend", "destination": "Database", "dataType": "User Data, Orders"},
            {"source": "Backend", "destination": "Payment Gateway", "dataType": "Payment Details"}
        ]
        st.session_state.trust_boundaries = [
            {"name": "Frontend Boundary", "description": "Untrusted client-side React app"},
            {"name": "Backend Boundary", "description": "Trusted Node.js API and MySQL database"},
            {"name": "Payment Gateway Boundary", "description": "External Stripe service"}
        ]
        st.session_state.threat_model = None
        st.session_state.error = ""
        st.session_state.generated_diagram = None
        save_session()
        st.rerun()

# Render the current step
if st.session_state.step == 1:
    step_1()
elif st.session_state.step == 2:
    step_2()
elif st.session_state.step == 3:
    step_3()

# Footer
st.markdown("---\n*Enterprise Threat Modeling | Aligned with [OWASP](https://owasp.org/www-community/Threat_Modeling_Process)*")
