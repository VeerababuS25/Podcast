import streamlit as st
import base64
import re
from graphviz import Digraph, ExecutableNotFound

# Streamlit app configuration
st.set_page_config(page_title="OWASP Threat Modeling", page_icon="🔒", layout="wide")

# Initialize session state
if 'step' not in st.session_state:
    st.session_state.step = 1
if 'scope' not in st.session_state:
    st.session_state.scope = {
        "assets": "User data (PII), payment details, order history",
        "objectives": "Ensure confidentiality of PII, integrity of orders, availability of services",
        "compliance": "GDPR, PCI-DSS"
    }
if 'text_input' not in st.session_state:
    st.session_state.text_input = (
        "E-commerce web app with a React frontend, Node.js backend API, MySQL database, and Stripe payment gateway. "
        "The app is public-facing, handles user authentication, and processes sensitive data like PII and payment details."
    )
if 'diagram' not in st.session_state:
    st.session_state.diagram = None
if 'data_flows' not in st.session_state:
    st.session_state.data_flows = [
        {"source": "Frontend", "destination": "Backend", "dataType": "User Input (PII, Credentials)"},
        {"source": "Backend", "destination": "Database", "dataType": "User Data, Orders"},
        {"source": "Backend", "destination": "Payment Gateway", "dataType": "Payment Details"}
    ]
if 'trust_boundaries' not in st.session_state:
    st.session_state.trust_boundaries = [
        {"name": "Frontend Boundary", "description": "Untrusted client-side React app running on user devices"},
        {"name": "Backend Boundary", "description": "Trusted server-side Node.js API and MySQL database"},
        {"name": "Payment Gateway Boundary", "description": "External third-party Stripe service"}
    ]
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = None
if 'error' not in st.session_state:
    st.session_state.error = ""
if 'generated_diagram' not in st.session_state:
    st.session_state.generated_diagram = None

# Title and introduction
st.title("OWASP Threat Modeling: E-commerce Example")
st.markdown("""
Welcome to *OWASP Threat Modeling*! This app follows the OWASP Threat Modeling Process to identify and mitigate security threats using the **STRIDE** framework. It focuses on **Data Flows**, **Trust Boundaries**, and **Assets**, with threats assigned numeric IDs (e.g., T1, T2) and mapped to a refined Data Flow Diagram (DFD).
""")

# Section: OWASP Process Overview
st.header("OWASP Threat Modeling Process")
st.markdown("""
This app implements the four-step OWASP Threat Modeling Process:
1. **Define Scope and Objectives**: Identify assets, security objectives (e.g., CIA triad), and compliance requirements.
2. **Decompose the Application**: Map data flows, trust boundaries, and components in a DFD.
3. **Identify Threats**: Use STRIDE to find threats across components, flows, and boundaries.
4. **Identify and Prioritize Mitigations**: Assign mitigations, prioritize by risk (likelihood and impact), and map to OWASP ASVS/SAMM.
""")

# Section: Key Concepts
st.header("Key Concepts")
st.subheader("STRIDE Framework")
st.markdown("""
**STRIDE** categorizes threats:
- **Spoofing**: Impersonating a user/system (e.g., stealing credentials).
- **Tampering**: Modifying data/code (e.g., altering prices).
- **Repudiation**: Avoiding accountability (e.g., disabling logs).
- **Information Disclosure**: Exposing sensitive data (e.g., leaking PII).
- **Denial of Service**: Disrupting availability (e.g., flooding a server).
- **Elevation of Privilege**: Gaining unauthorized access (e.g., becoming admin).
""")
st.subheader("Data Flow")
st.markdown("**Data Flow** shows how data moves between components (e.g., browser to server).")
st.subheader("Trust Boundaries")
st.markdown("**Trust Boundaries** separate components with different trust levels (e.g., client vs. server).")
st.subheader("Assets and Objectives")
st.markdown("**Assets** (e.g., PII, payment details) and **Security Objectives** (e.g., confidentiality, integrity) define what to protect.")
st.subheader("Threat IDs and Prioritization")
st.markdown("Threats are assigned IDs (e.g., T1, T2) and prioritized by risk (likelihood × impact) for mitigation focus.")

def generate_diagram(threats):
    """Generate a refined DFD with numbered threat IDs and assets using Graphviz."""
    try:
        dot = Digraph(comment="Data Flow Diagram", format="png")
        dot.attr(rankdir="TB", size="10,8", fontname="Arial", bgcolor="white", splines="polyline")
        dot.attr("node", fontname="Arial", fontsize="12")
        dot.attr("edge", fontname="Arial", fontsize="10")

        # Define node styles
        node_styles = {
            "Frontend": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral", "color": "red"},
            "Backend": {"shape": "box", "style": "filled", "fillcolor": "lightblue", "color": "blue"},
            "Database": {"shape": "cylinder", "style": "filled", "fillcolor": "lightblue", "color": "blue"},
            "Payment Gateway": {"shape": "oval", "style": "filled", "fillcolor": "lightgreen", "color": "green"}
        }

        # Add nodes
        nodes = set()
        for flow in st.session_state.data_flows:
            nodes.add(flow["source"])
            nodes.add(flow["destination"])
        
        # Map threats to nodes and edges
        node_threats = {}
        edge_threats = {}
        for threat in threats:
            dfd_element = threat.get("dfd_element", "")
            threat_id = threat.get("id", "")
            if "→" in dfd_element:
                edge_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")
            else:
                node_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")

        # Add nodes with threat IDs and assets
        assets = st.session_state.scope.get("assets", "").lower()
        for node in nodes:
            threat_label = node_threats.get(node, [])
            asset_info = "Assets: PII" if node.lower() in assets else "Assets: None"
            label = f"{node}\n{asset_info}\nThreats: {', '.join(threat_label) if threat_label else 'None'}"
            style = node_styles.get(node, {"shape": "box", "style": "filled", "fillcolor": "white", "color": "black"})
            dot.node(node, label, **style, penwidth="2" if threat_label else "1")

        # Add data flow edges
        for flow in st.session_state.data_flows:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_label = edge_threats.get(edge_key, [])
            label = f"{flow['dataType']}\nThreats: {', '.join(threat_label) if threat_label else 'None'}"
            dot.edge(flow["source"], flow["destination"], label=label, color="red" if threat_label else "black", penwidth="2" if threat_label else "1")

        # Add trust boundaries
        for boundary in st.session_state.trust_boundaries:
            with dot.subgraph(name=f"cluster_{boundary['name']}") as c:
                c.attr(label=f"{boundary['name']}\nThreats: {', '.join(node_threats.get(boundary['name'], []) or ['None'])}", 
                       style="dashed", color="purple", fontname="Arial", fontsize="12", penwidth="2")
                components = re.findall(r"\b\w+\b", boundary["description"].lower())
                for node in nodes:
                    if node.lower() in components or node.lower() in boundary["name"].lower():
                        c.node(node)

        # Render diagram
        diagram_path = dot.render("diagram", format="png", cleanup=True)
        with open(diagram_path, "rb") as f:
            st.session_state.generated_diagram = base64.b64encode(f.read()).decode("utf-8")
        return st.session_state.generated_diagram
    except ExecutableNotFound:
        st.session_state.error = "Graphviz executable not found. Falling back to ASCII diagram with numbered threat IDs."
        return None
    except Exception as e:
        st.session_state.error = f"Failed to generate diagram: {str(e)}"
        return None

def fallback_ascii_diagram(threats):
    """Generate a refined ASCII diagram with numbered threat IDs and assets."""
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
    """Perform STRIDE-based threat analysis with risk prioritization."""
    threats = []
    threat_counter = 1

    def add_threat(threat_type, description, stride, mitigation, asvs, samm, dfd_element, controls=None, likelihood="Medium", impact="High"):
        nonlocal threat_counter
        risk_score = {"Low": 1, "Medium": 2, "High": 3}
        priority = risk_score[likelihood] * risk_score[impact]
        priority_label = "High" if priority >= 6 else "Medium" if priority >= 3 else "Low"
        threat = {
            "id": f"T{threat_counter}",
            "type": threat_type,
            "description": description,
            "stride": stride,
            "mitigation": mitigation,
            "asvs": asvs,
            "samm": samm,
            "dfd_element": dfd_element,
            "likelihood": likelihood,
            "impact": impact,
            "priority": priority_label
        }
        if controls:
            threat["controls"] = controls
        threats.append(threat)
        threat_counter += 1

    # Analyze scope and objectives
    scope = st.session_state.scope
    assets = scope.get("assets", "").lower()
    objectives = scope.get("objectives", "").lower()
    is_public_facing = "public-facing" in st.session_state.text_input.lower()

    # STRIDE threats based on assets and objectives
    if "pii" in assets or "payment details" in assets:
        add_threat(
            "Information Disclosure",
            "Sensitive data (PII, payment details) exposed due to weak encryption.",
            "Information Disclosure",
            "Encrypt data at rest (AES-256) and in transit (TLS 1.3).",
            "V9.1.1 - Verify secure communication; V4.1.3 - Verify access controls.",
            "Implementation Level 2 - Secure data handling; Operations Level 2 - Protect data.",
            "Backend → Database",
            controls="Use AWS KMS for key management and TLS 1.3.",
            likelihood="High" if is_public_facing else "Medium",
            impact="High"
        )
    if "confidentiality" in objectives:
        add_threat(
            "Spoofing",
            "Impersonation of users to access sensitive data.",
            "Spoofing",
            "Implement MFA and secure session management.",
            "V2.1.1 - Verify strong authentication; V2.7.1 - Verify session management.",
            "Threat Assessment Level 1 - Identify risks; Governance Level 2 - Define policies.",
            "Frontend → Backend",
            controls="Use MFA (TOTP) and HTTP-only, Secure cookies.",
            likelihood="High" if is_public_facing else "Medium",
            impact="High"
        )
    if "integrity" in objectives:
        add_threat(
            "Tampering",
            "Modification of order data affecting integrity.",
            "Tampering",
            "Use digital signatures and server-side validation.",
            "V5.1.3 - Verify input validation; V5.3.4 - Verify secure queries.",
            "Secure Architecture Level 1 - Define requirements; Design Level 2 - Integrity controls.",
            "Backend → Database",
            controls="Apply HMAC-SHA256 and whitelist validation.",
            likelihood="Medium",
            impact="High"
        )
    if "availability" in objectives:
        add_threat(
            "Denial of Service",
            "Flooding disrupts service availability.",
            "Denial of Service",
            "Implement rate limiting and use a CDN (e.g., AWS CloudFront).",
            "V1.10.1 - Verify anti-DoS controls; V13.1.1 - Verify API resilience.",
            "Incident Management Level 2 - Monitor for DoS; Operations Level 2 - Ensure availability.",
            "Frontend → Backend",
            controls="Set rate limits (100 requests/min) and enable auto-scaling.",
            likelihood="High" if is_public_facing else "Medium",
            impact="High"
        )

    # Predefined e-commerce threats
    add_threat(
        "Spoofing",
        "Hackers impersonate users by stealing credentials.",
        "Spoofing",
        "Implement MFA and secure session management.",
        "V2.1.1 - Verify strong authentication; V2.7.1 - Verify session management.",
        "Threat Assessment Level 1 - Identify risks; Governance Level 2 - Define policies.",
        "Frontend → Backend",
        controls="Use MFA (TOTP) and HTTP-only, Secure cookies.",
        likelihood="High" if is_public_facing else "Medium",
        impact="High"
    )
    add_threat(
        "Tampering",
        "Users modify cart data (e.g., price).",
        "Tampering",
        "Validate inputs server-side and use signed tokens.",
        "V5.1.3 - Verify input validation; V5.3.4 - Verify secure queries.",
        "Secure Architecture Level 1 - Define requirements; Design Level 2 - Integrity controls.",
        "Frontend → Backend",
        controls="Use HMAC-SHA256 for integrity and whitelist validation.",
        likelihood="Medium",
        impact="High"
    )
    add_threat(
        "Repudiation",
        "Users deny placing orders due to missing logs.",
        "Repudiation",
        "Log all user actions with timestamps and IDs.",
        "V7.1.1 - Verify logging controls; V7.2.1 - Verify log integrity.",
        "Security Operations Level 2 - Enable audit logging; Incident Management Level 2 - Monitor logs.",
        "Backend → Database",
        controls="Use AWS CloudTrail for logging and ensure log integrity.",
        likelihood="Low",
        impact="Medium"
    )
    add_threat(
        "Information Disclosure",
        "Payment details exposed to third-party service.",
        "Information Disclosure",
        "Use HTTPS and secure API tokens for third-party communication.",
        "V9.1.1 - Verify secure communication; V13.2.1 - Verify API security.",
        "Implementation Level 2 - Secure data handling; Operations Level 2 - Protect data.",
        "Backend → Payment Gateway",
        controls="Use TLS 1.3 and OAuth 2.0 for Stripe API.",
        likelihood="High" if is_public_facing else "Medium",
        impact="High"
    )
    add_threat(
        "Elevation of Privilege",
        "Weak RBAC allows privilege escalation.",
        "Elevation of Privilege",
        "Enforce strict RBAC and validate roles server-side.",
        "V4.2.1 - Verify RBAC; V4.2.2 - Verify segregation of duties.",
        "Secure Architecture Level 2 - Implement RBAC; Governance Level 2 - Audit permissions.",
        "Backend",
        controls="Use AWS IAM roles with least privilege.",
        likelihood="Medium",
        impact="High"
    )

    # Analyze user-defined data flows
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
                "V2.1.2 - Verify identity validation; V2.7.3 - Verify session binding.",
                "Threat Assessment Level 1 - Identify risks; Governance Level 2 - Enforce policies.",
                edge_key,
                controls="Use OAuth 2.0 with PKCE and RS256 JWT signing.",
                likelihood="High" if is_public_facing else "Medium",
                impact="High"
            )
        add_threat(
            "Tampering",
            f"Data integrity risk in flow from {source} to {destination}.",
            "Tampering",
            "Use digital signatures and validate inputs at destination.",
            "V5.1.4 - Verify data integrity; V5.2.2 - Verify input sanitization.",
            "Design Level 2 - Integrity controls; Verification Level 1 - Validate inputs.",
            edge_key,
            controls="Apply HMAC-SHA256 and schema-based validation.",
            likelihood="Medium",
            impact="High"
        )
        if 'pii' in data_type or 'sensitive' in data_type:
            add_threat(
                "Information Disclosure",
                f"Sensitive data ({data_type}) exposed in flow from {source} to {destination}.",
                "Information Disclosure",
                "Encrypt data with TLS 1.3 and mask sensitive data in logs.",
                "V9.1.2 - Verify encryption; V4.1.4 - Verify access restrictions.",
                "Implementation Level 2 - Secure data; Operations Level 2 - Protect data.",
                edge_key,
                controls="Use TLS 1.3 and data masking for logs.",
                likelihood="High" if is_public_facing else "Medium",
                impact="High"
            )

    # Analyze trust boundaries
    for boundary in st.session_state.trust_boundaries:
        name = boundary.get('name', '').lower()
        description = boundary.get('description', '').lower()

        if 'boundary' in name or 'frontend' in name:
            add_threat(
                "Spoofing",
                f"Cross-boundary spoofing in {name}.",
                "Spoofing",
                "Enforce mutual TLS and validate cross-boundary requests.",
                "V2.1.3 - Verify boundary authentication; V13.2.1 - Verify API security.",
                "Threat Assessment Level 2 - Model boundary risks; Governance Level 2 - Define policies.",
                boundary["name"],
                controls="Use mutual TLS with client certificates.",
                likelihood="High" if is_public_facing else "Medium",
                impact="High"
            )
        if 'database' in name or 'backend' in name:
            add_threat(
                "Tampering",
                f"Data tampering within {name} due to weak controls.",
                "Tampering",
                "Use integrity checks and secure coding practices.",
                "V5.1.3 - Verify input validation; V5.3.5 - Verify secure coding.",
                "Design Level 2 - Integrity controls; Verification Level 2 - Validate controls.",
                boundary["name"],
                controls="Apply SHA-256 checksums and OWASP guidelines.",
                likelihood="Medium",
                impact="High"
            )

    # Sort threats by priority
    threats.sort(key=lambda x: {"High": 1, "Medium": 2, "Low": 3}[x["priority"]])
    return {"threats": threats}

def step_1():
    st.header("Step 1: Define Scope and Objectives")
    st.markdown("""
    Define the assets to protect, security objectives (e.g., CIA triad: Confidentiality, Integrity, Availability), and compliance requirements (e.g., GDPR, PCI-DSS). Use the default e-commerce example or customize below.
    """)
    st.session_state.scope["assets"] = st.text_input(
        "Assets (e.g., User data, Payment details)",
        st.session_state.scope["assets"]
    )
    st.session_state.scope["objectives"] = st.text_input(
        "Security Objectives (e.g., Confidentiality, Integrity, Availability)",
        st.session_state.scope["objectives"]
    )
    st.session_state.scope["compliance"] = st.text_input(
        "Compliance Requirements (e.g., GDPR, PCI-DSS)",
        st.session_state.scope["compliance"]
    )
    st.session_state.text_input = st.text_area(
        "Describe System Architecture (e.g., components, technologies, public-facing)",
        st.session_state.text_input,
        height=200
    )
    uploaded_file = st.file_uploader("Upload a Data Flow Diagram (PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        st.session_state.diagram = base64.b64encode(uploaded_file.read()).decode("utf-8")
        st.image(uploaded_file, caption="Uploaded Data Flow Diagram")
    if st.button("Next"):
        if st.session_state.scope["assets"] and st.session_state.scope["objectives"] and (st.session_state.text_input or st.session_state.diagram):
            st.session_state.step = 2
            st.rerun()
        else:
            st.session_state.error = "Please provide assets, objectives, and a system description or diagram."

def step_2():
    st.header("Step 2: Decompose the Application")
    st.markdown("""
    Map data flows (source, destination, data type) and trust boundaries to decompose the application. Use the default e-commerce data flows and trust boundaries or add your own.
    """)
    
    st.subheader("Data Flows")
    with st.container():
        source = st.text_input("Data Flow Source (e.g., User, API)", key="data_flow_source")
        destination = st.text_input("Data Flow Destination (e.g., Database, Service)", key="data_flow_destination")
        data_type = st.text_input("Data Type (e.g., PII, Public, Confidential)", key="data_flow_type")
        if st.button("Add Data Flow"):
            if source and destination and data_type:
                st.session_state.data_flows.append({"source": source, "destination": destination, "dataType": data_type})
                st.success("Data Flow added!")
                st.rerun()
            else:
                st.session_state.error = "Please fill in all data flow fields."
    
    if st.session_state.data_flows:
        st.write("**Current Data Flows:**")
        for flow in st.session_state.data_flows:
            st.write(f"{flow['source']} → {flow['destination']} ({flow['dataType']})")

    st.subheader("Trust Boundaries")
    with st.container():
        trust_boundary_options = [
            "Web Server Boundary",
            "Database Boundary",
            "API Boundary",
            "Frontend Boundary",
            "Payment Gateway Boundary",
            "Custom"
        ]
        selected_boundary = st.selectbox("Select Trust Boundary", trust_boundary_options, key="trust_boundary_select")
        name = selected_boundary
        if selected_boundary == "Custom":
            name = st.text_input("Custom Trust Boundary Name", key="custom_boundary_name")
        description = st.text_input("Trust Boundary Description", key="boundary_description")
        if st.button("Add Trust Boundary"):
            if name and description and name != "Custom":
                st.session_state.trust_boundaries.append({"name": name, "description": description})
                st.success("Trust Boundary added!")
                st.rerun()
            else:
                st.session_state.error = "Please provide a valid trust boundary name and description."
    
    if st.session_state.trust_boundaries:
        st.write("**Current Trust Boundaries:**")
        for boundary in st.session_state.trust_boundaries:
            st.write(f"{boundary['name']}: {boundary['description']}")

    if st.session_state.data_flows or st.session_state.trust_boundaries:
        st.subheader("Preview Data Flow Diagram")
        preview_threats = analyze_threats().get("threats", [])
        diagram = generate_diagram(preview_threats)
        if diagram:
            st.image(f"data:image/png;base64,{diagram}", caption="Data Flow Diagram with Assets and Threat IDs", width=800)
        else:
            st.markdown("**ASCII Diagram with Assets and Threat IDs**:")
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
            st.session_state.error = "Please add at least one data flow or trust boundary."

def step_3():
    st.header("Step 3: Identify Threats")
    st.markdown("Threats are identified using STRIDE, labeled with IDs (e.g., T1, T2), and mapped to DFD elements.")
    if st.session_state.threat_model:
        st.subheader("Identified Threats")
        dfd_elements = {}
        for threat in st.session_state.threat_model["threats"]:
            dfd_element = threat["dfd_element"]
            dfd_elements.setdefault(dfd_element, []).append(threat)
        
        for dfd_element, threats in dfd_elements.items():
            st.markdown(f"### Threats for {dfd_element}")
            for threat in threats:
                with st.expander(f"{threat['id']}: {threat['type']} (STRIDE: {threat['stride']})"):
                    st.markdown(f"- **Description**: {threat['description']}")
                    st.markdown(f"- **Likelihood**: {threat['likelihood']}")
                    st.markdown(f"- **Impact**: {threat['impact']}")
                    st.markdown(f"- **Priority**: {threat['priority']}")
                    st.markdown(f"- **Mitigation**: {threat['mitigation']}")
                    if "controls" in threat:
                        st.markdown(f"- **Security Controls**: {threat['controls']}")
                    st.markdown(f"- **OWASP ASVS**: {threat['asvs']}")
                    st.markdown(f"- **OWASP SAMM**: {threat['samm']}")
                    st.markdown(f"- **DFD Element**: {threat['dfd_element']}")

    if st.session_state.generated_diagram:
        st.subheader("Data Flow Diagram with Assets and Threat IDs")
        st.image(f"data:image/png;base64,{st.session_state.generated_diagram}", caption="Data Flow Diagram with Assets and Threat IDs", width=800)
    else:
        st.markdown("**ASCII Diagram with Assets and Threat IDs**:")
        st.code(fallback_ascii_diagram(st.session_state.threat_model.get("threats", [])), language="text")

    st.header("Step 4: Identify and Prioritize Mitigations")
    st.markdown("Mitigations are prioritized based on risk (likelihood × impact). High-priority threats should be addressed first.")
    if st.session_state.threat_model:
        st.subheader("Prioritized Mitigations")
        for priority in ["High", "Medium", "Low"]:
            st.markdown(f"#### {priority} Priority")
            for threat in st.session_state.threat_model["threats"]:
                if threat["priority"] == priority:
                    st.markdown(f"- **{threat['id']}: {threat['type']}** (DFD: {threat['dfd_element']})")
                    st.markdown(f"  - **Mitigation**: {threat['mitigation']}")
                    if "controls" in threat:
                        st.markdown(f"  - **Controls**: {threat['controls']}")

    if st.button("Start Over"):
        st.session_state.step = 1
        st.session_state.scope = {
            "assets": "User data (PII), payment details, order history",
            "objectives": "Ensure confidentiality of PII, integrity of orders, availability of services",
            "compliance": "GDPR, PCI-DSS"
        }
        st.session_state.text_input = (
            "E-commerce web app with a React frontend, Node.js backend API, MySQL database, and Stripe payment gateway. "
            "The app is public-facing, handles user authentication, and processes sensitive data like PII and payment details."
        )
        st.session_state.diagram = None
        st.session_state.data_flows = [
            {"source": "Frontend", "destination": "Backend", "dataType": "User Input (PII, Credentials)"},
            {"source": "Backend", "destination": "Database", "dataType": "User Data, Orders"},
            {"source": "Backend", "destination": "Payment Gateway", "dataType": "Payment Details"}
        ]
        st.session_state.trust_boundaries = [
            {"name": "Frontend Boundary", "description": "Untrusted client-side React app running on user devices"},
            {"name": "Backend Boundary", "description": "Trusted server-side Node.js API and MySQL database"},
            {"name": "Payment Gateway Boundary", "description": "External third-party Stripe service"}
        ]
        st.session_state.threat_model = None
        st.session_state.error = ""
        st.session_state.generated_diagram = None
        st.rerun()
    if st.session_state.error:
        st.error(st.session_state.error)

# Render the current step
if st.session_state.step == 1:
    step_1()
elif st.session_state.step == 2:
    step_2()
elif st.session_state.step == 3:
    step_3()

# Footer
st.markdown("""
---
*Built with Streamlit | Aligned with [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling_Process).*
""")
