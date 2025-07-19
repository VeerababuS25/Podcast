import streamlit as st
import base64
import re
from graphviz import Digraph, ExecutableNotFound

# Streamlit app configuration
st.set_page_config(page_title="Threat Modeling 101", page_icon="🔒", layout="wide")

# Initialize session state
if 'step' not in st.session_state:
    st.session_state.step = 1
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
st.title("Threat Modeling 101: E-commerce Example with Enhanced DFD")
st.markdown("""
Welcome to *Threat Modeling 101*! This app teaches you how to identify and mitigate security threats using the **STRIDE** framework, focusing on **Data Flow** and **Trust Boundaries**. Threats are assigned numeric IDs (e.g., T1, T2) and mapped to a refined Data Flow Diagram (DFD) with improved visuals.
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
st.markdown("""
**Data Flow** shows how data moves between components (e.g., browser to server). Mapping flows identifies threat locations.
""")
st.subheader("Trust Boundaries")
st.markdown("""
**Trust Boundaries** separate components with different trust levels (e.g., untrusted client vs. trusted server). Threats often occur at these boundaries.
""")
st.subheader("Threat Labeling with IDs")
st.markdown("""
Each threat is assigned a unique ID (e.g., T1, T2) and mapped to DFD elements (components, data flows, trust boundaries) with clear visuals.
""")

def generate_diagram(threats):
    """Generate a refined DFD with numbered threat IDs using Graphviz."""
    try:
        dot = Digraph(comment="Data Flow Diagram", format="png")
        dot.attr(rankdir="TB", size="10,8", fontname="Arial", bgcolor="white", splines="polyline")
        dot.attr("node", fontname="Arial", fontsize="12")
        dot.attr("edge", fontname="Arial", fontsize="10")

        # Define node styles based on component type
        node_styles = {
            "Frontend": {"shape": "oval", "style": "filled", "fillcolor": "lightcoral", "color": "red"},
            "Backend": {"shape": "box", "style": "filled", "fillcolor": "lightblue", "color": "blue"},
            "Database": {"shape": "cylinder", "style": "filled", "fillcolor": "lightblue", "color": "blue"},
            "Payment Gateway": {"shape": "oval", "style": "filled", "fillcolor": "lightgreen", "color": "green"}
        }

        # Add nodes for data flow sources and destinations
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

        # Add nodes with refined styles and threat IDs
        for node in nodes:
            threat_label = node_threats.get(node, [])
            label = f"{node}\nThreats: {', '.join(threat_label) if threat_label else 'None'}"
            style = node_styles.get(node, {"shape": "box", "style": "filled", "fillcolor": "white", "color": "black"})
            dot.node(node, label, **style, penwidth="2" if threat_label else "1")

        # Add data flow edges with threat IDs
        for flow in st.session_state.data_flows:
            edge_key = f"{flow['source']} → {flow['destination']}"
            threat_label = edge_threats.get(edge_key, [])
            label = f"{flow['dataType']}\nThreats: {', '.join(threat_label) if threat_label else 'None'}"
            dot.edge(flow["source"], flow["destination"], label=label, color="red" if threat_label else "black", penwidth="2" if threat_label else "1")

        # Add trust boundaries as subgraphs
        for boundary in st.session_state.trust_boundaries:
            with dot.subgraph(name=f"cluster_{boundary['name']}") as c:
                c.attr(label=f"{boundary['name']}\nThreats: {', '.join(node_threats.get(boundary['name'], []) or ['None'])}", 
                       style="dashed", color="purple", fontname="Arial", fontsize="12", penwidth="2")
                components = re.findall(r"\b\w+\b", boundary["description"].lower())
                for node in nodes:
                    if node.lower() in components or node.lower() in boundary["name"].lower():
                        c.node(node)

        # Render diagram to file and encode as base64
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
    """Generate a refined ASCII diagram with numbered threat IDs and a legend table."""
    # Map threats to DFD elements
    edge_threats = {}
    node_threats = {}
    threat_details = {}
    for threat in threats:
        dfd_element = threat.get("dfd_element", "")
        threat_id = threat.get("id", "")
        threat_details[threat_id] = f"{threat['type']}: {threat['description']}"
        if "→" in dfd_element:
            edge_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")
        else:
            node_threats.setdefault(dfd_element, []).append(f"{threat_id}: {threat['type']}")

    # Compact ASCII diagram
    diagram = """
    +----------------+         +----------------+         +----------------+
    |    Frontend    |<------->|    Backend     |<------->|    Database    |
    |   (React App)  |         |   (Node.js)    |         |    (MySQL)     |
    |   [Untrusted]  |         |   [Trusted]    |         |   [Trusted]    |
    | Threats: {frontend_threats} | Threats: {backend_threats} | Threats: {database_threats} |
    +----------------+         +----------------+         +----------------+
            |                          |
            |                          v
            |                   +----------------+
            |                   | Payment Gateway |
            |                   |   (Stripe)     |
            |                   | [External Trust]|
            |                   | Threats: {payment_threats} |
            |                   +----------------+
    ---- Trust Boundary ----

    Data Flow Threats:
      Frontend → Backend: {frontend_backend_threats}
      Backend → Database: {backend_database_threats}
      Backend → Payment Gateway: {backend_payment_threats}
    """

    # Generate threat legend table
    legend = "\nThreat Legend:\n"
    legend += "+-------+--------------------------+\n"
    legend += "| ID    | Threat Description       |\n"
    legend += "+-------+--------------------------+\n"
    for threat_id, description in sorted(threat_details.items()):
        legend += f"| {threat_id:<5} | {description:<24} |\n"
    legend += "+-------+--------------------------+\n"

    return diagram.format(
        frontend_threats=", ".join(node_threats.get("Frontend", ["None"])),
        backend_threats=", ".join(node_threats.get("Backend", ["None"])),
        database_threats=", ".join(node_threats.get("Database", ["None"])),
        payment_threats=", ".join(node_threats.get("Payment Gateway", ["None"])),
        frontend_backend_threats=", ".join(edge_threats.get("Frontend → Backend", ["None"])),
        backend_database_threats=", ".join(edge_threats.get("Backend → Database", ["None"])),
        backend_payment_threats=", ".join(edge_threats.get("Backend → Payment Gateway", ["None"]))
    ) + legend

def analyze_threats():
    """Perform STRIDE-based threat analysis with numbered threat IDs."""
    threats = []
    threat_counter = 1

    def add_threat(threat_type, description, stride, mitigation, asvs, samm, dfd_element, controls=None):
        nonlocal threat_counter
        threat = {
            "id": f"T{threat_counter}",
            "type": threat_type,
            "description": description,
            "stride": stride,
            "mitigation": mitigation,
            "asvs": asvs,
            "samm": samm,
            "dfd_element": dfd_element
        }
        if controls:
            threat["controls"] = controls
        threats.append(threat)
        threat_counter += 1

    # Predefined e-commerce threats
    add_threat(
        "Spoofing",
        "Hackers impersonate users by stealing credentials.",
        "Spoofing",
        "Implement multi-factor authentication and secure session management.",
        "V2.1.1 - Verify strong authentication; V2.7.1 - Verify session management.",
        "Threat Assessment Level 1 - Identify authentication risks; Governance Level 2 - Define policies.",
        "Frontend → Backend",
        controls="Use MFA (e.g., TOTP) and HTTP-only, Secure cookies."
    )
    add_threat(
        "Tampering",
        "Users modify cart data (e.g., price).",
        "Tampering",
        "Validate inputs server-side and use signed tokens for integrity.",
        "V5.1.3 - Verify input validation; V5.3.4 - Verify secure queries.",
        "Secure Architecture Level 1 - Define security requirements; Design Level 2 - Integrity controls.",
        "Frontend → Backend",
        controls="Use HMAC-SHA256 for data integrity and whitelist input validation."
    )
    add_threat(
        "Repudiation",
        "Users deny placing orders due to missing logs.",
        "Repudiation",
        "Log all user actions with timestamps and IDs.",
        "V7.1.1 - Verify logging controls; V7.2.1 - Verify log integrity.",
        "Security Operations Level 2 - Enable audit logging; Incident Management Level 2 - Monitor logs.",
        "Backend → Database",
        controls="Use AWS CloudTrail for logging and ensure log integrity."
    )
    add_threat(
        "Information Disclosure",
        "Sensitive data exposed in transit or storage.",
        "Information Disclosure",
        "Use HTTPS and encrypt sensitive database fields.",
        "V9.1.1 - Verify secure communication; V4.1.3 - Verify access controls.",
        "Implementation Level 2 - Secure data handling; Operations Level 2 - Protect data.",
        "Backend → Database",
        controls="Enable TLS 1.3 and use AES-256 for database encryption."
    )
    add_threat(
        "Information Disclosure",
        "Payment details exposed in transit to third-party service.",
        "Information Disclosure",
        "Use HTTPS and secure API tokens for third-party communication.",
        "V9.1.1 - Verify secure communication; V13.2.1 - Verify API security.",
        "Implementation Level 2 - Secure data handling; Operations Level 2 - Protect data.",
        "Backend → Payment Gateway",
        controls="Use TLS 1.3 and OAuth 2.0 for Stripe API."
    )
    add_threat(
        "Denial of Service",
        "Flooding disrupts availability.",
        "Denial of Service",
        "Implement rate limiting and use a CDN for traffic spikes.",
        "V1.10.1 - Verify anti-DoS controls; V13.1.1 - Verify API resilience.",
        "Incident Management Level 2 - Monitor for DoS; Operations Level 2 - Ensure availability.",
        "Frontend → Backend",
        controls="Configure rate limiting (100 requests/min) and use AWS CloudFront."
    )
    add_threat(
        "Elevation of Privilege",
        "Weak role-based access controls allow privilege escalation.",
        "Elevation of Privilege",
        "Enforce strict RBAC and validate roles server-side.",
        "V4.2.1 - Verify RBAC; V4.2.2 - Verify segregation of duties.",
        "Secure Architecture Level 2 - Implement RBAC; Governance Level 2 - Audit permissions.",
        "Backend",
        controls="Use AWS IAM roles with least privilege."
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
                controls="Use OAuth 2.0 with PKCE and RS256 JWT signing."
            )
        add_threat(
            "Tampering",
            f"Data integrity risk in flow from {source} to {destination}.",
            "Tampering",
            "Use digital signatures and validate inputs at destination.",
            "V5.1.4 - Verify data integrity; V5.2.2 - Verify input sanitization.",
            "Design Level 2 - Integrity controls; Verification Level 1 - Validate inputs.",
            edge_key,
            controls="Apply HMAC-SHA256 and schema-based validation."
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
                controls="Use TLS 1.3 and data masking for logs."
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
                controls="Use mutual TLS with client certificates."
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
                controls="Apply SHA-256 checksums and OWASP guidelines."
            )

    return {"threats": threats}

def step_1():
    st.header("Step 1: Provide System Details")
    st.markdown("""
    **Default Example**: E-commerce web app with a React frontend, Node.js backend, MySQL database, and Stripe payment gateway.
    Feel free to use this example or describe your own system below.
    """)
    st.session_state.text_input = st.text_area(
        "Describe your system architecture (e.g., components, technologies, public-facing, third-party services)",
        st.session_state.text_input,
        height=200
    )
    uploaded_file = st.file_uploader("Upload a Data Flow Diagram (e.g., PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        st.session_state.diagram = base64.b64encode(uploaded_file.read()).decode("utf-8")
        st.image(uploaded_file, caption="Uploaded Data Flow Diagram")
    if st.button("Next"):
        if st.session_state.text_input or st.session_state.diagram:
            st.session_state.step = 2
            st.rerun()
        else:
            st.session_state.error = "Please provide a system description or diagram."

def step_2():
    st.header("Step 2: Define Data Flows and Trust Boundaries")
    st.markdown("""
    **Default E-commerce Data Flows**:
    - Frontend → Backend (User Input: PII, Credentials)
    - Backend → Database (User Data, Orders)
    - Backend → Payment Gateway (Payment Details)

    **Default Trust Boundaries**:
    - Frontend Boundary: Untrusted client-side React app
    - Backend Boundary: Trusted server-side Node.js API and MySQL database
    - Payment Gateway Boundary: External third-party Stripe service

    Modify or add new data flows and trust boundaries below.
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
            st.image(f"data:image/png;base64,{diagram}", caption="Refined Data Flow Diagram with Numbered Threat IDs", width=800)
        else:
            st.markdown("**Refined ASCII Diagram with Numbered Threat IDs**:")
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
    st.header("Step 3: Threat Model Results")
    st.markdown("Below are the identified threats, labeled with numeric IDs (e.g., T1, T2) and mapped to Data Flow Diagram (DFD) elements. Refer to the DFD for threat locations.")
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
                    st.markdown(f"- **Mitigation**: {threat['mitigation']}")
                    if "controls" in threat:
                        st.markdown(f"- **Security Controls**: {threat['controls']}")
                    st.markdown(f"- **OWASP ASVS**: {threat['asvs']}")
                    st.markdown(f"- **OWASP SAMM**: {threat['samm']}")
                    st.markdown(f"- **DFD Element**: {threat['dfd_element']}")

    if st.session_state.generated_diagram:
        st.subheader("Refined Data Flow Diagram with Numbered Threat IDs")
        st.image(f"data:image/png;base64,{st.session_state.generated_diagram}", caption="Refined Data Flow Diagram with Numbered Threat IDs", width=800)
    else:
        st.markdown("**Refined ASCII Diagram with Numbered Threat IDs**:")
        st.code(fallback_ascii_diagram(st.session_state.threat_model.get("threats", [])), language="text")
    if st.button("Start Over"):
        st.session_state.step = 1
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

# Section: Tips for Threat Modeling
st.header("Tips for Effective Threat Modeling")
st.markdown("""
1. **Map Data Flows**: Diagram data movement to identify vulnerabilities.
2. **Define Trust Boundaries**: Mark trust level changes (e.g., client to server).
3. **Apply STRIDE**: Analyze components and flows systematically.
4. **Use Numbered Threat IDs**: Map threats to DFD elements with IDs (e.g., T1, T2).
5. **Involve the Team**: Include developers, designers, and stakeholders.
6. **Iterate**: Update the threat model as the system evolves.
7. **Document**: Record threats, mitigations, and DFD mappings.
""")

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
*Built with Streamlit | Learn more at [OWASP](https://owasp.org/www-community/Threat_Modeling) or [Microsoft STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats).*
""")
