# Create an improved comprehensive WAF system architecture diagram
diagram_code = """
flowchart LR
    %% Web Traffic Layer
    WT[🌐 Web Traffic<br/>HTTP/HTTPS] --> WS[🖥️ Apache/Nginx<br/>Web Servers]
    
    %% Log Ingestion Layer
    WS --> LI1[📥 Batch Ingestion]
    WS --> LI2[🔄 Stream Ingestion]
    LI1 --> LP
    LI2 --> LP
    
    %% Data Processing Pipeline
    LP[⚙️ Log Parser<br/>& Normalizer] --> FE[🔧 Feature Extract<br/>& Tokenizer]
    FE --> SP[📋 Sequence Prep<br/>Transformer Ready]
    
    %% AI/ML Core
    SP --> BERT[🧠 BERT Model<br/>Pre-trained]
    BERT --> AD[🔍 Anomaly Detect<br/>Engine]
    AD --> IL[📈 Incremental<br/>Learning]
    
    %% Decision Engine
    IL --> RS[⚖️ Risk Scoring<br/>Engine]
    RS --> TA[🚨 Threshold Alert<br/>& Actions]
    TA --> RESP{🛡️ Response<br/>Decision}
    RESP --> BLOCK[❌ Block Request]
    RESP --> ALLOW[✅ Allow Request]
    RESP --> ALERT[⚠️ Generate Alert]
    
    %% Integration Points
    API[🔌 API Endpoints<br/>Integration] --> WS
    MS[🏗️ Microservices<br/>Architecture] --> API
    
    %% Response Flow (distinct styling)
    BLOCK -.->|Block Response| WS
    ALLOW -.->|Allow Response| WS
    ALERT -.->|Alert Response| WS
    
    %% Monitoring & Management Layer
    DASH[📊 Dashboard<br/>Interface]
    LOG[📝 Logging<br/>& Metrics]
    PERF[📈 Model Performance<br/>Monitor]
    
    RS --> DASH
    IL --> PERF
    TA --> LOG
    PERF --> DASH
    LOG --> DASH
    
    %% Styling for different layers
    classDef traffic fill:#B3E5EC,stroke:#1FB8CD,stroke-width:2px
    classDef web fill:#FFCDD2,stroke:#DB4545,stroke-width:2px
    classDef ingestion fill:#A5D6A7,stroke:#2E8B57,stroke-width:2px
    classDef processing fill:#9FA8B0,stroke:#5D878F,stroke-width:2px
    classDef ai fill:#FFEB8A,stroke:#D2BA4C,stroke-width:2px
    classDef decision fill:#E8C5A0,stroke:#B4413C,stroke-width:2px
    classDef monitoring fill:#D4A5C7,stroke:#944454,stroke-width:2px
    classDef integration fill:#C8E6C9,stroke:#964325,stroke-width:2px
    
    %% Apply classes
    class WT traffic
    class WS web
    class LI1,LI2 ingestion
    class LP,FE,SP processing
    class BERT,AD,IL ai
    class RS,TA,RESP,BLOCK,ALLOW,ALERT decision
    class API,MS integration
    class DASH,LOG,PERF monitoring
"""

# Create the improved diagram and save as both PNG and SVG
png_path, svg_path = create_mermaid_diagram(
    diagram_code, 
    'waf_architecture_improved.png', 
    'waf_architecture_improved.svg',
    width=1600,
    height=1000
)

print(f"Improved WAF Architecture diagram saved as:")
print(f"PNG: {png_path}")
print(f"SVG: {svg_path}")