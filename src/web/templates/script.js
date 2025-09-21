document.addEventListener('DOMContentLoaded', function () {
    const nodes = new vis.DataSet([]);
    const edges = new vis.DataSet([]);
    const container = document.getElementById('mynetwork');
    const infoPanel = document.getElementById('info-panel');
    const infoContent = document.getElementById('info-content');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const clearBtn = document.getElementById('clear-btn');
    const statusIndicator = document.getElementById('status-indicator');
    const searchInput = document.getElementById('search-input');
    const data = { nodes: nodes, edges: edges };

    const options = {
        nodes: {
            shape: 'icon', borderWidth: 2,
            font: { size: 12, color: '#c9d1d9', face: 'Roboto Mono' },
            shadow: { enabled: true, color: 'rgba(88, 166, 255, 0.3)', size: 15 }
        },
        edges: {
            width: 0.5, 
            scaling: {
                min: 0.5,
                max: 0.5 
            },
            color: {
                color: 'rgba(137, 147, 158, 0.4)',
                highlight: '#58a6ff',
                hover: '#58a6ff',
                inherit: false
            },
            arrows: { to: { enabled: true, scaleFactor: 0.4, type: 'arrow' } },
            smooth: { enabled: true, type: "dynamic" }
        },
        physics: {
            enabled: true, solver: 'barnesHut',
            barnesHut: { gravitationalConstant: -15000, centralGravity: 0.15, springLength: 150, springConstant: 0.05, damping: 0.3 },
            stabilization: { iterations: 1500 }
        },
        interaction: { hover: true, tooltipDelay: 200, hideEdgesOnDrag: true, navigationButtons: true }
    };
    const network = new vis.Network(container, data, options);

    startBtn.addEventListener('click', () => fetch('/start_capture', { method: 'POST' }));
    stopBtn.addEventListener('click', () => fetch('/stop_capture', { method: 'POST' }));
    clearBtn.addEventListener('click', () => {
        fetch('/clear_data', { method: 'POST' }).then(() => {
            nodes.clear(); edges.clear(); infoPanel.classList.remove('visible'); resetEdgeStyles();
        });
    });

    network.on("click", params => {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            highlightPaths(nodeId);
            displayNodeInfo(nodeId);
        } else {
            resetEdgeStyles();
            infoPanel.classList.remove('visible');
        }
    });
    const defaultEdgeColor = 'rgba(137, 147, 158, 0.4)';
    const outgoingEdgeColor = '#58a6ff';
    const incomingEdgeColor = '#a371f7';

    function resetEdgeStyles() {
        // Resets all edge colors to default.
      
        const allEdges = edges.get({ returnType: "Object" });
        const updates = [];
        for (let id in allEdges) {
            updates.push({ id: id, color: defaultEdgeColor });
        }
        if (updates.length > 0) {
            edges.update(updates);
        }
    }

    function highlightPaths(nodeId) {
        // Highlights incoming and outgoing edges of a node.
      
        resetEdgeStyles();

        const connectedEdges = network.getConnectedEdges(nodeId);
        const updates = [];
        
        connectedEdges.forEach(edgeId => {
            const edge = edges.get(edgeId);
            if (edge.from === nodeId) {
                updates.push({ id: edgeId, color: outgoingEdgeColor });
            } else if (edge.to === nodeId) {
                updates.push({ id: edgeId, color: incomingEdgeColor });
            }
        });

        if (updates.length > 0) {
            edges.update(updates);
        }
    }
    
    function formatBytes(bytes, decimals = 2) { /* ... same as before ... */ }
    async function displayNodeInfo(nodeId) { /* ... same as before ... */ }
    async function updateData() { /* ... same as before ... */ }
    async function checkStatus() { /* ... same as before ... */ }

    function formatBytes(bytes, decimals = 2) {
        // Converts bytes into human-readable units.
      
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    async function displayNodeInfo(nodeId) {
        // Fetches and displays information about a node.
      
        try {
            const response = await fetch(`/node_info/${nodeId}`);
            if (!response.ok) {
                infoContent.innerHTML = `<h2>Error</h2><p>Could not fetch details.</p>`;
                infoPanel.classList.add('visible');
                return;
            }
            const info = await response.json();
            
            let html = `<h2>${info.hostname}</h2>`;
            if (info.hostname !== info.ip) html += `<span class="hostname">(${info.ip})</span>`;

            html += `<h3>Details</h3><ul>`;
            if (info.details.mac_address) {
                html += `<li>MAC: <span>${info.details.mac_address}</span></li>`;
                html += `<li>Vendor: <span>${info.details.vendor}</span></li>`;
            }
            if (info.details.owner) html += `<li>Owner: <span>${info.details.owner}</span></li>`;
            if (info.details.is_malicious === true) {
                html += `<li>Status: <span style="color: #f85149; font-weight: bold;">&#9888; Malicious IP</span></li>`;
            } else if (info.details.is_malicious === false) {
                 html += `<li>Status: <span style="color: #3fb950;">Clean</span></li>`;
            }
            html += `</ul>`;

            html += `<h3>Incoming (${info.incoming_details.length})</h3><ul>`;
            if (info.incoming_details.length === 0) html += `<li>No incoming traffic recorded.</li>`;
            info.incoming_details.forEach(inc => {
                const protocols = Object.entries(inc.protocols).map(([p, c]) => `${p}(${c})`).join(', ');
                html += `<li>From: <span>${inc.from_host}</span><br>
                         Data: ${formatBytes(inc.total_size)} | Packets: ${inc.weight}<br>
                         <span class="protocol-list">${protocols}</span></li>`;
            });
            html += `</ul>`;
            
            html += `<h3>Outgoing (${info.outgoing_details.length})</h3><ul>`;
            if (info.outgoing_details.length === 0) html += `<li>No outgoing traffic recorded.</li>`;
            info.outgoing_details.forEach(out => {
                const protocols = Object.entries(out.protocols).map(([p, c]) => `${p}(${c})`).join(', ');
                html += `<li>To: <span>${out.to_host}</span><br>
                         Data: ${formatBytes(out.total_size)} | Packets: ${out.weight}<br>
                         <span class="protocol-list">${protocols}</span></li>`;
            });
            html += `</ul>`;
            
            infoContent.innerHTML = html;
            infoPanel.classList.add('visible');
        } catch (error) { console.error("Failed to display node info:", error); }
    }
    
    async function updateData() {
        // Fetches and updates graph nodes and edges from backend.
        
        try {
            const response = await fetch('/data');
            const graphData = await response.json();
            const processedNodes = graphData.nodes.map(node => {
                let iconCode, iconColor, borderColor;
                if (node.is_malicious) {
                    iconCode = '\uf71c'; iconColor = '#f85149'; borderColor = '#f85149';
                } else {
                    switch (node.node_type) {
                        case 'my_device':
                            iconCode = '\uf109'; iconColor = '#c9d1d9'; borderColor = '#c9d1d9'; break;
                        case 'local_device':
                            iconCode = '\uf233'; iconColor = '#f0883e'; borderColor = '#f0883e'; break;
                        default:
                            iconCode = '\uf0c2'; iconColor = '#58a6ff'; borderColor = '#58a6ff'; break;
                    }
                }
                return {
                    ...node,
                    shape: 'icon',
                    icon: { face: "'Font Awesome 6 Free'", weight: "900", code: iconCode, size: 30, color: iconColor },
                    color: { border: borderColor, background: '#161b22' }
                };
            });
            nodes.update(processedNodes);
            edges.update(graphData.edges);
        } catch (error) { console.error('Error fetching graph data:', error); }
    }

    async function checkStatus() {
        // Checks the status of the backend service.
        
        try {
            const response = await fetch('/status');
            const status = await response.json();
            statusIndicator.className = status.is_running ? 'status-indicator status-running' : 'status-indicator status-stopped';
        } catch (error) { statusIndicator.className = 'status-indicator status-stopped'; }
    }
    
    searchInput.addEventListener('keyup', (e) => {
        const query = e.target.value.toLowerCase();
        if (query === "") { network.unselectAll(); network.fit(); resetEdgeStyles(); return; }
        const matchingNodes = nodes.get({
            filter: node => (node.label || '').toLowerCase().includes(query) || (node.id || '').toLowerCase().includes(query)
        });
        if (matchingNodes.length > 0) {
            const nodeIds = matchingNodes.map(n => n.id);
            network.selectNodes(nodeIds);
            network.focus(nodeIds[0], { scale: 1.2, animation: true });
        } else { network.unselectAll(); }
    });

    const updateInterval = parseInt(container.dataset.updateInterval, 10) || 5000;
    setInterval(updateData, updateInterval);
    setInterval(checkStatus, 3000);
    updateData();
    checkStatus();
});