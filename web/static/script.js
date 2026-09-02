document.addEventListener("DOMContentLoaded", function () {
  const nodes = new vis.DataSet([]);
  const edges = new vis.DataSet([]);
  const container = document.getElementById("mynetwork");
  const nodeCache = new Map();

  let MY_LOCAL_IP = "";

  const options = {
    nodes: {
      shape: "dot",
      font: {
        size: 12,
        color: "#888",
        face: "Fira Code, monospace",
        vadjust: -32,
      },
      borderWidth: 2,
      chosen: {
        node: (values) => {
          values.borderWidth = 3;
        },
      },
    },
    edges: {
      width: 1.5,
      selectionWidth: 2,
      arrows: { to: { enabled: true, scaleFactor: 0.3 } },
      smooth: { type: "curvedCW", roundness: 0.2 },
      color: { inherit: false, opacity: 0.4 },
      chosen: {
        edge: function (values) {
          values.opacity = 1.0;
          values.color = "#ffffff";
        },
      },
    },
    physics: {
      enabled: true,
      solver: "forceAtlas2Based",
      forceAtlas2Based: {
        gravitationalConstant: -150,
        centralGravity: 0.01,
        springLength: 150,
        springConstant: 0.08,
        avoidOverlap: 1,
      },
      stabilization: { iterations: 100 },
    },
    interaction: {
      hover: true,
      multiselect: false,
      tooltipDelay: 100,
      hoverConnectedEdges: true,
    },
  };

  const network = new vis.Network(container, { nodes, edges }, options);

  document
    .getElementById("search-input")
    .addEventListener("input", function (e) {
      const term = e.target.value.toLowerCase();
      const allNodes = nodes.get();

      const updates = allNodes.map((node) => {
        const isMatch =
          term &&
          (node.id.toLowerCase().includes(term) ||
            (node.label && node.label.toLowerCase().includes(term)));

        return {
          id: node.id,
          color: {
            background: isMatch ? "#ffd700" : "#020406",
            border: isMatch
              ? "#ffffff"
              : node.id === MY_LOCAL_IP
                ? "var(--primary)"
                : "#333",
          },
          shadow: { enabled: !!isMatch, color: "#ffd700", size: 15 },
        };
      });
      nodes.update(updates);
    });

  async function updateData() {
    try {
      const [dRes, sRes] = await Promise.all([
        fetch("/data"),
        fetch("/status"),
      ]);
      const data = await dRes.json();
      const status = await sRes.json();
      const indicator = document.getElementById("status-indicator");
      const statusText = document.getElementById("status-text");
      indicator.className = status.is_running ? "active" : "";
      statusText.innerText = status.is_running ? "LIVE_SCAN" : "IDLE";

      if (!data) return;

      const processedNodes = data.nodes.map((n) => {
        nodeCache.set(n.id, n);
        const isMe = n.node_type === "my_device";
        if (isMe) MY_LOCAL_IP = n.id;

        const displayName = n.label && n.label !== n.id ? n.label : n.id;

        return {
          id: n.id,
          label: displayName,
          size: isMe ? 25 : 12,
          color: {
            background: "#020406",
            border: n.is_malicious
              ? "var(--danger)"
              : isMe
                ? "var(--primary)"
                : "#333",
          },
          font: { color: n.is_malicious ? "var(--danger)" : "#777" },
        };
      });
      nodes.update(processedNodes);

      if (data.edges) {
        const processedEdges = data.edges.map((e) => {
          const isSent = e.from === MY_LOCAL_IP;
          return {
            id: `${e.from}-${e.to}`,
            from: e.from,
            to: e.to,
            color: {
              color: isSent
                ? "rgba(255, 62, 62, 0.3)"
                : "rgba(0, 242, 255, 0.3)",
            },
          };
        });
        edges.update(processedEdges);
      }
    } catch (e) {
      console.error(e);
    }
  }

  network.on("click", function (params) {
    let targetNodeId = null;

    if (params.nodes.length > 0) {
      targetNodeId = params.nodes[0];
    } else if (params.edges.length > 0) {
      const edgeData = edges.get(params.edges[0]);
      targetNodeId = edgeData.to !== MY_LOCAL_IP ? edgeData.to : edgeData.from;
    }

    if (targetNodeId) {
      const data = nodeCache.get(targetNodeId);
      showNodeDetails(data);
      network.selectNodes([targetNodeId]);
    } else {
      document.getElementById("info-panel").classList.remove("visible");
    }
  });

  function showNodeDetails(data) {
    const content = document.getElementById("info-content");
    content.innerHTML = `
            <div class="info-card">
                <span class="info-label">ADDRESS_IP</span>
                <span class="info-value">${data.id}</span>
            </div>
            <div class="info-card">
                <span class="info-label">RESOLVED_DOMAIN</span>
                <span class="info-value" style="color:var(--primary)">${data.label || "N/A"}</span>
            </div>
            <div class="info-card">
                <span class="info-label">SECURITY_THREAT</span>
                <span class="info-value" style="color:${data.is_malicious ? "var(--danger)" : "var(--success)"}">
                    ${data.is_malicious ? "DETECTED / BLOCKING" : "SCAN_CLEAN"}
                </span>
            </div>
        `;
    document.getElementById("info-panel").classList.add("visible");
  }

  document.getElementById("start-btn").onclick = () =>
    fetch("/start_capture", { method: "POST" });
  document.getElementById("stop-btn").onclick = () =>
    fetch("/stop_capture", { method: "POST" });
  document.getElementById("clear-btn").onclick = () => {
    fetch("/clear_data", { method: "POST" });
    nodes.clear();
    edges.clear();
  };
  document.getElementById("close-panel").onclick = () =>
    document.getElementById("info-panel").classList.remove("visible");

  setInterval(updateData, 2500);
});
