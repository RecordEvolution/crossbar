# Cluster IP Auto-Refresh Fix

## Problem Summary

When router nodes in a Crossbar.io cluster restart (e.g., Kubernetes pod rescheduling), they receive new IP addresses. However, proxy workers were connecting to stale IP addresses stored in the master's database, causing connection failures.

**Symptoms:**
- WAMP clients unable to connect to realms via proxy
- Proxy workers timing out with "Connection refused" errors
- Router nodes running with new IPs (e.g., 10.108.3.17) but database containing old IPs (e.g., 10.108.1.12)

## Root Cause

The cluster_ip field in the master database was not being updated when router nodes reconnected with new IP addresses. The system had several issues:

1. **WAMP meta events not enabled**: The management realm didn't have `wamp.session.on_join` meta events enabled, so session join handlers never fired
2. **Wrong update location**: Initial attempts to update cluster_ip in session join handlers (`_on_session_startup`) failed because meta events weren't being published
3. **Stale data returned**: The authenticator returned the old `node.authextra` from the database, overwriting the current cluster_ip sent by the node

## Solution

Update the cluster_ip during authentication phase, before the session joins. This doesn't rely on WAMP meta events and executes on every node connection.

### Implementation

**Key Changes:**

1. **Node sends cluster_ip in authextra** (`crossbar/edge/node/management.py`)
   - Reads `CROSSBAR_NODE_CLUSTER_IP` from environment variable
   - Falls back to `127.0.0.1` if not set
   - Sends cluster_ip in authextra during authentication

2. **Authenticator updates database** (`crossbar/master/node/authenticator.py`)
   - Extracts `cluster_ip` from incoming `details['authextra']`
   - Compares with database `node.cluster_ip`
   - Updates database if different (with write transaction)
   - Updates both `node.cluster_ip` and `node.authextra['cluster_ip']`
   - Logs IP changes for observability

3. **Cleanup** 
   - Removed cluster_ip from key file generation (`crossbar/common/key.py`)
   - Removed cluster_ip from auto-pairing logic (`crossbar/master/node/controller.py`)
   - Removed redundant database update from session join handler (`crossbar/master/mrealm/controller.py`)

### Code Flow

```
Router Node Restart
    ↓
Read CROSSBAR_NODE_CLUSTER_IP from environment (pod IP)
    ↓
Connect to master with cluster_ip in authextra
    ↓
Authenticator._auth_node() extracts incoming cluster_ip
    ↓
Compare incoming_cluster_ip vs database node.cluster_ip
    ↓
If different: Update database + log change
    ↓
Return updated authextra to node
    ↓
ApplicationRealmMonitor reads node.cluster_ip from database
    ↓
Configure proxy backend connections with current IP
    ↓
Proxy workers connect to correct router IP
```

## Testing

### Local Docker Verification
```bash
# Build and deploy
just build_amd
docker-compose up -d

# Check router environment
docker exec crossbar_router_realm1 env | grep CROSSBAR_NODE_CLUSTER_IP

# Verify authenticator receives cluster_ip
docker logs crossbar_master 2>&1 | grep "Node authentication received"

# Check for IP changes (on pod restart)
docker logs crossbar_master 2>&1 | grep "cluster IP changed"

# Verify proxy connections succeed
docker logs crossbar_proxy1 2>&1 | grep "proxy backend session joined"
```

### Kubernetes/GKE Verification
```bash
# Check router pod IP
kubectl get pod crossbar-router-realm1-sfs-0 -o wide

# Verify environment variable
kubectl exec crossbar-router-realm1-sfs-0 -- env | grep CROSSBAR_NODE_CLUSTER_IP

# Check master logs for IP updates
kubectl logs crossbar-master-0 | grep "cluster IP changed"

# Verify proxy connections
kubectl logs crossbar-proxy-realm1-0 | grep "proxy backend session joined"

# Test pod restart
kubectl delete pod crossbar-router-realm1-sfs-0
# Wait for pod to restart with new IP
kubectl logs crossbar-master-0 | grep "cluster IP changed"
```

## Environment Configuration

Router nodes must set `CROSSBAR_NODE_CLUSTER_IP` to their reachable IP address or hostname:

### Kubernetes StatefulSet
```yaml
env:
- name: CROSSBAR_NODE_CLUSTER_IP
  valueFrom:
    fieldRef:
      fieldPath: status.podIP
```

### Docker Compose
```yaml
environment:
  CROSSBAR_NODE_CLUSTER_IP: crossbar_router_realm1  # hostname or IP
```

## Important Notes

1. **Hostnames supported**: The cluster_ip can be either an IP address or a resolvable hostname. Twisted's TCP client automatically resolves DNS names.

2. **Authentication-time update**: The cluster_ip update happens during authentication, not during session join. This is critical and doesn't depend on WAMP meta events.

3. **Backward compatibility**: Old key files with cluster_ip are still supported (cluster_ip in allowed_tags), but new key generation doesn't include it.

4. **No restart required**: When a router pod restarts with a new IP, the master database updates automatically on the next authentication. Proxy workers pick up the new IP from the database.

5. **Observability**: Log messages show when cluster IPs change:
   ```
   Node router_realm1 cluster IP changed from 10.108.1.12 to 10.108.3.17 - updating database during authentication
   ```

## Files Modified

- `crossbar/edge/node/management.py` - Send cluster_ip in authextra
- `crossbar/master/node/authenticator.py` - Update database during authentication
- `crossbar/master/mrealm/controller.py` - Removed redundant update logic
- `crossbar/common/key.py` - Removed cluster_ip from key generation
- `crossbar/master/node/controller.py` - Removed cluster_ip from auto-pairing

## Related Issues

- PR #2137: Resilient Proxy node and Router node management
- Kubernetes pod IP changes on rescheduling
- StatefulSet pod lifecycle management
