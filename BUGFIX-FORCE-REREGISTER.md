# Force Re-registration Fix for Stale RLink Registrations

## Problem Summary

When router nodes disconnect and reconnect via RLink (router-to-router links), their previous procedure registrations become stale on the remote router. When the RLink reconnects and tries to re-register the same procedures, it receives `wamp.error.procedure_already_exists` errors, preventing the procedures from being available in the cluster.

**Symptoms:**
- RLink connections succeed but procedures don't get registered
- `procedure_already_exists` errors in logs during RLink registration
- Procedures unavailable on remote routers after RLink reconnection
- Manual cleanup required to restore functionality

## Root Cause

When an RLink session disconnects unexpectedly (network issue, pod restart, etc.), the remote router doesn't immediately clean up the registrations made by that RLink. When the RLink reconnects:

1. **Stale registrations remain**: The old registrations from the previous RLink session are still active
2. **Standard registration fails**: New registration attempt gets `procedure_already_exists` error
3. **No automatic cleanup**: Without `force_reregister`, there's no mechanism to replace stale registrations

## Solution

Implement automatic retry with `force_reregister=True` when RLink encounters `procedure_already_exists` errors. This allows the new RLink session to forcefully replace stale registrations from previous sessions.

### Implementation

**Key Changes:**

1. **Dealer supports force_reregister** (`crossbar/router/dealer.py`)
   - Added `force_reregister` option to `Register` message handling
   - When `force_reregister=True`, kicks out all other observers before registering
   - Sends `UNREGISTERED` messages to kicked observers
   - Deletes and recreates observation if all observers were kicked

2. **RLink automatic retry logic** (`crossbar/worker/rlink.py`)
   - Preserves original `force_reregister` setting from registration details
   - First tries registration with original settings
   - On `procedure_already_exists` error:
     - If original didn't use `force_reregister`, retries with `force_reregister=True`
     - If original already used `force_reregister`, logs error (possible race condition)
   - Handles stale registrations from previous RLink connections

### Code Flow

```
RLink Session Connects
    ↓
Forwards registrations from local router to remote router
    ↓
First attempt: register(force_reregister=False)  # or original setting
    ↓
    ├─ Success → Registration complete
    │
    └─ procedure_already_exists error
        ↓
        Check if original used force_reregister
        ↓
        If not, retry: register(force_reregister=True)
        ↓
        Dealer kicks out stale observers (previous RLink session)
        ↓
        Sends UNREGISTERED to stale sessions
        ↓
        Deletes old observation, creates new one
        ↓
        Registration succeeds with new RLink session
```

## Code Details

### Dealer Force Re-registration Logic

```python
if register.force_reregister and registration:
    # Kick out all other observers, but not the session doing the re-registration
    observers_to_kick = [obs for obs in registration.observers if obs != session]
    
    for obs in observers_to_kick:
        self._registration_map.drop_observer(obs, registration)
        kicked = message.Unregistered(
            0,
            registration=registration.id,
            reason="wamp.error.unregistered",
        )
        self._router.send(obs, kicked)
    
    # If we kicked out all observers, delete the observation so it can be recreated
    if observers_to_kick and len(registration.observers) == len(observers_to_kick):
        self._registration_map.delete_observation(registration)
```

### RLink Retry Logic

```python
# First try with original settings
try:
    reg = yield other.register(on_call,
                               uri,
                               options=RegisterOptions(
                                   details_arg='details',
                                   invoke=invoke,
                                   match=match,
                                   force_reregister=original_force_reregister,
                                   forward_for=forward_for,
                               ))
except ApplicationError as e:
    if e.error == 'wamp.error.procedure_already_exists':
        # If procedure already exists AND original didn't use force_reregister,
        # retry with force_reregister=True to replace stale registration.
        if not original_force_reregister:
            other_leg = 'local' if self.IS_REMOTE_LEG else 'remote'
            self.log.debug(
                f"procedure {uri} already exists on {other_leg}, "
                f"retrying with force_reregister=True")
            try:
                reg = yield other.register(on_call,
                                           uri,
                                           options=RegisterOptions(
                                               details_arg='details',
                                               invoke=invoke,
                                               match=match,
                                               force_reregister=True,
                                               forward_for=forward_for,
                                           ))
            except Exception as retry_e:
                self.log.error(f"failed to force-reregister {uri}: {retry_e}")
                return
```

## Testing

### Local Testing
```bash
# Start cluster with router and RLink
docker-compose up -d

# Check RLink connection
docker logs crossbar_router_realm1 2>&1 | grep -i rlink

# Verify procedure registrations
docker logs crossbar_router_realm1 2>&1 | grep "forward-register"

# Simulate disconnect/reconnect
docker restart crossbar_router_realm1

# Check for force_reregister retry messages
docker logs crossbar_router_realm1 2>&1 | grep "retrying with force_reregister=True"

# Verify procedures are available
# Test RPC calls to procedures
```

### Kubernetes Testing
```bash
# Check RLink status
kubectl logs crossbar-router-realm1-sfs-0 | grep rlink

# Delete pod to simulate reconnection
kubectl delete pod crossbar-router-realm1-sfs-0

# Watch for reconnection and registration
kubectl logs -f crossbar-router-realm1-sfs-0 | grep -E "rlink|force_reregister|procedure_already_exists"

# Verify procedures registered successfully
kubectl logs crossbar-router-realm1-sfs-0 | grep "forward-register.*success"
```

## Edge Cases Handled

1. **Session already registered**: If the current session is already registered for the procedure, it won't kick itself out
2. **Original force_reregister=True**: If the original registration already used `force_reregister`, a conflict indicates a race condition or multiple RLinks
3. **All observers kicked**: If all observers are removed, the observation is deleted and recreated cleanly
4. **Retry failure**: If the retry with `force_reregister=True` also fails, the error is logged and the registration is abandoned

## Important Notes

1. **Automatic cleanup**: Stale registrations are automatically replaced without manual intervention
2. **Session preservation**: The current session won't kick itself out if it's already registered
3. **Non-destructive**: If the original registration used `force_reregister=True`, we don't retry to avoid loops
4. **Backward compatible**: Existing code without `force_reregister` continues to work normally
5. **RLink-specific**: This primarily benefits RLink (router-to-router) connections where stale registrations are common

## Observability

Log messages to watch for:

### Successful force re-registration:
```
procedure com.example.procedure already exists on remote, retrying with force_reregister=True
```

### Force re-registration conflict (race condition):
```
procedure com.example.procedure already exists even though we used force_reregister=True. 
Race condition or multiple rlinks?
```

### Observer kicked out:
```
UNREGISTERED message sent to session (kicked by force_reregister)
```

## Files Modified

- `crossbar/router/dealer.py` - Added force_reregister handling in `processRegister`
- `crossbar/worker/rlink.py` - Added automatic retry with force_reregister on conflict

## Related Issues

- PR #2137: Resilient Proxy node and Router node management
- RLink session lifecycle management
- Stale registration cleanup
- Router cluster resilience

## Migration Notes

No migration required. The fix is backward compatible:
- Existing registrations continue to work normally
- Only activates on `procedure_already_exists` errors
- Original registration behavior preserved for non-RLink sessions
