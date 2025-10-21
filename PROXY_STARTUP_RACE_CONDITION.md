# Proxy Startup Race Condition

## Issue Description

During Crossbar cluster startup or reconfiguration, there is a race condition where proxy workers start accepting client connections before the application realm routes are fully configured. This causes client connections to be denied with error `wamp.error.no_such_realm`.

## Root Cause

The cluster orchestration has two independent monitors running asynchronously:

1. **WebclusterMonitor** (`crossbar/master/cluster/webcluster.py`)
   - Manages proxy workers and transports
   - Starts proxy transports which immediately begin accepting connections

2. **ApplicationRealmMonitor** (`crossbar/master/arealm/arealm.py`)
   - Manages proxy connections and routes  
   - Creates routes that map realms to backend router connections

These monitors run independently without coordination, leading to the following sequence:

```
Time  | Component            | Action
------|----------------------|------------------------------------------
T1    | WebclusterMonitor    | Calls start_proxy_transport
T2    | ProxyWorker          | Transport starts, begins accepting connections
T3    | Client               | Attempts to connect to realm "realm1"
T4    | ProxyWorker          | has_realm("realm1") → False
T5    | ProxyWorker          | Returns Deny(NO_SUCH_REALM) to client ❌
...   | ...                  | ...
T10   | ApplicationRealmMonitor | Creates proxy connections
T11   | ApplicationRealmMonitor | Creates proxy routes for "realm1" ✅
T12   | Client               | Retries connection → Success ✓
```

## Observed Behavior

### Debug Logs Showing the Race

**Proxy Transport Started (T1-T2):**
```
2025-10-19T11:05:13+0000 [Proxy 50] ProxyController.start_proxy_transport 
                          proxy transport "primary" started and listening!
```

**Client Connection Denied (T3-T5):**
```
2025-10-19T11:05:14+0000 [Proxy 50] ProxyController.has_realm(realm="realm1") -> False
2025-10-19T11:05:14+0000 [Proxy 50] ProxyFrontendSession._process_Hello 
                          authmethod "wampcra" completed with result=Deny(
                          reason=<wamp.error.no_such_realm>, 
                          message='explicit realm <realm1> configured for dynamic 
                          authenticator does not exist')
```

**Routes Created Later (T10-T11):**
```
2025-10-19T11:06:20+0000 [Proxy 50] ProxyRoute.start 
                          proxy route route001 started for realm "realm1" with config=
2025-10-19T11:06:21+0000 [Proxy 50] ProxyRoute.start 
                          proxy route route002 started for realm "realm1" with config=
```

**Gap:** ~1 minute between transport start (11:05:13) and route creation (11:06:20)

## Impact

- **Client Connection Failures:** Clients connecting during startup receive `NO_SUCH_REALM` errors
- **User Experience:** Appears as service unavailability during restarts/reconfigurations  
- **Retry Required:** Clients must implement retry logic with backoff
- **Scaling Issues:** Larger clusters with more realms have longer setup windows

## Affected Components

- **Proxy Workers:** All proxy workers experience this during startup
- **Client Libraries:** Any WAMP client connecting during proxy initialization  
- **Dynamic Authenticators:** Authentication fails when realm routes don't exist

## Fixes Implemented

### 1. Improved Error Messages (Immediate)

Modified `crossbar/router/auth/pending.py` to provide clearer error messages that indicate the temporary nature of the problem:

**Before:**
```python
return Deny(ApplicationError.NO_SUCH_REALM,
            message='explicit realm <{}> configured for dynamic authenticator does not exist')
```

**After:**
```python
return Deny(ApplicationError.NO_SUCH_REALM,
            message='explicit realm <{}> configured for dynamic authenticator does not exist - '
                    'proxy routes may still be initializing, please retry connection')
```

This helps client developers understand that retry is expected.

### 2. Enhanced Logging (Diagnostic)

Added logging in `crossbar/master/arealm/arealm.py` to clearly indicate when routes are ready:

```python
self.log.info(
    'Proxy routes now configured for realm "{realm_name}" on worker {wc_worker_id} - '
    'clients can now connect to this realm ({num_routes} routes active)',
    realm_name=realm_name,
    wc_worker_id=wc_worker_id,
    num_routes=len(routes))
```

This provides operational visibility into when realms become available.

## Recommended Long-term Solutions

### Option A: Coordinated Startup (Preferred)

Modify the webcluster monitor to delay transport startup until routes are configured:

1. WebclusterMonitor creates proxy workers (no transport yet)
2. ApplicationRealmMonitor creates connections and routes
3. ApplicationRealmMonitor signals webcluster monitor "routes ready"
4. WebclusterMonitor starts proxy transport

**Pros:** Eliminates race completely  
**Cons:** Requires coordination between monitors, more complex

### Option B: Queued Connections

Proxy could queue incoming connections until routes are ready:

```python
class ProxyController:
    def __init__(self):
        self._routes_initialized = False
        self._queued_connections = []
    
    def mark_routes_ready(self, realm):
        # Called when routes are created
        self._routes_initialized = True
        self._process_queued_connections()
```

**Pros:** Transparent to clients  
**Cons:** Adds complexity, connections held open consuming resources

### Option C: Health Check Endpoint

Add a health/readiness endpoint that returns ready only when routes are configured:

```python
GET /health/ready
→ 503 Service Unavailable  # During initialization
→ 200 OK                   # After routes configured
```

**Pros:** Standard pattern, easy for load balancers  
**Cons:** Requires HTTP monitoring, doesn't help direct WAMP connections

## Workaround for Users

Until a long-term fix is implemented, clients should:

1. **Implement Retry Logic:**
   ```python
   from autobahn.wamp.exception import ApplicationError
   
   max_retries = 10
   retry_delay = 2  # seconds
   
   for attempt in range(max_retries):
       try:
           session = await component.start()
           break  # Success!
       except ApplicationError as e:
           if e.error == 'wamp.error.no_such_realm':
               if attempt < max_retries - 1:
                   await asyncio.sleep(retry_delay)
                   continue
           raise
   ```

2. **Use Exponential Backoff:** Increase delay between retries

3. **Monitor Logs:** Watch for "Proxy routes now configured" messages to know when ready

## Testing

To reproduce the issue:

1. Start a clean Crossbar cluster
2. Immediately attempt client connections to all realms
3. Observe `NO_SUCH_REALM` errors in first ~60 seconds
4. Wait for route configuration logs
5. Retry connections → should succeed

## Related Issues

- Dynamic authenticator realm checks in `pending.py`
- Monitor coordination in master orchestration
- Proxy worker initialization sequence

## Date Identified

2025-10-19

## Fixed By

- Improved error messages: commit [pending]
- Enhanced logging: commit [pending]
- Long-term coordination fix: [to be implemented]
