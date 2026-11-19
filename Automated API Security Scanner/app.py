import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
import streamlit as st

st.set_page_config(page_title="API Security Scanner", page_icon="🔐", layout="wide")

st.title("🔐 Automated API Security Scanner")
st.caption("Authorized, low-impact checks for Broken Object Level Authorization (BOLA) and rate-limiting behavior.")

# ---------------------------- Helpers ----------------------------
def make_headers(auth_type: str, token: str, extra_headers: Dict[str, str]) -> Dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": "Authorized-API-Security-Scanner/1.0"}
    if auth_type == "Bearer token" and token:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(extra_headers)
    return headers

def parse_headers(raw: str) -> Dict[str, str]:
    if not raw.strip():
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise ValueError("Headers must be a JSON object containing string keys and values.")
    return data

def request_once(method: str, url: str, headers: Dict[str, str], timeout: int,
                 body: Optional[Dict[str, Any]] = None):
    started = time.perf_counter()
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=body if method in ("POST", "PUT", "PATCH") and body is not None else None,
        timeout=timeout,
        allow_redirects=False,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    content_type = response.headers.get("Content-Type", "")
    try:
        payload = response.json() if "json" in content_type.lower() else response.text[:4000]
    except ValueError:
        payload = response.text[:4000]
    return {
        "status": response.status_code,
        "elapsed_ms": elapsed_ms,
        "body": payload,
        "headers": dict(response.headers),
        "content_length": len(response.content),
    }

def body_fingerprint(body: Any) -> str:
    # A compact comparison aid; this is not a proof of authorization failure.
    return json.dumps(body, sort_keys=True, default=str)[:4000]

def graphql_body(query_template: str, object_id: str, variables_raw: str) -> Dict[str, Any]:
    variables = json.loads(variables_raw or "{}")
    query = query_template.replace("{object_id}", object_id)
    return {"query": query, "variables": variables}

def render_result(label: str, result: Dict[str, Any]):
    st.write(f"**{label}**")
    cols = st.columns(3)
    cols[0].metric("HTTP status", result["status"])
    cols[1].metric("Response time", f'{result["elapsed_ms"]} ms')
    cols[2].metric("Response bytes", result["content_length"])
    with st.expander("Response details"):
        st.json(result["body"]) if isinstance(result["body"], (dict, list)) else st.code(str(result["body"]))
        st.json({k: v for k, v in result["headers"].items()
                 if k.lower() in ("retry-after", "ratelimit-limit", "ratelimit-remaining",
                                  "ratelimit-reset", "x-ratelimit-limit", "x-ratelimit-remaining",
                                  "www-authenticate")})

# ---------------------------- Sidebar ----------------------------
with st.sidebar:
    st.header("Test authorization")
    st.warning("Only test APIs you own or have explicit written permission to assess. Use a staging environment where possible.")
    st.checkbox("I am authorized to test this API", key="authorized")
    st.divider()
    st.subheader("Request settings")
    timeout = st.slider("Request timeout (seconds)", 3, 20, 10)
    verify_tls = st.checkbox("Verify TLS certificates", value=True)
    st.caption("TLS verification is always enabled in this starter app.")

if not st.session_state.get("authorized", False):
    st.info("Confirm authorization in the sidebar to enable testing.")
    st.stop()

tab_bola, tab_rate, tab_notes = st.tabs(["BOLA check", "Rate-limit check", "Methodology & limitations"])

# ---------------------------- BOLA ----------------------------
with tab_bola:
    st.subheader("Broken Object Level Authorization (BOLA)")
    st.write(
        "Compare the same object request under two authorized test identities. "
        "The scanner checks whether Identity B can retrieve an object intended for Identity A. "
        "Use test accounts and non-sensitive test records only."
    )

    protocol = st.radio("API type", ["REST", "GraphQL"], horizontal=True, key="bola_protocol")
    method = "GET"
    if protocol == "REST":
        method = st.selectbox("HTTP method", ["GET", "POST"], key="bola_method")
        st.caption("Use a URL containing {object_id}, for example https://staging.example.com/api/orders/{object_id}")
        endpoint = st.text_input("REST endpoint template", placeholder="https://staging.example.com/api/orders/{object_id}")
        body_template = None
    else:
        endpoint = st.text_input("GraphQL endpoint", placeholder="https://staging.example.com/graphql")
        query_template = st.text_area(
            "GraphQL query template (include {object_id})",
            value='query GetOrder { order(id: "{object_id}") { id status } }',
            height=110,
        )
        variables_raw = st.text_area("GraphQL variables JSON (optional)", value="{}", height=70)
        body_template = {}

    st.markdown("**Test identities**")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Identity A – object owner**")
        token_a = st.text_input("Identity A bearer token", type="password", key="token_a")
        object_a = st.text_input("Object ID owned by A", placeholder="order-1001", key="object_a")
    with c2:
        st.markdown("**Identity B – different user**")
        token_b = st.text_input("Identity B bearer token", type="password", key="token_b")
        object_b = st.text_input("Object ID owned by B", placeholder="order-2002", key="object_b")

    auth_type = st.selectbox("Authentication", ["Bearer token", "No bearer token"])
    extra_headers_raw = st.text_area("Additional headers JSON (optional)", value="{}", height=75, key="bola_headers")
    st.caption("Do not paste production credentials. Tokens are used only for requests during this session.")

    if st.button("Run BOLA comparison", type="primary"):
        try:
            if not endpoint.startswith("https://"):
                raise ValueError("Use an HTTPS endpoint.")
            if not object_a or not object_b or object_a == object_b:
                raise ValueError("Provide two different, non-empty test object IDs.")
            if "{object_id}" not in endpoint and protocol == "REST":
                raise ValueError("REST endpoint must contain the {object_id} placeholder.")
            extra_headers = parse_headers(extra_headers_raw)
            if protocol == "REST":
                url_a = endpoint.replace("{object_id}", object_a)
                url_b = endpoint.replace("{object_id}", object_a)
                req_body_a = req_body_b = None
            else:
                url_a = url_b = endpoint
                req_body_a = graphql_body(query_template, object_a, variables_raw)
                req_body_b = graphql_body(query_template, object_a, variables_raw)

            headers_a = make_headers(auth_type, token_a, extra_headers)
            headers_b = make_headers(auth_type, token_b, extra_headers)
            if protocol == "GraphQL":
                headers_a["Content-Type"] = headers_b["Content-Type"] = "application/json"

            with st.spinner("Sending two controlled requests..."):
                owner_result = request_once("POST" if protocol == "GraphQL" else method,
                                            url_a, headers_a, timeout, req_body_a)
                # Identity B requests the object ID belonging to A.
                cross_result = request_once("POST" if protocol == "GraphQL" else method,
                                            url_b, headers_b, timeout, req_body_b)

            st.markdown("### Results")
            left, right = st.columns(2)
            with left:
                render_result("Identity A requesting A's object", owner_result)
            with right:
                render_result("Identity B requesting A's object", cross_result)

            owner_success = 200 <= owner_result["status"] < 300
            cross_success = 200 <= cross_result["status"] < 300
            same_body = body_fingerprint(owner_result["body"]) == body_fingerprint(cross_result["body"])
            if owner_success and cross_success and same_body:
                st.error("Potential BOLA: Identity B received a successful response matching Identity A's response.")
                st.write("Treat this as a finding requiring manual validation. Confirm that the returned object is private to A and that the API's intended policy denies B.")
            elif cross_result["status"] in (401, 403, 404):
                st.success("No obvious BOLA behavior in this comparison: Identity B was denied or the object was not disclosed.")
            elif cross_success:
                st.warning("Inconclusive: Identity B received a successful response. Review the response body and authorization policy manually.")
            else:
                st.info("Inconclusive: responses did not demonstrate the simple BOLA pattern. Review API behavior and test additional authorized cases.")

            st.caption("This check compares a single owner/cross-user test case. It is not a complete authorization audit.")
        except Exception as exc:
            st.error(f"Test could not run: {exc}")

# ---------------------------- Rate limiting ----------------------------
with tab_rate:
    st.subheader("Rate-limiting behavior")
    st.write(
        "Send a small, sequential burst of requests to one approved test endpoint. "
        "The check stops immediately when HTTP 429 is returned and never attempts to bypass throttling."
    )
    rate_protocol = st.radio("Request format", ["REST", "GraphQL"], horizontal=True, key="rate_protocol")
    rate_url = st.text_input("Target HTTPS endpoint", placeholder="https://staging.example.com/api/health")
    rate_method = st.selectbox("HTTP method", ["GET", "POST"], key="rate_method")
    rate_token = st.text_input("Bearer token (optional)", type="password", key="rate_token")
    rate_headers_raw = st.text_area("Additional headers JSON (optional)", value="{}", height=75, key="rate_headers")
    rate_body_raw = st.text_area("JSON request body (for POST / GraphQL)", value='{"query":"{ __typename }"}', height=90)
    count = st.slider("Maximum requests", min_value=2, max_value=20, value=5)
    delay = st.slider("Delay between requests (seconds)", min_value=0.5, max_value=3.0, value=1.0, step=0.5)
    st.caption("Safety cap: 20 sequential requests, no concurrency, no retry after 429.")

    if st.button("Run rate-limit check", type="primary"):
        try:
            if not rate_url.startswith("https://"):
                raise ValueError("Use an HTTPS endpoint.")
            headers = make_headers("Bearer token" if rate_token else "No bearer token",
                                   rate_token, parse_headers(rate_headers_raw))
            body = json.loads(rate_body_raw) if rate_method == "POST" or rate_protocol == "GraphQL" else None
            if rate_protocol == "GraphQL":
                headers["Content-Type"] = "application/json"
                method_to_use = "POST"
            else:
                method_to_use = rate_method

            records = []
            status_box = st.empty()
            progress = st.progress(0)
            for i in range(count):
                result = request_once(method_to_use, rate_url, headers, timeout, body)
                records.append({"request": i + 1, "status": result["status"],
                                "elapsed_ms": result["elapsed_ms"],
                                "retry_after": result["headers"].get("Retry-After", ""),
                                "rate_limit_remaining": result["headers"].get("RateLimit-Remaining",
                                    result["headers"].get("X-RateLimit-Remaining", ""))})
                status_box.write(f"Request {i + 1}/{count}: HTTP {result['status']} · {result['elapsed_ms']} ms")
                progress.progress((i + 1) / count)
                if result["status"] == 429:
                    st.warning("HTTP 429 received. Test stopped immediately; no further requests were sent.")
                    break
                if i < count - 1:
                    time.sleep(delay)

            st.markdown("### Rate-limit observations")
            st.dataframe(records, use_container_width=True, hide_index=True)
            statuses = [r["status"] for r in records]
            if 429 in statuses:
                st.success("Rate limiting was observed: the server returned HTTP 429.")
            else:
                st.warning("No HTTP 429 was observed within this small test window. This does not prove rate limiting is absent; the configured limit may be higher or enforced by another layer.")
            st.download_button("Download results JSON", json.dumps(records, indent=2),
                               file_name="api_rate_limit_results.json", mime="application/json")
        except Exception as exc:
            st.error(f"Test could not run: {exc}")

# ---------------------------- Notes ----------------------------
with tab_notes:
    st.subheader("Testing methodology")
    st.markdown("""
### BOLA
- Uses two authorized test identities.
- Identity A requests an object ID owned by A.
- Identity B requests that same object ID.
- A successful cross-user response is flagged as a potential issue, not automatically declared a vulnerability.
- Validate object ownership, response contents, and expected access policy manually.

### Rate limiting
- Sends a bounded number of sequential requests.
- Records HTTP status, response time, `Retry-After`, and common rate-limit headers.
- Stops immediately on HTTP 429.
- Does not use concurrency, credential rotation, IP rotation, or retry/bypass behavior.

### Limitations
- This is a focused test harness, not a full DAST product or comprehensive API security audit.
- REST URL templates and GraphQL query templates must be supplied by the tester.
- Complex GraphQL authorization often requires endpoint-specific queries and variables.
- It does not discover API routes, enumerate object IDs, fuzz parameters, or test business logic.
- Use dedicated test accounts and synthetic records. Avoid production data and destructive endpoints.
- This starter app does not persist credentials or scan results to a server-side database.
- Run behind authentication if shared with a team. Consider audit logging, RBAC, secret management, and a dedicated backend before production deployment.
""")
    st.subheader("Suggested remediation")
    st.markdown("""
**For BOLA:** enforce object-level authorization on every request using the authenticated principal and the requested object's ownership/tenant relationship. Do not rely on unguessable IDs alone.

**For rate limiting:** apply per-user, per-token, and/or per-IP quotas appropriate to the operation; return HTTP 429 with a useful `Retry-After` header; monitor abuse and expensive GraphQL query complexity.
""")
