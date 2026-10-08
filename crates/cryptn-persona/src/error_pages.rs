//! Stock httpd error pages, quoted verbatim from 2.4.58 sources.
//!
//! Page shape (`ap_send_error_response`, http_protocol.c:1517):
//! `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n
//! <title>{title}</title>\n</head><body>\n<h1>{h1}</h1>\n{canned}\n{hr+address}
//! </body></html>\n` where h1 is `&title[4]` (the title minus its code) and
//! the footer is `ap_psignature("<hr>\n")`:
//! `<hr>\n<address>Apache/2.4.58 (Ubuntu) Server at {host} Port {port}
//! </address>\n`.

use cryptn_front::Response;

/// The stock reason line for a status (e.g. "404 Not Found"), as it appears
/// in `<title>` and `<h1>`.
fn title_line(code: u16) -> String {
    format!("{} {}", code, cryptn_front::reason(code))
}

/// `&title[4]` — the H1 drops the leading "404 ".
fn h1_line(code: u16) -> String {
    title_line(code)[4..].to_string()
}

/// HTML-escape like `ap_escape_html` for the characters a hostname/method
/// can carry: `&`, `<`, `>`, `"`.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Canned body text per status, verbatim from `get_canned_error_string()`.
fn canned(code: u16, _method: &str) -> &'static str {
    match code {
        301 | 302 | 307 | 308 => {
            // Location-dependent; the caller appends the link. Handled
            // separately in `error_page_with`; unreachable here.
            ""
        }
        400 => "<p>Your browser sent a request that this server could not understand.<br />\n</p>\n",
        401 => "<p>This server could not verify that you\nare authorized to access the document\nrequested.  Either you supplied the wrong\ncredentials (e.g., bad password), or your\nbrowser doesn't understand how to supply\nthe credentials required.</p>\n",
        403 => "<p>You don't have permission to access this resource.</p>\n",
        404 => "<p>The requested URL was not found on this server.</p>\n",
        405 => "", // method-dependent, composed by caller
        408 => "<p>Server timeout waiting for the HTTP request from the client.</p>\n",
        410 => "<p>The requested resource is no longer available on this server and there is no forwarding address.\nPlease remove all references to this resource.</p>\n",
        411 => "", // method-dependent
        412 => "<p>The precondition on the request for this URL evaluated to false.</p>\n",
        413 => "", // method-dependent
        414 => "<p>The requested URL's length exceeds the capacity\nlimit for this server.<br />\n</p>\n",
        415 => "<p>The supplied request data is not in a format\nacceptable for processing by this resource.</p>\n",
        416 => "<p>None of the range-specifier values in the Range\nrequest-header field overlap the current extent\nof the selected resource.</p>\n",
        417 => "<p>No expectation was seen, the Expect request-header \nfield was not presented by the client.\n</p>\n<p>Only the 100-continue expectation is supported.</p>\n",
        429 => "<p>The user has sent too many requests\nin a given amount of time.</p>\n",
        431 => "<p>The server refused this request because\nthe request header fields are too large.</p>\n",
        500 => "<p>The server encountered an internal error or\nmisconfiguration and was unable to complete\nyour request.</p>\n",
        501 => "", // method-dependent
        503 => "<p>The server is temporarily unable to service your\nrequest due to maintenance downtime or capacity\nproblems. Please try again later.</p>\n",
        505 => "<p>A request feature of the HTTP protocol is not supported\nby the server.</p>\n",
        _ => "<p>The server encountered an internal error or\nmisconfiguration and was unable to complete\nyour request.</p>\n",
    }
}

/// The server signature footer, `ap_psignature` with `ServerSignature On`
/// (Ubuntu's default): `<hr>\n<address>Apache/2.4.58 (Ubuntu) Server at
/// {host} Port {port}</address>\n`.
fn signature(server_banner: &str, host: &str, port: u16) -> String {
    format!(
        "<hr>\n<address>{} Server at {} Port {}</address>\n",
        server_banner,
        escape_html(host),
        port
    )
}

/// Compose the full stock error page for a status.
///
/// `server_banner` is e.g. `Apache/2.4.58 (Ubuntu)` — the persona's
/// configured Server header value. `host` is the request's Host header
/// (without port) as `ap_get_server_name` resolves it.
pub fn error_page(code: u16, method: &str, server_banner: &str, host: &str, port: u16) -> Vec<u8> {
    let title = title_line(code);
    let h1 = h1_line(code);

    // Method-dependent canned strings (http_protocol.c composes these with
    // ap_escape_html(r->method)).
    let body = match code {
        405 => format!(
            "<p>The requested method {} is not allowed for this URL.</p>\n",
            escape_html(method)
        ),
        411 => format!(
            "<p>A request of the requested method {} requires a valid Content-length.<br />\n</p>\n",
            escape_html(method)
        ),
        413 => format!(
            "The requested resource does not allow request data with {} requests, or the amount of data provided in\nthe request exceeds the capacity limit.\n",
            escape_html(method)
        ),
        501 => format!(
            "<p>{} not supported for current URL.<br />\n</p>\n",
            escape_html(method)
        ),
        _ => canned(code, method).to_string(),
    };

    let mut page = String::with_capacity(512);
    page.push_str("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>");
    page.push_str(&title);
    page.push_str("</title>\n</head><body>\n<h1>");
    page.push_str(&h1);
    page.push_str("</h1>\n");
    page.push_str(&body);
    page.push_str(&signature(server_banner, host, port));
    page.push_str("</body></html>\n");
    page.into_bytes()
}

/// Build a stock error `Response` with persona headers in Apache's order:
/// Date, Server, Content-Length, Connection, Content-Type — plus `Allow`
/// for 405/501 (Ubuntu enables mod_{headers,alias}; error pages carry
/// Keep-Alive on HTTP/1.1).
#[allow(clippy::too_many_arguments)] // stock-page composition is inherently wide
pub fn error_response(
    code: u16,
    method: &str,
    server_banner: &str,
    host: &str,
    port: u16,
    keep_alive: bool,
    allow: Option<&str>,
    date: &str,
) -> Response {
    let body = error_page(code, method, server_banner, host, port);
    let mut r = Response::new(code);
    r.push_header("Date", date);
    r.push_header("Server", server_banner);
    if let Some(allow) = allow {
        r.push_header("Allow", allow);
    }
    r.push_header("Content-Length", body.len().to_string());
    if keep_alive {
        r.push_header("Keep-Alive", "timeout=5, max=100");
        r.push_header("Connection", "Keep-Alive");
    } else {
        r.push_header("Connection", "close");
    }
    r.push_header("Content-Type", "text/html; charset=iso-8859-1");
    r.body = body;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_page_is_verbatim_shape() {
        let page = error_page(404, "GET", "Apache/2.4.58 (Ubuntu)", "box.example", 80);
        let text = String::from_utf8(page).unwrap();
        assert!(text.starts_with(
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n"
        ), "{text}");
        assert!(text.contains("<p>The requested URL was not found on this server.</p>\n"));
        assert!(text.contains(
            "<hr>\n<address>Apache/2.4.58 (Ubuntu) Server at box.example Port 80</address>\n"
        ));
        assert!(text.ends_with("</body></html>\n"));
    }

    #[test]
    fn method_not_allowed_quotes_method() {
        let page = error_page(405, "PROPFIND", "Apache/2.4.58 (Ubuntu)", "h", 80);
        let text = String::from_utf8(page).unwrap();
        assert!(
            text.contains("<p>The requested method PROPFIND is not allowed for this URL.</p>\n")
        );
    }

    #[test]
    fn escapes_host_in_signature() {
        let page = error_page(403, "GET", "Apache/2.4.58 (Ubuntu)", "<script>", 80);
        let text = String::from_utf8(page).unwrap();
        assert!(text.contains("Server at &lt;script&gt; Port 80"));
    }

    #[test]
    fn titles_drop_code_for_h1() {
        assert_eq!(h1_line(404), "Not Found");
        assert_eq!(h1_line(414), "URI Too Long");
    }
}
